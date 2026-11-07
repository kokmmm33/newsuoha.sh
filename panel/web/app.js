(function () {
  "use strict";

  function detectInitialClientPlatform() {
    const ua = navigator.userAgent || "";
    if (/Windows/i.test(ua)) {
      return /ARM64|aarch64/i.test(ua) ? "windows-arm64" : "windows-amd64";
    }
    if (/Macintosh|Mac OS X/i.test(ua)) {
      // Safari & Chrome freeze Mac UA to "Intel Mac OS X"; inspect WebGL GPU vendor to distinguish Intel vs Apple Silicon
      try {
        const canvas = document.createElement("canvas");
        const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
        if (gl) {
          const dbg = gl.getExtension("WEBGL_debug_renderer_info");
          const renderer = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "") : "";
          if (/Intel|AMD|Radeon/i.test(renderer) && !/Apple/i.test(renderer)) {
            return "darwin-amd64";
          }
        }
      } catch (_) {}
      return "darwin-arm64";
    }
    if (/aarch64|arm64/i.test(ua)) return "linux-arm64";
    if (/armv7|armhf/i.test(ua)) return "linux-armv7";
    if (/i686|i386/i.test(ua)) return "linux-386";
    return "linux-amd64";
  }

  const state = {
    authenticated: false,
    activeTab: "tunnel",
    tunnelMode: "quick",
    selectedCFPort: 443,
    clientPlatform: detectInitialClientPlatform(),
    clientPlatformManual: false,
    overview: null,
    prefDraft: [],
    fallbacksDraft: [],
    realityScanRan: false,
    realityScanning: false,
    realityScanResults: [],
    formHydrated: false,
    pollTimer: null,
    currentQRText: ""
  };

  // ==================== Theme Management ====================
  function initTheme() {
    const saved = localStorage.getItem("suoha_theme");
    const theme = saved === "light" || saved === "dark" ? saved : "dark";
    document.documentElement.setAttribute("data-theme", theme);
  }

  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("suoha_theme", next);
  }

  // ==================== Utilities ====================
  function $(id) {
    return document.getElementById(id);
  }

  function escapeHTML(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function showToast(msg, isError) {
    const wrap = $("toast-container");
    if (!wrap) return;
    const el = document.createElement("div");
    el.className = "toast " + (isError ? "err" : "ok");
    el.textContent = msg;
    wrap.appendChild(el);
    setTimeout(() => {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 3400);
  }

  // Works on both HTTPS and plain HTTP (http://VPS_IP:Port)
  async function copyText(text, label) {
    const val = String(text || "").trim();
    if (!val || val === "-" || val === "暂未启动" || val === "未开启穿透域名") {
      showToast("当前暂无可复制的内容", true);
      return;
    }
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(val);
      } else {
        const ta = document.createElement("textarea");
        ta.value = val;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        ta.style.top = "0";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        if (!ok) throw new Error("copy failed");
      }
      showToast((label ? label + " " : "") + "已复制到剪贴板");
    } catch (_) {
      showToast("复制失败，请手动选中文本复制", true);
    }
  }

  async function apiFetch(url, options) {
    const opts = Object.assign(
      {
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" }
      },
      options || {}
    );
    const resp = await fetch(url, opts);
    let data = {};
    try {
      data = await resp.json();
    } catch (_) {}

    if (resp.status === 401 && !url.endsWith("/api/admin/login") && !url.endsWith("/api/admin/session")) {
      enterLoginView();
      throw new Error(data.error || "登录已过期，请重新登录");
    }
    if (!resp.ok || data.ok === false) {
      throw new Error(data.error || `请求失败 (HTTP ${resp.status})`);
    }
    return data;
  }

  // ==================== Auth & View Switching ====================
  function enterLoginView() {
    state.authenticated = false;
    state.formHydrated = false;
    stopPolling();
    $("app-view").classList.add("hidden");
    $("login-view").classList.remove("hidden");
    $("login-password").value = "";
  }

  function enterAppView() {
    state.authenticated = true;
    $("login-view").classList.add("hidden");
    $("app-view").classList.remove("hidden");
    loadOverview(true);
    schedulePolling(4000);
  }

  async function checkSession() {
    try {
      const res = await apiFetch("/api/admin/session", { method: "GET" });
      if (res.authenticated) {
        enterAppView();
      } else {
        enterLoginView();
      }
    } catch (_) {
      enterLoginView();
    }
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearTimeout(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function schedulePolling(delayMs) {
    stopPolling();
    if (!state.authenticated) return;
    state.pollTimer = setTimeout(async () => {
      await loadOverview(false);
      const st = state.overview && state.overview.status;
      const nextDelay = st && st.tunnel_state === "starting" ? 2000 : 5000;
      schedulePolling(nextDelay);
    }, delayMs);
  }

  // ==================== Data Loading & Rendering ====================
  async function loadOverview(hydrateForms) {
    try {
      const data = await apiFetch("/api/admin/overview", { method: "GET" });
      state.overview = data;
      renderLiveStatus(data);
      renderSubscriptionsAndNodes(data);
      renderClientHelper(data);

      if (hydrateForms || !state.formHydrated) {
        hydrateAllForms(data);
        state.formHydrated = true;
      }
      if (state.activeTab === "settings") {
        loadLogs();
      }
    } catch (err) {
      if (hydrateForms) {
        showToast(err.message, true);
      }
    }
  }

  function renderLiveStatus(data) {
    const st = data.status || {};
    const cfg = data.config || {};

    // Xray Chip
    const chipXray = $("chip-xray");
    chipXray.className = "status-chip " + (st.xray_running ? "is-running" : st.xray_error ? "is-error" : "");
    $("chip-xray-text").textContent = st.xray_running ? "Xray: 运行中" : st.xray_error ? "Xray: 异常" : "Xray: 已停止";

    // Tunnel Chip
    const chipTun = $("chip-tunnel");
    if (st.tunnel_state === "running" && st.tunnel_running) {
      chipTun.className = "status-chip is-running";
      $("chip-tunnel-text").textContent = "Argo: 已连通";
    } else if (st.tunnel_state === "starting") {
      chipTun.className = "status-chip is-starting";
      $("chip-tunnel-text").textContent = "Argo: 协商建立中...";
    } else if (st.tunnel_state === "error") {
      chipTun.className = "status-chip is-error";
      $("chip-tunnel-text").textContent = "Argo: 错误";
    } else {
      chipTun.className = "status-chip";
      $("chip-tunnel-text").textContent = "Argo: 未启动";
    }

    // Reality Chip
    const chipReality = $("chip-reality");
    if (chipReality) {
      chipReality.className = "status-chip " + (st.reality_active ? "is-running" : "");
      $("chip-reality-text").textContent = st.reality_active
        ? `Reality: :${cfg.protocols.reality_port}`
        : cfg.protocols && cfg.protocols.reality_enabled
        ? "Reality: 待机"
        : "Reality: 未启用";
    }

    // IPv6 SS Chip
    const chipSS = $("chip-ss");
    chipSS.className = "status-chip " + (st.ipv6_ss_active ? "is-running" : "");
    $("chip-ss-text").textContent = st.ipv6_ss_active
      ? `IPv6 SS: :${cfg.protocols.ss_port}`
      : cfg.protocols && cfg.protocols.ipv6_ss_enabled
      ? "IPv6 SS: 待机"
      : "IPv6 SS: 未启用";

    // Reality & Domain Readouts
    const realityEl = $("val-reality-status");
    if (realityEl) {
      const proto = cfg.protocols || {};
      const sni = proto.reality_sni || "www.apple.com";
      const directHost = proto.server_host_override || st.server_ip || st.detected_ipv6 || "本机IP";
      const hostFmt = directHost.includes(":") ? `[${directHost}]` : directHost;
      if (st.reality_active) {
        realityEl.textContent = `${hostFmt}:${proto.reality_port}  (SNI: ${sni} · XTLS-Vision 运行中)`;
      } else if (proto.reality_enabled) {
        realityEl.textContent = `${hostFmt}:${proto.reality_port}  (SNI: ${sni} · 待启动 Xray)`;
      } else {
        realityEl.textContent = `未启用 (默认 SNI: ${sni}，可在【协议配置】一键开启)`;
      }
    }

    $("val-argo-vl").textContent = st.argo_vl || (st.tunnel_state === "starting" ? "正在分配临时隧道域名..." : "暂未启动");
    $("val-argo-tr").textContent = st.argo_tr || (st.tunnel_state === "starting" ? "正在分配临时隧道域名..." : "暂未启动");
    $("val-argo-panel").textContent = st.argo_panel
      ? "https://" + st.argo_panel + (cfg.allow_argo_panel ? "/" : " (面板后台访问已关闭，仅订阅可用)")
      : "未开启穿透域名";

    const v4 = st.server_ip || "未检测";
    const v6 = st.detected_ipv6 || (cfg.protocols && cfg.protocols.ipv6_addr) || "无公网 IPv6";
    $("val-server-ips").textContent = `${v4}  |  IPv6: ${v6}`;
    $("val-local-gateway").textContent = data.local_gateway || `http://127.0.0.1:${cfg.listen_port}`;
  }

  function hydrateAllForms(data) {
    const cfg = data.config || {};
    const tun = cfg.tunnel || {};
    const proto = cfg.protocols || {};
    const pref = data.preferred || { ips: [] };

    // Tunnel form
    setTunnelModeUI(tun.mode || "quick");
    $("tun-enabled").checked = !!tun.enabled;
    $("tun-edge-ip").value = tun.edge_ip_version === "6" ? "6" : "4";
    $("tun-quick-topology").value = tun.quick_topology === "dual" ? "dual" : "unified";
    $("tun-custom-domain").value = tun.custom_domain || "";
    $("tun-cf-token").value = tun.cf_token || "";
    $("tun-panel-quick").checked = !!tun.panel_quick_tunnel;
    updateAuxTunnelVisibility();

    // Protocols form
    $("proto-node-tag").value = proto.node_tag || "Argo_Node";
    $("proto-uuid").value = proto.uuid || "";
    $("proto-tls-port").value = String(proto.tls_default_port || 443);
    $("proto-reality-enabled").checked = !!proto.reality_enabled;
    $("proto-reality-port").value = proto.reality_port || 24443;
    $("proto-reality-fp").value = proto.reality_fingerprint || "chrome";
    $("proto-reality-sni").value = proto.reality_sni || "www.apple.com";
    $("proto-reality-sid").value = proto.reality_short_id || "";
    $("proto-reality-pub").value = proto.reality_public_key || "";
    $("proto-reality-priv").value = proto.reality_private_key || "";
    highlightRealitySNIPill($("proto-reality-sni").value);
    $("proto-vless-enabled").checked = !!proto.vless_enabled;
    $("proto-vless-path").value = proto.vless_path || "";
    $("proto-vless-port").value = proto.vless_local_port || 18201;
    $("proto-trojan-enabled").checked = !!proto.trojan_enabled;
    $("proto-trojan-path").value = proto.trojan_path || "";
    $("proto-trojan-port").value = proto.trojan_local_port || 18202;
    $("proto-ss-enabled").checked = !!proto.ipv6_ss_enabled;
    $("proto-ss-ipv6").value = proto.ipv6_addr || (data.status && data.status.detected_ipv6) || "";
    $("proto-ss-port").value = proto.ss_port || 32888;
    $("proto-ss-method").value = proto.ss_method || "aes-128-gcm";
    $("proto-ss-pass").value = proto.ss_password || "";

    // Preferred IPs & Fallbacks
    state.selectedCFPort = proto.tls_default_port || 443;
    highlightPortPill(state.selectedCFPort);
    state.prefDraft = (pref.ips || []).map((x) => Object.assign({}, x));
    renderPrefTable();

    state.fallbacksDraft = (cfg.fallback_domains || []).map((x) => Object.assign({}, x));
    renderFallbacksTable();

    // Settings form
    $("set-allow-argo-panel").checked = !!cfg.allow_argo_panel;
    $("set-listen-port").value = cfg.listen_port || 25000;
    $("set-host-override").value = proto.server_host_override || "";
    $("set-admin-user").value = cfg.admin_user || "admin";
    $("set-cur-password").value = "";
    $("set-new-password").value = "";
  }

  function renderSubscriptionsAndNodes(data) {
    const sub = data.subscription || {};
    $("url-direct-sub").textContent = sub.direct_sub_url || "-";
    $("url-direct-clash").textContent = sub.direct_clash_url || "-";

    $("link-sub-import").href = sub.direct_sub_url ? "sub://" + sub.direct_sub_url : "#";
    $("link-clash-import").href = sub.direct_clash_url
      ? "clash://install-config?url=" + encodeURIComponent(sub.direct_clash_url)
      : "#";

    if (sub.argo_sub_url) {
      $("row-argo-sub").classList.remove("hidden");
      $("row-argo-clash").classList.remove("hidden");
      $("url-argo-sub").textContent = sub.argo_sub_url;
      $("url-argo-clash").textContent = sub.argo_clash_url;
      $("link-argo-clash-import").href =
        "clash://install-config?url=" + encodeURIComponent(sub.argo_clash_url);
    } else {
      $("row-argo-sub").classList.add("hidden");
      $("row-argo-clash").classList.add("hidden");
    }

    renderNodesTable(sub.nodes || []);
  }

  function renderNodesTable(nodes) {
    const filter = $("node-proto-filter").value || "all";
    const list = filter === "all" ? nodes : nodes.filter((n) => n.protocol === filter);
    $("node-total-count").textContent = String(nodes.length);

    const tbody = $("nodes-tbody");
    if (!list.length) {
      tbody.innerHTML =
        '<tr><td colspan="4" class="empty-placeholder">当前暂无可用节点，请在【协议配置】启用 VLESS-Reality 直连 / IPv6 SS 或在【隧道管理】启动 Argo 隧道</td></tr>';
      return;
    }

    tbody.innerHTML = list
      .map((n, idx) => {
        const hostDisp = n.host.includes(":") ? `[${n.host}]:${n.port}` : `${n.host}:${n.port}`;
        return `<tr>
          <td><span class="badge-proto ${escapeHTML(n.protocol)}">${escapeHTML(n.protocol)}</span></td>
          <td class="mono">${escapeHTML(n.name)}</td>
          <td class="mono">${escapeHTML(hostDisp)}</td>
          <td style="text-align:right;">
            <button type="button" class="btn btn-sm" data-node-copy="${idx}">复制</button>
            <button type="button" class="btn btn-sm" data-node-qr="${idx}">扫码</button>
          </td>
        </tr>`;
      })
      .join("");

    // Bind row buttons cleanly against filtered list
    tbody.querySelectorAll("[data-node-copy]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const item = list[Number(btn.getAttribute("data-node-copy"))];
        if (item) copyText(item.uri, item.name);
      });
    });
    tbody.querySelectorAll("[data-node-qr]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const item = list[Number(btn.getAttribute("data-node-qr"))];
        if (item) openQRModal(item.name, item.uri);
      });
    });
  }

  function resolveClientServerURL(helper) {
    const locHost = (window.location.hostname || "").toLowerCase();
    const isLocalLoopback =
      !locHost || locHost === "localhost" || locHost === "127.0.0.1" || locHost === "::1" || locHost === "[::1]";
    if (!isLocalLoopback && window.location.origin && /^https?:\/\//i.test(window.location.origin)) {
      return window.location.origin;
    }
    return helper.server_url || helper.direct_url || helper.argo_url || window.location.origin || "";
  }

  function updateClientCommandsUI() {
    if (!state.overview) return;
    const helper = state.overview.client_helper || {};
    const cfgProto = (state.overview.config && state.overview.config.protocols) || {};
    const sel = $("client-platform-select");
    if (sel && sel.value !== state.clientPlatform) {
      sel.value = state.clientPlatform;
    }

    const plat = state.clientPlatform || "darwin-arm64";
    const isWin = plat.indexOf("windows-") === 0;
    const isMac = plat.indexOf("darwin-") === 0;
    const repo = helper.release_repo || "kokmmm33/newsuoha.sh";
    const asset = isWin ? `suoha-client-${plat}.exe` : `suoha-client-${plat}`;
    const token = helper.token || "";
    const serverUrl = resolveClientServerURL(helper);
    const tlsPort = Number(cfgProto.tls_default_port || helper.tls_port || 443);
    const portArg = tlsPort && tlsPort !== 443 ? ` -port ${tlsPort}` : "";

    const dlBtn = $("btn-download-client-bin");
    if (dlBtn) {
      dlBtn.href = `https://github.com/${repo}/releases/download/latest/${asset}`;
      dlBtn.textContent = `下载 ${asset}`;
    }

    if (!token || !serverUrl) {
      $("cmd-auto-once").textContent = "-";
      $("cmd-auto-daemon").textContent = "-";
      $("cmd-manual-once").textContent = "-";
      $("cmd-manual-daemon").textContent = "-";
      return;
    }

    if (isWin) {
      $("cmd-auto-once").textContent =
        `powershell -ExecutionPolicy Bypass -Command "irm '${serverUrl}/api/client.ps1?token=${token}&once=1' | iex"`;
      $("cmd-auto-daemon").textContent =
        `powershell -ExecutionPolicy Bypass -Command "irm '${serverUrl}/api/client.ps1?token=${token}' | iex"`;

      const winBase =
        `$b = ".\\${asset}"; if (!(Test-Path $b)) { $b = "$HOME\\Downloads\\${asset}" }; Unblock-File $b -EA 0; & $b -server "${serverUrl}" -token "${token}"${portArg}`;
      $("cmd-manual-once").textContent = `${winBase} -once`;
      $("cmd-manual-daemon").textContent = winBase;
    } else {
      $("cmd-auto-once").textContent =
        `sh -c "$(curl -fsSL '${serverUrl}/api/client.sh?token=${token}&once=1')"`;
      $("cmd-auto-daemon").textContent =
        `sh -c "$(curl -fsSL '${serverUrl}/api/client.sh?token=${token}')"`;

      const fixPerm = isMac
        ? `chmod +x "$BIN" && (xattr -cr "$BIN" 2>/dev/null || true)`
        : `chmod +x "$BIN"`;
      const unixBase =
        `BIN=./${asset}; [ -f "$BIN" ] || BIN="$HOME/Downloads/${asset}"; ${fixPerm} && "$BIN" -server "${serverUrl}" -token "${token}"${portArg}`;
      $("cmd-manual-once").textContent = `${unixBase} -once`;
      $("cmd-manual-daemon").textContent = unixBase;
    }
  }

  function renderClientHelper(data) {
    const pref = data.preferred || { ips: [] };
    const helper = data.client_helper || {};
    const srcText =
      pref.source === "client" ? "suoha-client 自动上报" : pref.source === "manual" ? "面板手动保存" : "默认";
    $("val-pref-status").textContent = pref.updated_at
      ? `${pref.updated_at} (${srcText}，共 ${(pref.ips || []).length} 个优选 IP)`
      : "暂未上传动态优选 IP（当前使用默认隧道域名与保底公共优选域名）";

    $("val-client-token").textContent = helper.token || "-";
    updateClientCommandsUI();
  }

  // ==================== Preferred IP & Fallback Tables ====================
  function renderPrefTable() {
    $("pref-ip-count").textContent = String(state.prefDraft.length);
    const tbody = $("pref-ips-tbody");
    if (!state.prefDraft.length) {
      tbody.innerHTML =
        '<tr><td colspan="7" class="empty-placeholder">当前无动态优选 IP（点击右上角“+ 新增一行”或“批量粘贴导入”，或运行本地 suoha-client 上传）</td></tr>';
      return;
    }

    tbody.innerHTML = state.prefDraft
      .map(
        (item, idx) => `<tr data-pref-idx="${idx}">
        <td><input type="text" class="mono pref-f-ip" value="${escapeHTML(item.ip)}" placeholder="104.16.x.x 或域名" /></td>
        <td><input type="number" class="mono pref-f-port" value="${Number(item.port || 443)}" min="1" max="65535" /></td>
        <td><input type="text" class="mono pref-f-colo" value="${escapeHTML(item.colo || "")}" placeholder="HKG" /></td>
        <td><input type="text" class="mono pref-f-lat" value="${escapeHTML(item.latency || "")}" placeholder="35ms" /></td>
        <td><input type="text" class="mono pref-f-spd" value="${escapeHTML(item.speed || "")}" placeholder="20MB" /></td>
        <td><input type="text" class="pref-f-lbl" value="${escapeHTML(item.label || "")}" placeholder="留空自动生成" /></td>
        <td style="text-align:right;">
          <button type="button" class="btn btn-danger btn-sm" data-pref-del="${idx}">删除</button>
        </td>
      </tr>`
      )
      .join("");

    tbody.querySelectorAll("[data-pref-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncPrefDraftFromDOM();
        const i = Number(btn.getAttribute("data-pref-del"));
        state.prefDraft.splice(i, 1);
        renderPrefTable();
      });
    });
  }

  function syncPrefDraftFromDOM() {
    const rows = document.querySelectorAll("#pref-ips-tbody tr[data-pref-idx]");
    if (!rows.length && !state.prefDraft.length) return;
    const next = [];
    rows.forEach((tr) => {
      next.push({
        ip: tr.querySelector(".pref-f-ip").value.trim(),
        port: Number(tr.querySelector(".pref-f-port").value) || 443,
        colo: tr.querySelector(".pref-f-colo").value.trim(),
        latency: tr.querySelector(".pref-f-lat").value.trim(),
        speed: tr.querySelector(".pref-f-spd").value.trim(),
        label: tr.querySelector(".pref-f-lbl").value.trim()
      });
    });
    state.prefDraft = next;
  }

  function renderFallbacksTable() {
    const tbody = $("fallbacks-tbody");
    if (!state.fallbacksDraft.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty-placeholder">暂无保底公共优选域名，可点击右上角“+ 添加保底域名”</td></tr>';
      return;
    }

    tbody.innerHTML = state.fallbacksDraft
      .map(
        (fb, idx) => `<tr data-fb-idx="${idx}">
        <td>
          <input type="checkbox" class="fb-f-enabled" ${fb.enabled !== false ? "checked" : ""} style="width:16px;height:16px;cursor:pointer;" />
        </td>
        <td><input type="text" class="mono fb-f-host" value="${escapeHTML(fb.host)}" placeholder="cf.090227.xyz" /></td>
        <td><input type="number" class="mono fb-f-port" value="${Number(fb.port || 443)}" min="1" max="65535" /></td>
        <td><input type="text" class="fb-f-label" value="${escapeHTML(fb.label || "")}" placeholder="优选域名" /></td>
        <td style="text-align:right;">
          <button type="button" class="btn btn-danger btn-sm" data-fb-del="${idx}">删除</button>
        </td>
      </tr>`
      )
      .join("");

    tbody.querySelectorAll("[data-fb-del]").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncFallbacksDraftFromDOM();
        const i = Number(btn.getAttribute("data-fb-del"));
        state.fallbacksDraft.splice(i, 1);
        renderFallbacksTable();
      });
    });
  }

  function syncFallbacksDraftFromDOM() {
    const rows = document.querySelectorAll("#fallbacks-tbody tr[data-fb-idx]");
    if (!rows.length && !state.fallbacksDraft.length) return;
    const next = [];
    rows.forEach((tr) => {
      next.push({
        enabled: tr.querySelector(".fb-f-enabled").checked,
        host: tr.querySelector(".fb-f-host").value.trim(),
        port: Number(tr.querySelector(".fb-f-port").value) || 443,
        label: tr.querySelector(".fb-f-label").value.trim()
      });
    });
    state.fallbacksDraft = next;
  }

  function highlightPortPill(port) {
    document.querySelectorAll("#cf-port-pills .port-pill").forEach((el) => {
      el.classList.toggle("active", Number(el.getAttribute("data-cfport")) === Number(port));
    });
  }

  function highlightRealitySNIPill(sni) {
    const target = String(sni || "").trim().toLowerCase();
    document.querySelectorAll("#reality-sni-pills .port-pill").forEach((el) => {
      el.classList.toggle("active", String(el.getAttribute("data-sni") || "").toLowerCase() === target);
    });
  }

  async function saveProtocolsConfig(overridePatch) {
    const btn = $("btn-save-protocols");
    if (btn) btn.disabled = true;
    try {
      const curProto = (state.overview && state.overview.config && state.overview.config.protocols) || {};
      const payload = Object.assign(
        {
          node_tag: $("proto-node-tag").value.trim(),
          uuid: $("proto-uuid").value.trim(),
          tls_default_port: Number($("proto-tls-port").value) || 443,
          reality_enabled: $("proto-reality-enabled").checked,
          reality_port: Number($("proto-reality-port").value) || 24443,
          reality_sni: $("proto-reality-sni").value.trim() || "www.apple.com",
          reality_fingerprint: $("proto-reality-fp").value || "chrome",
          reality_short_id: $("proto-reality-sid").value.trim(),
          reality_private_key: $("proto-reality-priv").value.trim(),
          reality_public_key: $("proto-reality-pub").value.trim(),
          vless_enabled: $("proto-vless-enabled").checked,
          vless_path: $("proto-vless-path").value.trim(),
          vless_local_port: Number($("proto-vless-port").value) || 18201,
          trojan_enabled: $("proto-trojan-enabled").checked,
          trojan_path: $("proto-trojan-path").value.trim(),
          trojan_local_port: Number($("proto-trojan-port").value) || 18202,
          ipv6_ss_enabled: $("proto-ss-enabled").checked,
          ipv6_addr: $("proto-ss-ipv6").value.trim(),
          ss_port: Number($("proto-ss-port").value) || 32888,
          ss_method: $("proto-ss-method").value,
          ss_password: $("proto-ss-pass").value.trim(),
          server_host_override: curProto.server_host_override || ""
        },
        overridePatch || {}
      );
      await apiFetch("/api/admin/protocols/apply", {
        method: "POST",
        body: JSON.stringify(payload)
      });
      await loadOverview(true);
      showToast("协议配置已保存，Xray 与订阅已同步更新");
    } catch (err) {
      showToast(err.message, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function renderRealityScanTable(results) {
    const tbody = $("reality-scan-tbody");
    if (!tbody) return;
    if (!results || !results.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty-placeholder">未发现候选域名，请尝试切换扫描模式或输入自定义域名检测</td></tr>';
      return;
    }

    tbody.innerHTML = results
      .map((r, idx) => {
        const catTag = r.category
          ? ` <span class="badge-tag" style="margin-left:4px;">${escapeHTML(r.category)}</span>`
          : "";
        const compatBadge = r.valid
          ? '<span class="badge-proto ss">TLS1.3 + H2</span>'
          : '<span class="badge-proto trojan">不兼容</span>';
        const latText = r.latency_ms > 0 ? `${Number(r.latency_ms)} ms` : "-";
        const detail = r.valid
          ? `${escapeHTML(r.ip || "-")}${r.issuer ? " · " + escapeHTML(r.issuer) : ""}`
          : `<span style="color:var(--text-muted);">${escapeHTML(r.reason || "不支持 TLS 1.3 或 HTTP/2")}</span>`;
        const actions = r.valid
          ? `<button type="button" class="btn btn-sm" data-reality-fill="${idx}">填入</button>
             <button type="button" class="btn btn-primary btn-sm" data-reality-apply="${idx}">设为并保存</button>`
          : '<span class="mono" style="font-size:12px;color:var(--text-muted);">不可用</span>';
        return `<tr>
          <td class="mono">${escapeHTML(r.domain)}${catTag}</td>
          <td>${compatBadge}</td>
          <td class="mono">${escapeHTML(latText)}</td>
          <td style="font-size:12px;">${detail}</td>
          <td style="text-align:right;white-space:nowrap;">${actions}</td>
        </tr>`;
      })
      .join("");

    tbody.querySelectorAll("[data-reality-fill]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const item = results[Number(btn.getAttribute("data-reality-fill"))];
        if (!item) return;
        $("proto-reality-sni").value = item.domain;
        highlightRealitySNIPill(item.domain);
        showToast(`已填入 SNI 域名: ${item.domain}（点击底部保存后生效）`);
      });
    });

    tbody.querySelectorAll("[data-reality-apply]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const item = results[Number(btn.getAttribute("data-reality-apply"))];
        if (!item) return;
        $("proto-reality-sni").value = item.domain;
        highlightRealitySNIPill(item.domain);
        await saveProtocolsConfig({ reality_sni: item.domain });
      });
    });
  }

  async function runRealityScan(mode, customText) {
    if (state.realityScanning) return;
    if (mode === "custom" && !String(customText || "").trim()) {
      showToast("请先输入需要检测的域名 (如 www.apple.com)", true);
      return;
    }
    state.realityScanning = true;
    const scanBtns = ["btn-scan-preset", "btn-scan-neighbor", "btn-scan-custom", "btn-verify-reality-sni"];
    scanBtns.forEach((id) => {
      if ($(id)) $(id).disabled = true;
    });

    const noteEl = $("reality-scan-note");
    if (noteEl) {
      noteEl.textContent = "服务器正在并发探测 TCP:443 握手、TLS 1.3、HTTP/2 (h2) 与证书链有效性，请稍候...";
      noteEl.classList.remove("hidden");
    }
    const tbody = $("reality-scan-tbody");
    if (tbody) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty-placeholder">正在从本机服务器扫描检测可用域名...</td></tr>';
    }

    try {
      const res = await apiFetch("/api/admin/reality/scan", {
        method: "POST",
        body: JSON.stringify({
          mode: mode || "preset",
          custom: customText || ""
        })
      });
      const report = res.report || {};
      state.realityScanRan = true;
      state.realityScanResults = report.results || [];
      renderRealityScanTable(state.realityScanResults);

      if (noteEl) {
        const modeLabel =
          report.mode === "neighbor"
            ? "同网段 /24 邻近域名"
            : report.mode === "custom"
            ? "指定域名检测"
            : "内置优选域名池";
        const baseSummary = `[${modeLabel}] 共检测 ${Number(report.scanned || 0)} 个域名，可用 ${Number(
          report.valid_count || 0
        )} 个（已按本机握手延迟升序排列）。`;
        noteEl.textContent = report.note ? `${baseSummary} ${report.note}` : baseSummary;
        noteEl.classList.remove("hidden");
      }
    } catch (err) {
      if (noteEl) {
        noteEl.textContent = "扫描失败: " + err.message;
        noteEl.classList.remove("hidden");
      }
      showToast(err.message, true);
    } finally {
      state.realityScanning = false;
      scanBtns.forEach((id) => {
        if ($(id)) $(id).disabled = false;
      });
    }
  }

  // ==================== Logs ====================
  async function loadLogs() {
    const src = $("log-source-filter").value || "all";
    try {
      const res = await apiFetch(`/api/admin/logs?source=${encodeURIComponent(src)}`, { method: "GET" });
      const logs = res.logs || [];
      const box = $("log-console");
      if (!logs.length) {
        box.innerHTML = '<div class="empty-placeholder">暂无日志输出</div>';
        return;
      }
      box.innerHTML = logs
        .map(
          (l) => `<div class="log-line">
            <span class="log-time">${escapeHTML(l.time)}</span>
            <span class="log-src ${escapeHTML(l.source)}">[${escapeHTML(l.source)}]</span>
            <span>${escapeHTML(l.message)}</span>
          </div>`
        )
        .join("");
      box.scrollTop = box.scrollHeight;
    } catch (_) {}
  }

  // ==================== Tunnel Mode UI Helpers ====================
  function setTunnelModeUI(mode) {
    state.tunnelMode = mode === "token" ? "token" : "quick";
    $("mode-btn-quick").classList.toggle("selected", state.tunnelMode === "quick");
    $("mode-btn-token").classList.toggle("selected", state.tunnelMode === "token");

    const isToken = state.tunnelMode === "token";
    $("field-quick-topology").classList.toggle("hidden", isToken);
    $("field-token-domain").classList.toggle("hidden", !isToken);
    $("field-token-secret").classList.toggle("hidden", !isToken);
    $("field-token-guide").classList.toggle("hidden", !isToken);
    updateAuxTunnelVisibility();
  }

  function updateAuxTunnelVisibility() {
    const enabled = $("tun-enabled").checked;
    const isUnifiedQuick = state.tunnelMode === "quick" && $("tun-quick-topology").value === "unified";
    // When unified Quick Tunnel is active, the single tunnel already exposes HTTPS sub & panel
    $("field-aux-panel-tunnel").classList.toggle("hidden", enabled && isUnifiedQuick);
  }

  // ==================== QR Modal ====================
  function openQRModal(title, text) {
    if (!text || text === "-") {
      showToast("链接尚未就绪", true);
      return;
    }
    state.currentQRText = text;
    $("qr-modal-title").textContent = title || "扫码导入";
    $("qr-modal-uri").textContent = text;
    try {
      $("qr-canvas-box").innerHTML = window.SuohaQR.toSVG(text, 2);
      $("qr-modal").classList.remove("hidden");
    } catch (err) {
      showToast(err.message || "生成二维码失败", true);
    }
  }

  function closeQRModal() {
    $("qr-modal").classList.add("hidden");
  }

  // ==================== Event Bindings ====================
  function bindEvents() {
    $("btn-theme-login").addEventListener("click", toggleTheme);
    $("btn-theme-app").addEventListener("click", toggleTheme);

    // Login form
    $("login-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const errBox = $("login-error");
      errBox.classList.add("hidden");
      const btn = $("btn-login-submit");
      btn.disabled = true;
      try {
        await apiFetch("/api/admin/login", {
          method: "POST",
          body: JSON.stringify({
            username: $("login-username").value.trim(),
            password: $("login-password").value
          })
        });
        enterAppView();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.remove("hidden");
      } finally {
        btn.disabled = false;
      }
    });

    // Logout
    $("btn-logout").addEventListener("click", async () => {
      try {
        await apiFetch("/api/admin/logout", { method: "POST" });
      } catch (_) {}
      enterLoginView();
    });

    // Topbar Quick Actions
    $("btn-quick-start").addEventListener("click", async () => {
      try {
        showToast("正在启动 Xray 与 Argo 隧道服务...");
        await apiFetch("/api/admin/service/action", {
          method: "POST",
          body: JSON.stringify({ target: "all", action: "restart" })
        });
        await loadOverview(true);
        schedulePolling(1800);
        showToast("服务启动指令已下发，正在建立隧道");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    $("btn-quick-stop").addEventListener("click", async () => {
      if (!window.confirm("确定要停止当前运行的隧道与 Xray 服务吗？")) return;
      try {
        await apiFetch("/api/admin/service/action", {
          method: "POST",
          body: JSON.stringify({ target: "all", action: "stop" })
        });
        await loadOverview(true);
        showToast("服务已停止");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    $("btn-refresh-all").addEventListener("click", () => {
      loadOverview(true);
      showToast("数据已刷新");
    });

    // Navigation Tabs
    document.querySelectorAll(".nav-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        const target = tab.getAttribute("data-tab");
        state.activeTab = target;
        document.querySelectorAll(".nav-tab").forEach((t) => t.classList.toggle("active", t === tab));
        ["tunnel", "sub", "protocols", "preferred", "settings"].forEach((name) => {
          $("pane-" + name).classList.toggle("hidden", name !== target);
        });
        if (target === "settings") {
          loadLogs();
        }
      });
    });

    // Generic Copy & QR buttons
    document.body.addEventListener("click", (e) => {
      const copyBtn = e.target.closest("[data-copy-target]");
      if (copyBtn) {
        const el = $(copyBtn.getAttribute("data-copy-target"));
        if (el) copyText(el.textContent);
        return;
      }
      const qrBtn = e.target.closest("[data-qr-target]");
      if (qrBtn) {
        const el = $(qrBtn.getAttribute("data-qr-target"));
        const title = qrBtn.getAttribute("data-qr-title");
        if (el) openQRModal(title, el.textContent.trim());
      }
    });

    // Tunnel Mode Selector
    $("mode-btn-quick").addEventListener("click", () => setTunnelModeUI("quick"));
    $("mode-btn-token").addEventListener("click", () => setTunnelModeUI("token"));
    $("tun-enabled").addEventListener("change", updateAuxTunnelVisibility);
    $("tun-quick-topology").addEventListener("change", updateAuxTunnelVisibility);

    $("btn-detect-net").addEventListener("click", async () => {
      try {
        showToast("正在探测本机公网 IPv4 / IPv6...");
        const res = await apiFetch("/api/admin/network/detect", { method: "POST", body: "{}" });
        if (res.network && res.network.ipv6_addr && !$("proto-ss-ipv6").value) {
          $("proto-ss-ipv6").value = res.network.ipv6_addr;
        }
        await loadOverview(false);
        showToast("本机网络出口检测完成");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    $("btn-save-tunnel").addEventListener("click", async () => {
      const btn = $("btn-save-tunnel");
      btn.disabled = true;
      try {
        const payload = {
          enabled: $("tun-enabled").checked,
          mode: state.tunnelMode,
          edge_ip_version: $("tun-edge-ip").value,
          quick_topology: $("tun-quick-topology").value,
          panel_quick_tunnel: $("tun-panel-quick").checked,
          custom_domain: $("tun-custom-domain").value.trim(),
          cf_token: $("tun-cf-token").value.trim()
        };
        await apiFetch("/api/admin/tunnel/apply", {
          method: "POST",
          body: JSON.stringify(payload)
        });
        await loadOverview(true);
        schedulePolling(1800);
        showToast("隧道配置已保存并生效");
      } catch (err) {
        showToast(err.message, true);
      } finally {
        btn.disabled = false;
      }
    });

    // Subscription & Nodes Actions
    $("node-proto-filter").addEventListener("change", () => {
      if (state.overview && state.overview.subscription) {
        renderNodesTable(state.overview.subscription.nodes || []);
      }
    });

    $("btn-copy-all-nodes").addEventListener("click", () => {
      const nodes = (state.overview && state.overview.subscription && state.overview.subscription.nodes) || [];
      if (!nodes.length) {
        showToast("当前暂无可用节点", true);
        return;
      }
      copyText(nodes.map((n) => n.uri).join("\n"), `全部 ${nodes.length} 个节点`);
    });

    $("btn-rotate-sub-uuid").addEventListener("click", async () => {
      if (!window.confirm("重置订阅安全 UUID 后，旧订阅链接将立即失效，客户端需重新导入新链接。确定继续？")) return;
      try {
        await apiFetch("/api/admin/rotate", {
          method: "POST",
          body: JSON.stringify({ target: "sub_uuid" })
        });
        await loadOverview(true);
        showToast("订阅安全路径 UUID 已重置");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    // Protocols Actions
    $("btn-rotate-node-uuid").addEventListener("click", async () => {
      if (!window.confirm("确定重新随机生成节点 UUID 与 WebSocket 路径吗？客户端点击“更新订阅”即可同步。")) return;
      try {
        await apiFetch("/api/admin/rotate", {
          method: "POST",
          body: JSON.stringify({ target: "node_uuid" })
        });
        await loadOverview(true);
        showToast("节点 UUID 与 WS 路径已更新");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    $("btn-fill-ipv6").addEventListener("click", async () => {
      try {
        const res = await apiFetch("/api/admin/network/detect", { method: "POST", body: "{}" });
        if (res.network && res.network.ipv6_addr) {
          $("proto-ss-ipv6").value = res.network.ipv6_addr;
          showToast("检测到公网 IPv6: " + res.network.ipv6_addr);
        } else {
          showToast("未检测到可用的公网 IPv6 地址", true);
        }
      } catch (err) {
        showToast(err.message, true);
      }
    });

    // Reality SNI Pills, Scanner & Key Rotation
    $("proto-reality-sni").addEventListener("input", (e) => {
      highlightRealitySNIPill(e.target.value);
    });

    document.querySelectorAll("#reality-sni-pills .port-pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        const sni = pill.getAttribute("data-sni") || "www.apple.com";
        $("proto-reality-sni").value = sni;
        highlightRealitySNIPill(sni);
      });
    });

    $("btn-regen-reality-keys").addEventListener("click", async () => {
      if (!window.confirm("确定重新生成 Reality X25519 密钥对与 ShortID 吗？更新后客户端点击“更新订阅”即可同步。")) return;
      try {
        const res = await apiFetch("/api/admin/rotate", {
          method: "POST",
          body: JSON.stringify({ target: "reality_keys" })
        });
        if (res.private_key) $("proto-reality-priv").value = res.private_key;
        if (res.public_key) $("proto-reality-pub").value = res.public_key;
        if (res.short_id) $("proto-reality-sid").value = res.short_id;
        await loadOverview(false);
        showToast("Reality 密钥对与 ShortID 已重新生成并同步");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    $("btn-toggle-reality-scan").addEventListener("click", () => {
      const box = $("reality-scanner-box");
      const opening = box.classList.contains("hidden");
      box.classList.toggle("hidden", !opening);
      if (opening && !state.realityScanRan && !state.realityScanning) {
        runRealityScan("preset", "");
      }
    });

    $("btn-verify-reality-sni").addEventListener("click", () => {
      const cur = $("proto-reality-sni").value.trim() || "www.apple.com";
      $("reality-scanner-box").classList.remove("hidden");
      runRealityScan("custom", cur);
    });

    $("btn-scan-preset").addEventListener("click", () => runRealityScan("preset", ""));
    $("btn-scan-neighbor").addEventListener("click", () => runRealityScan("neighbor", ""));
    $("btn-scan-custom").addEventListener("click", () =>
      runRealityScan("custom", $("reality-scan-custom-input").value.trim())
    );
    $("reality-scan-custom-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        runRealityScan("custom", $("reality-scan-custom-input").value.trim());
      }
    });

    $("btn-save-protocols").addEventListener("click", () => saveProtocolsConfig());

    // Preferred IPs & suoha-client Actions
    $("client-platform-select").value = state.clientPlatform;
    $("client-platform-select").addEventListener("change", (e) => {
      state.clientPlatform = e.target.value;
      state.clientPlatformManual = true;
      updateClientCommandsUI();
    });

    if (navigator.userAgentData && typeof navigator.userAgentData.getHighEntropyValues === "function") {
      navigator.userAgentData
        .getHighEntropyValues(["architecture", "platform"])
        .then((info) => {
          if (state.clientPlatformManual) return;
          const plat = String(info.platform || "").toLowerCase();
          const arch = String(info.architecture || "").toLowerCase();
          if (plat.includes("mac")) {
            state.clientPlatform = arch.includes("x86") ? "darwin-amd64" : "darwin-arm64";
          } else if (plat.includes("win")) {
            state.clientPlatform = arch.includes("arm") ? "windows-arm64" : "windows-amd64";
          } else if (plat.includes("linux")) {
            state.clientPlatform = arch.includes("arm") ? "linux-arm64" : "linux-amd64";
          }
          updateClientCommandsUI();
        })
        .catch(() => {});
    }

    $("btn-rotate-client-token").addEventListener("click", async () => {
      if (!window.confirm("重置后正在运行的 suoha-client 需更新 -token 参数。确定重置吗？")) return;
      try {
        await apiFetch("/api/admin/rotate", {
          method: "POST",
          body: JSON.stringify({ target: "client_token" })
        });
        await loadOverview(true);
        showToast("客户端鉴权 Token 已重置");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    $("btn-toggle-batch").addEventListener("click", () => {
      $("batch-import-box").classList.toggle("hidden");
    });

    $("btn-add-pref-row").addEventListener("click", () => {
      syncPrefDraftFromDOM();
      state.prefDraft.push({
        ip: "",
        port: state.selectedCFPort || 443,
        colo: "",
        latency: "",
        speed: "",
        label: ""
      });
      renderPrefTable();
    });

    $("btn-clear-pref").addEventListener("click", async () => {
      if (!window.confirm("确定清空全部动态优选 IP 吗？（保底公共优选域名不受影响）")) return;
      try {
        await apiFetch("/api/admin/preferred/save", {
          method: "POST",
          body: JSON.stringify({ ips: [] })
        });
        await loadOverview(true);
        showToast("动态优选 IP 列表已清空");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    $("btn-save-pref-table").addEventListener("click", async () => {
      syncPrefDraftFromDOM();
      try {
        await apiFetch("/api/admin/preferred/save", {
          method: "POST",
          body: JSON.stringify({ ips: state.prefDraft })
        });
        await loadOverview(true);
        showToast("动态优选 IP 列表已保存并刷新订阅");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    const submitBatch = async (append) => {
      const txt = $("batch-pref-textarea").value.trim();
      if (!txt) {
        showToast("请先粘贴至少一行 IP 或域名", true);
        return;
      }
      try {
        await apiFetch("/api/admin/preferred/save", {
          method: "POST",
          body: JSON.stringify({
            batch_text: txt,
            append_batch: append,
            default_port: state.selectedCFPort || 443
          })
        });
        $("batch-pref-textarea").value = "";
        $("batch-import-box").classList.add("hidden");
        await loadOverview(true);
        showToast("批量优选列表导入成功");
      } catch (err) {
        showToast(err.message, true);
      }
    };

    $("btn-batch-append").addEventListener("click", () => submitBatch(true));
    $("btn-batch-replace").addEventListener("click", () => submitBatch(false));

    // Fallbacks & CF TLS Port Pills
    document.querySelectorAll("#cf-port-pills .port-pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        const port = Number(pill.getAttribute("data-cfport")) || 443;
        state.selectedCFPort = port;
        highlightPortPill(port);
        syncFallbacksDraftFromDOM();
        state.fallbacksDraft.forEach((fb) => {
          fb.port = port;
        });
        renderFallbacksTable();
      });
    });

    $("btn-add-fallback").addEventListener("click", () => {
      syncFallbacksDraftFromDOM();
      state.fallbacksDraft.push({
        enabled: true,
        host: "",
        port: state.selectedCFPort || 443,
        label: ""
      });
      renderFallbacksTable();
    });

    $("btn-save-fallbacks").addEventListener("click", async () => {
      syncFallbacksDraftFromDOM();
      try {
        await apiFetch("/api/admin/preferred/fallbacks", {
          method: "POST",
          body: JSON.stringify({
            fallback_domains: state.fallbacksDraft,
            tls_default_port: state.selectedCFPort || 443,
            apply_port_to_preferred: $("chk-sync-port-pref").checked
          })
        });
        await loadOverview(true);
        showToast("保底优选域名与默认 TLS 端口已更新");
      } catch (err) {
        showToast(err.message, true);
      }
    });

    // Logs & Settings Actions
    $("log-source-filter").addEventListener("change", loadLogs);
    $("btn-refresh-logs").addEventListener("click", loadLogs);
    $("btn-clear-logs").addEventListener("click", async () => {
      await apiFetch("/api/admin/logs/clear", { method: "POST", body: "{}" });
      loadLogs();
      showToast("日志缓存已清空");
    });

    $("btn-save-settings").addEventListener("click", async () => {
      const btn = $("btn-save-settings");
      btn.disabled = true;
      try {
        const newPort = Number($("set-listen-port").value);
        const res = await apiFetch("/api/admin/settings", {
          method: "POST",
          body: JSON.stringify({
            allow_argo_panel: $("set-allow-argo-panel").checked,
            listen_port: newPort,
            server_host_override: $("set-host-override").value.trim(),
            admin_user: $("set-admin-user").value.trim(),
            current_password: $("set-cur-password").value,
            new_password: $("set-new-password").value
          })
        });
        $("set-cur-password").value = "";
        $("set-new-password").value = "";
        showToast("面板设置已保存");

        if (res.port_changed && window.location.port) {
          showToast(`监听端口已切换至 ${res.listen_port}，正在跳转...`);
          setTimeout(() => {
            window.location.port = String(res.listen_port);
          }, 700);
          return;
        }
        await loadOverview(true);
      } catch (err) {
        showToast(err.message, true);
      } finally {
        btn.disabled = false;
      }
    });

    // QR Modal Events
    $("btn-qr-close").addEventListener("click", closeQRModal);
    $("btn-qr-copy").addEventListener("click", () => copyText(state.currentQRText));
    $("qr-modal").addEventListener("click", (e) => {
      if (e.target === $("qr-modal")) closeQRModal();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeQRModal();
    });
  }

  // ==================== Bootstrap ====================
  initTheme();
  bindEvents();
  checkSession();
})();
