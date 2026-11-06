/*!
 * Compact self-contained ISO/IEC 18004 QR Code SVG Generator (Versions 1-25, EC Level L, UTF-8 Byte Mode)
 * Zero external dependencies. Works 100% offline.
 */
(function (global) {
  "use strict";

  // ISO/IEC 18004 Table 9 — EC Level L (01) for Versions 1..25
  const EC_CODEWORDS_PER_BLOCK = [
    0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18,
    20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
    28, 28, 30, 30, 26
  ];
  const NUM_ERROR_CORRECTION_BLOCKS = [
    0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4,
    4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
    8, 9, 9, 10, 12
  ];

  // ISO/IEC 18004 Annex E Table E.1 — Alignment pattern center coordinates for Versions 1..25
  const ALIGNMENT_COORDS = [
    [],
    [],
    [6, 18],
    [6, 22],
    [6, 26],
    [6, 30],
    [6, 34],
    [6, 22, 38],
    [6, 24, 42],
    [6, 26, 46],
    [6, 28, 50],
    [6, 30, 54],
    [6, 32, 58],
    [6, 34, 62],
    [6, 26, 46, 66],
    [6, 26, 48, 70],
    [6, 26, 50, 74],
    [6, 30, 54, 78],
    [6, 30, 56, 82],
    [6, 30, 58, 86],
    [6, 34, 62, 90],
    [6, 28, 50, 72, 94],
    [6, 26, 50, 74, 98],
    [6, 30, 54, 78, 102],
    [6, 28, 54, 80, 106],
    [6, 32, 58, 84, 110]
  ];

  function getNumRawDataModules(ver) {
    let result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
      const numAlign = Math.floor(ver / 7) + 2;
      result -= (25 * numAlign - 10) * numAlign - 55;
      if (ver >= 7) {
        result -= 36;
      }
    }
    return result;
  }

  function reedSolomonComputeDivisor(degree) {
    const result = new Uint8Array(degree);
    result[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i++) {
      for (let j = 0; j < degree; j++) {
        result[j] = gfMultiply(result[j], root);
        if (j + 1 < degree) {
          result[j] ^= result[j + 1];
        }
      }
      root = gfMultiply(root, 0x02);
    }
    return result;
  }

  function reedSolomonComputeRemainder(data, divisor) {
    const result = new Uint8Array(divisor.length);
    for (let i = 0; i < data.length; i++) {
      const factor = data[i] ^ result[0];
      result.copyWithin(0, 1);
      result[result.length - 1] = 0;
      for (let j = 0; j < divisor.length; j++) {
        result[j] ^= gfMultiply(divisor[j], factor);
      }
    }
    return result;
  }

  function gfMultiply(x, y) {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11d);
      z ^= ((y >>> i) & 1) * x;
    }
    return z;
  }

  function appendBits(val, len, bb) {
    for (let i = len - 1; i >= 0; i--) {
      bb.push((val >>> i) & 1);
    }
  }

  function getBit(x, i) {
    return ((x >>> i) & 1) !== 0;
  }

  function encodeQRMatrix(text) {
    const bytes = new TextEncoder().encode(String(text || ""));
    let version = 1;
    let dataCapacityBits = 0;

    for (; version <= 25; version++) {
      const numDataCodewords =
        Math.floor(getNumRawDataModules(version) / 8) -
        EC_CODEWORDS_PER_BLOCK[version] * NUM_ERROR_CORRECTION_BLOCKS[version];
      dataCapacityBits = numDataCodewords * 8;
      const ccBits = version <= 9 ? 8 : 16;
      const neededBits = 4 + ccBits + bytes.length * 8;
      if (neededBits <= dataCapacityBits) {
        break;
      }
    }
    if (version > 25) {
      throw new Error("QR 内容过长，超出二维码容量上限");
    }

    const bb = [];
    appendBits(0x4, 4, bb); // Byte mode
    appendBits(bytes.length, version <= 9 ? 8 : 16, bb);
    for (let i = 0; i < bytes.length; i++) {
      appendBits(bytes[i], 8, bb);
    }

    appendBits(0, Math.min(4, dataCapacityBits - bb.length), bb);
    appendBits(0, (8 - (bb.length % 8)) % 8, bb);

    const dataCodewords = new Uint8Array(dataCapacityBits / 8);
    for (let i = 0; i < bb.length; i++) {
      dataCodewords[i >>> 3] |= bb[i] << (7 - (i & 7));
    }
    let padIdx = Math.floor(bb.length / 8);
    for (let padByte = 0xec; padIdx < dataCodewords.length; padIdx++, padByte ^= 0xec ^ 0x11) {
      dataCodewords[padIdx] = padByte;
    }

    // Add Reed-Solomon EC and interleave blocks
    const allCodewords = addEccAndInterleave(dataCodewords, version);

    // Build matrix
    const size = version * 4 + 17;
    const modules = Array.from({ length: size }, () => new Uint8Array(size));
    const isFunction = Array.from({ length: size }, () => new Uint8Array(size));

    drawFunctionPatterns(version, size, modules, isFunction);
    drawCodewords(allCodewords, size, modules, isFunction);

    // Select optimal mask (0..7)
    let bestMask = 0;
    let minPenalty = Infinity;
    for (let msk = 0; msk < 8; msk++) {
      applyMask(msk, size, modules, isFunction);
      drawFormatBits(msk, size, modules, isFunction);
      const pen = getPenaltyScore(size, modules);
      if (pen < minPenalty) {
        minPenalty = pen;
        bestMask = msk;
      }
      applyMask(msk, size, modules, isFunction); // revert XOR
    }

    applyMask(bestMask, size, modules, isFunction);
    drawFormatBits(bestMask, size, modules, isFunction);
    return { size, modules };
  }

  function addEccAndInterleave(data, ver) {
    const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[ver];
    const blockEccLen = EC_CODEWORDS_PER_BLOCK[ver];
    const rawCodewords = Math.floor(getNumRawDataModules(ver) / 8);
    const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
    const shortBlockLen = Math.floor(rawCodewords / numBlocks);

    const blocks = [];
    const rsDiv = reedSolomonComputeDivisor(blockEccLen);
    for (let i = 0, k = 0; i < numBlocks; i++) {
      const datLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
      const dat = data.subarray(k, k + datLen);
      k += datLen;
      const ecc = reedSolomonComputeRemainder(dat, rsDiv);
      const block = new Uint8Array(shortBlockLen + 1);
      block.set(dat, 0);
      block.set(ecc, shortBlockLen + 1 - blockEccLen);
      blocks.push({ dat, ecc });
    }

    const result = new Uint8Array(rawCodewords);
    let pos = 0;
    const maxDatLen = shortBlockLen - blockEccLen + 1;
    for (let i = 0; i < maxDatLen; i++) {
      for (let j = 0; j < blocks.length; j++) {
        if (i < blocks[j].dat.length) {
          result[pos++] = blocks[j].dat[i];
        }
      }
    }
    for (let i = 0; i < blockEccLen; i++) {
      for (let j = 0; j < blocks.length; j++) {
        result[pos++] = blocks[j].ecc[i];
      }
    }
    return result;
  }

  function setFunctionModule(x, y, isDark, modules, isFunction) {
    modules[y][x] = isDark ? 1 : 0;
    isFunction[y][x] = 1;
  }

  function drawFinderPattern(cx, cy, size, modules, isFunction) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const xx = cx + dx;
        const yy = cy + dy;
        if (xx >= 0 && xx < size && yy >= 0 && yy < size) {
          setFunctionModule(xx, yy, dist !== 2 && dist !== 4, modules, isFunction);
        }
      }
    }
  }

  function drawAlignmentPattern(cx, cy, modules, isFunction) {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) {
        setFunctionModule(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1, modules, isFunction);
      }
    }
  }

  function drawFunctionPatterns(ver, size, modules, isFunction) {
    for (let i = 0; i < size; i++) {
      setFunctionModule(6, i, i % 2 === 0, modules, isFunction);
      setFunctionModule(i, 6, i % 2 === 0, modules, isFunction);
    }

    drawFinderPattern(3, 3, size, modules, isFunction);
    drawFinderPattern(size - 4, 3, size, modules, isFunction);
    drawFinderPattern(3, size - 4, size, modules, isFunction);

    const alignPatPos = ALIGNMENT_COORDS[ver];
    const numAlign = alignPatPos.length;
    for (let i = 0; i < numAlign; i++) {
      for (let j = 0; j < numAlign; j++) {
        if (
          !(
            (i === 0 && j === 0) ||
            (i === 0 && j === numAlign - 1) ||
            (i === numAlign - 1 && j === 0)
          )
        ) {
          drawAlignmentPattern(alignPatPos[i], alignPatPos[j], modules, isFunction);
        }
      }
    }

    drawFormatBits(0, size, modules, isFunction);
    if (ver >= 7) {
      let rem = ver;
      for (let i = 0; i < 12; i++) {
        rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
      }
      const bits = (ver << 12) | rem;
      for (let i = 0; i < 18; i++) {
        const color = getBit(bits, i);
        const a = size - 11 + (i % 3);
        const b = Math.floor(i / 3);
        setFunctionModule(a, b, color, modules, isFunction);
        setFunctionModule(b, a, color, modules, isFunction);
      }
    }
  }

  function drawFormatBits(mask, size, modules, isFunction) {
    // EC Level L format indicator = 01 (1)
    const data = (0x01 << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) {
      rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    }
    const bits = ((data << 10) | rem) ^ 0x5412;

    for (let i = 0; i <= 5; i++) setFunctionModule(8, i, getBit(bits, i), modules, isFunction);
    setFunctionModule(8, 7, getBit(bits, 6), modules, isFunction);
    setFunctionModule(8, 8, getBit(bits, 7), modules, isFunction);
    setFunctionModule(7, 8, getBit(bits, 8), modules, isFunction);
    for (let i = 9; i < 15; i++) setFunctionModule(14 - i, 8, getBit(bits, i), modules, isFunction);

    for (let i = 0; i < 8; i++) setFunctionModule(size - 1 - i, 8, getBit(bits, i), modules, isFunction);
    for (let i = 8; i < 15; i++) setFunctionModule(8, size - 15 + i, getBit(bits, i), modules, isFunction);
    setFunctionModule(8, size - 8, true, modules, isFunction);
  }

  function drawCodewords(data, size, modules, isFunction) {
    let i = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? size - 1 - vert : vert;
          if (!isFunction[y][x] && i < data.length * 8) {
            modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7)) ? 1 : 0;
            i++;
          }
        }
      }
    }
  }

  function applyMask(mask, size, modules, isFunction) {
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (isFunction[y][x]) continue;
        let invert = false;
        switch (mask) {
          case 0: invert = (x + y) % 2 === 0; break;
          case 1: invert = y % 2 === 0; break;
          case 2: invert = x % 3 === 0; break;
          case 3: invert = (x + y) % 3 === 0; break;
          case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
          case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          case 7: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
        }
        if (invert) modules[y][x] ^= 1;
      }
    }
  }

  function getPenaltyScore(size, modules) {
    let result = 0;
    // Adjacent modules in row/col having same color
    for (let y = 0; y < size; y++) {
      let runColor = modules[y][0];
      let runX = 1;
      for (let x = 1; x < size; x++) {
        if (modules[y][x] === runColor) {
          runX++;
          if (runX === 5) result += 3;
          else if (runX > 5) result++;
        } else {
          runColor = modules[y][x];
          runX = 1;
        }
      }
    }
    for (let x = 0; x < size; x++) {
      let runColor = modules[0][x];
      let runY = 1;
      for (let y = 1; y < size; y++) {
        if (modules[y][x] === runColor) {
          runY++;
          if (runY === 5) result += 3;
          else if (runY > 5) result++;
        } else {
          runColor = modules[y][x];
          runY = 1;
        }
      }
    }
    // 2x2 blocks of same color
    for (let y = 0; y < size - 1; y++) {
      for (let x = 0; x < size - 1; x++) {
        const c = modules[y][x];
        if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) {
          result += 3;
        }
      }
    }
    return result;
  }

  function renderQRToSVG(text, border) {
    const quiet = typeof border === "number" ? border : 2;
    const { size, modules } = encodeQRMatrix(text);
    const total = size + quiet * 2;
    const parts = [];
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (modules[y][x]) {
          parts.push(`M${x + quiet},${y + quiet}h1v1h-1z`);
        }
      }
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="crispEdges" class="qr-svg" role="img" aria-label="QR Code"><rect width="100%" height="100%" fill="#ffffff"/><path d="${parts.join("")}" fill="#0f1419"/></svg>`;
  }

  global.SuohaQR = {
    toSVG: renderQRToSVG,
    encode: encodeQRMatrix
  };
})(typeof window !== "undefined" ? window : globalThis);
