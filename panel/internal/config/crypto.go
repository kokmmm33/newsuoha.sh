package config

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const defaultPBKDF2Iterations = 120000

// HashPassword hashes a plaintext password with PBKDF2-HMAC-SHA256 using random 16-byte salt.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt, defaultPBKDF2Iterations, 32)
	return fmt.Sprintf("pbkdf2$%d$%s$%s", defaultPBKDF2Iterations, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// VerifyPassword checks plaintext password against a stored PBKDF2 hash in constant time.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters < 1000 || iters > 2000000 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return false
	}
	expected, err := hex.DecodeString(parts[3])
	if err != nil || len(expected) == 0 {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, iters, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// pbkdf2SHA256 implements RFC 2898 PBKDF2-HMAC-SHA256 using only Go stdlib.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	var blockBuf [4]byte

	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
		msg := make([]byte, len(salt)+4)
		copy(msg, salt)
		copy(msg[len(salt):], blockBuf[:])

		u := prf(password, msg)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iter; i++ {
			u = prf(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// NewUUID generates an RFC 4122 version 4 UUID using crypto/rand.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// RandomHex returns n random bytes encoded as 2*n lowercase hex characters.
func RandomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RandomPassword generates an unambiguous alphanumeric password of length n.
func RandomPassword(length int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	if length <= 0 {
		length = 12
	}
	b := make([]byte, length)
	_, _ = rand.Read(b)
	out := make([]byte, length)
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out)
}

// RandomPortInRange returns a random port in [min, max].
func RandomPortInRange(min, max int) int {
	if max <= min {
		return min
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	span := uint32(max - min + 1)
	return min + int(binary.BigEndian.Uint32(b[:])%span)
}
