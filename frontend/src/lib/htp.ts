/**
 * Ultra-Lightweight Stream Packet Obfuscation via Hexagonal Tortoise Problem (HTP)
 * Congruence and Circular Bit Rotation.
 *
 * This module implements the client-side outbound obfuscation pipeline:
 *   1. Compute the HTP modular checksum.
 *   2. Pack timestamp, nonce, and checksum into a 64-bit block.
 *   3. Apply ring bitwise rotation (circular left shift).
 */

/**
 * Applies a circular left rotation to a 64-bit raw value.
 *
 * V_rot = (V_raw << k) | (V_raw >> (64 - k))
 */
export function obfuscatePacket(vRaw: bigint, k: number): bigint {
  const shift = BigInt.asUintN(64, BigInt(k)) % 64n;
  if (shift === 0n) {
    return vRaw & 0xFFFFFFFFFFFFFFFFn;
  }
  const vRot = (vRaw << shift) | (vRaw >> (64n - shift));
  return vRot & 0xFFFFFFFFFFFFFFFFn;
}

/**
 * Applies the inverse circular right rotation.
 *
 * V_raw = (V_rot >> k) | (V_rot << (64 - k))
 */
export function deobfuscatePacket(vRot: bigint, k: number): bigint {
  const shift = BigInt.asUintN(64, BigInt(k)) % 64n;
  if (shift === 0n) {
    return vRot & 0xFFFFFFFFFFFFFFFFn;
  }
  const vRaw = (vRot >> shift) | (vRot << (64n - shift));
  return vRaw & 0xFFFFFFFFFFFFFFFFn;
}

/**
 * Packs timestamp, nonce, and HTP check into a 64-bit transmission block.
 *
 *   Bits [63:32] : timestamp (uint32)
 *   Bits [31:8]  : nonce     (uint24)
 *   Bits [7:0]   : htpCheck  (uint8)
 */
export function packHTPBlock(
  timestamp: number,
  nonce: number,
  htpCheck: number,
): bigint {
  const t = BigInt.asUintN(32, BigInt(timestamp));
  const n = BigInt.asUintN(24, BigInt(nonce));
  const h = BigInt.asUintN(8, BigInt(htpCheck));
  return (t << 32n) | (n << 8n) | h;
}

/**
 * Unpacks the 64-bit transmission block into its three fields.
 */
export function unpackHTPBlock(vRaw: bigint): {
  timestamp: number;
  nonce: number;
  htpCheck: number;
} {
  const raw = vRaw & 0xFFFFFFFFFFFFFFFFn;
  const timestamp = Number(raw >> 32n);
  const nonce = Number((raw >> 8n) & 0xFFFFFFn);
  const htpCheck = Number(raw & 0xFFn);
  return { timestamp, nonce, htpCheck };
}

/**
 * splitmix64 is a fast 64-bit PRNG used to expand a seed into 12 uint32 vertices.
 */
function splitmix64(x: bigint): bigint {
  let z = (x + 0x9e3779b97f4a7c15n) & 0xFFFFFFFFFFFFFFFFn;
  z = (z ^ (z >> 30n)) & 0xFFFFFFFFFFFFFFFFn;
  z = (z * 0xbf58476d1ce4e5b9n) & 0xFFFFFFFFFFFFFFFFn;
  z = (z ^ (z >> 27n)) & 0xFFFFFFFFFFFFFFFFn;
  z = (z * 0x94d049bb133111ebn) & 0xFFFFFFFFFFFFFFFFn;
  z = (z ^ (z >> 31n)) & 0xFFFFFFFFFFFFFFFFn;
  return z;
}

/**
 * Expands a seed into 12 uint32 vertices following the HTP 3-hexagon grid.
 *
 *   H1: v0, v1, v2, v3, v4, v5
 *   H2: v4, v5, v6, v7, v8, v9
 *   H3: v2, v3, v4, v6, v10, v11
 */
function htpVertices(seed: bigint): number[] {
  const v: number[] = [];
  let x = seed & 0xFFFFFFFFFFFFFFFFn;
  for (let i = 0; i < 12; i++) {
    x = splitmix64(x);
    v.push(Number(x & 0xFFFFFFFFn));
  }
  return v;
}

/**
 * Computes the 8-bit HTP congruence token.
 *
 * @param timestamp - 32-bit Unix epoch timestamp.
 * @param nonce     - 24-bit monotonic counter.
 * @param S         - 32-bit seed from the TLS 1.3 handshake.
 */
export function computeHTPCheck(
  timestamp: number,
  nonce: number,
  S: number,
): number {
  const raw =
    (BigInt.asUintN(32, BigInt(timestamp)) << 32n) |
    (BigInt.asUintN(24, BigInt(nonce)) << 8n);
  const seed = raw ^ BigInt.asUintN(64, BigInt(S));
  const v = htpVertices(seed);

  // Hexagon sums modulo 2^32 (native unsigned 32-bit overflow).
  const h1 = (v[0] + v[1] + v[2] + v[3] + v[4] + v[5]) >>> 0;
  const h2 = (v[4] + v[5] + v[6] + v[7] + v[8] + v[9]) >>> 0;
  const h3 = (v[2] + v[3] + v[4] + v[6] + v[10] + v[11]) >>> 0;

  const s32 = BigInt.asUintN(32, BigInt(S));
  const check = (h1 ^ h2 ^ h3 ^ Number(s32)) >>> 0;
  return check & 0xFF;
}

/**
 * Creates a complete obfuscated HTP packet ready for transmission.
 *
 * @param timestamp - Current Unix epoch time.
 * @param nonce     - Next monotonic counter value.
 * @param S         - Shared 32-bit seed.
 * @param k         - Rotation parameter (0 < k < 64).
 */
export function createHTPPacket(
  timestamp: number,
  nonce: number,
  S: number,
  k: number,
): bigint {
  const htpCheck = computeHTPCheck(timestamp, nonce, S);
  const vRaw = packHTPBlock(timestamp, nonce, htpCheck);
  return obfuscatePacket(vRaw, k);
}
