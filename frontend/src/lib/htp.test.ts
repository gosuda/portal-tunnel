import { describe, expect, it } from "vitest";

import {
  computeHTPCheck,
  createHTPPacket,
  deobfuscatePacket,
  obfuscatePacket,
  packHTPBlock,
  unpackHTPBlock,
} from "@/lib/htp";

describe("htp", () => {
  describe("obfuscatePacket / deobfuscatePacket", () => {
    it("round-trips a 64-bit value with no rotation", () => {
      const vRaw = 0x123456789abcdef0n;
      const vRot = obfuscatePacket(vRaw, 0);
      expect(vRot).toBe(vRaw);
      expect(deobfuscatePacket(vRot, 0)).toBe(vRaw);
    });

    it("round-trips with small rotation", () => {
      const vRaw = 0x123456789abcdef0n;
      const vRot = obfuscatePacket(vRaw, 7);
      expect(deobfuscatePacket(vRot, 7)).toBe(vRaw);
    });

    it("round-trips with cross-boundary rotation", () => {
      const vRaw = 0x123456789abcdef0n;
      const vRot = obfuscatePacket(vRaw, 31);
      expect(deobfuscatePacket(vRot, 31)).toBe(vRaw);
    });

    it("round-trips with half-word rotation", () => {
      const vRaw = 0x123456789abcdef0n;
      const vRot = obfuscatePacket(vRaw, 32);
      expect(deobfuscatePacket(vRot, 32)).toBe(vRaw);
    });

    it("round-trips with maximum rotation", () => {
      const vRaw = 0x123456789abcdef0n;
      const vRot = obfuscatePacket(vRaw, 63);
      expect(deobfuscatePacket(vRot, 63)).toBe(vRaw);
    });

    it("clamps to 64-bit bounds", () => {
      const vRaw = 0xffffffffffffffffn;
      const vRot = obfuscatePacket(vRaw, 1);
      expect(vRot).toBe(0xffffffffffffffffn);
    });

    it("handles all-zero value", () => {
      const vRaw = 0x0000000000000000n;
      const vRot = obfuscatePacket(vRaw, 17);
      expect(deobfuscatePacket(vRot, 17)).toBe(vRaw);
    });
  });

  describe("packHTPBlock / unpackHTPBlock", () => {
    it("packs and unpacks basic values", () => {
      const packed = packHTPBlock(0x12345678, 0xabcdef, 0x42);
      expect(unpackHTPBlock(packed)).toEqual({
        timestamp: 0x12345678,
        nonce: 0xabcdef,
        htpCheck: 0x42,
      });
    });

    it("masks nonce to 24 bits", () => {
      const packed = packHTPBlock(0, 0xff1234, 0);
      expect(unpackHTPBlock(packed).nonce).toBe(0xff1234);
    });

    it("handles maximum values", () => {
      const packed = packHTPBlock(0xffffffff, 0xffffff, 0xff);
      expect(unpackHTPBlock(packed)).toEqual({
        timestamp: 0xffffffff,
        nonce: 0xffffff,
        htpCheck: 0xff,
      });
    });

    it("handles minimum values", () => {
      const packed = packHTPBlock(0, 0, 0);
      expect(unpackHTPBlock(packed)).toEqual({
        timestamp: 0,
        nonce: 0,
        htpCheck: 0,
      });
    });
  });

  describe("computeHTPCheck", () => {
    it("is deterministic for identical inputs", () => {
      const ts = 0x6655aa77;
      const nonce = 0x123456;
      const S = 0xdeadbeef;

      const first = computeHTPCheck(ts, nonce, S);
      for (let i = 0; i < 100; i++) {
        expect(computeHTPCheck(ts, nonce, S)).toBe(first);
      }
    });

    it("produces different tokens for different nonces", () => {
      const ts = Math.floor(Date.now() / 1000);
      const S = 0xcafebabe;

      const a = computeHTPCheck(ts, 1, S);
      const b = computeHTPCheck(ts, 2, S);
      expect(b).not.toBe(a);
    });

    it("produces different tokens for different seeds", () => {
      const ts = Math.floor(Date.now() / 1000);
      const nonce = 42;

      const a = computeHTPCheck(ts, nonce, 0x11111111);
      const b = computeHTPCheck(ts, nonce, 0x22222222);
      expect(b).not.toBe(a);
    });
  });

  describe("createHTPPacket", () => {
    it("creates a packet that can be deobfuscated and unpacked", () => {
      const ts = Math.floor(Date.now() / 1000);
      const nonce = 7;
      const S = 0xbadc0ffe;
      const k = 23;

      const vRot = createHTPPacket(ts, nonce, S, k);
      const vRaw = deobfuscatePacket(vRot, k);
      const { timestamp, nonce: outNonce, htpCheck } = unpackHTPBlock(vRaw);

      expect(timestamp).toBe(ts);
      expect(outNonce).toBe(nonce);
      expect(htpCheck).toBe(computeHTPCheck(ts, nonce, S));
    });

    it("produces different outputs for different rotation keys", () => {
      const ts = Math.floor(Date.now() / 1000);
      const nonce = 99;
      const S = 0xaabbccdd;

      const a = createHTPPacket(ts, nonce, S, 5);
      const b = createHTPPacket(ts, nonce, S, 11);
      expect(b).not.toBe(a);
    });
  });
});
