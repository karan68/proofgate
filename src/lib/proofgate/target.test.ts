import { describe, expect, it } from "vitest";

import {
  assertPublicTarget,
  isPublicAddress,
  normalizeTargetUrl,
  TargetValidationError,
} from "./target";

describe("target validation", () => {
  it("normalizes a public HTTPS URL and removes fragments", () => {
    expect(normalizeTargetUrl(" HTTPS://Example.COM/path?q=1#secret ")).toEqual({
      url: "https://example.com/path?q=1",
      hostname: "example.com",
      registrableDomain: "example.com",
      protocol: "https:",
      port: "443",
    });
  });

  it.each([
    "file:///etc/passwd",
    "http://localhost/admin",
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]/",
    "https://user:pass@example.com/",
    "https://service.internal/",
  ])("rejects unsafe target %s", (target) => {
    expect(() => normalizeTargetUrl(target)).toThrow(TargetValidationError);
  });

  it.each([
    ["8.8.8.8", true],
    ["1.1.1.1", true],
    ["10.0.0.1", false],
    ["100.64.0.1", false],
    ["169.254.1.1", false],
    ["::1", false],
    ["fc00::1", false],
  ])("classifies %s public=%s", (address, expected) => {
    expect(isPublicAddress(address)).toBe(expected);
  });

  it("rejects DNS rebinding to a private address", async () => {
    await expect(
      assertPublicTarget("https://example.com", {
        lookup: async () => ["93.184.216.34", "127.0.0.1"],
      }),
    ).rejects.toThrow("resolves to a private");
  });

  it("allows a public resolution and blocks uncommon execution ports", async () => {
    await expect(
      assertPublicTarget("https://example.com", {
        lookup: async () => ["93.184.216.34"],
      }),
    ).resolves.toMatchObject({ addresses: ["93.184.216.34"] });

    await expect(
      assertPublicTarget("https://example.com:8443", {
        lookup: async () => ["93.184.216.34"],
      }),
    ).rejects.toThrow("standard HTTP");
  });
});