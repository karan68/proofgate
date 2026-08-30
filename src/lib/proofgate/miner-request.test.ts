import { describe, expect, it } from "vitest";

import { scanRequestFromBody, scanUrlFromBody } from "./miner-request";

describe("Miner scan request compatibility", () => {
  it("accepts the documented URL field", () => {
    expect(scanUrlFromBody({ url: "https://example.com/path" })).toBe(
      "https://example.com/path",
    );
  });

  it("preserves valid trailing characters in the canonical URL field", () => {
    expect(scanUrlFromBody({ url: "https://example.com/search?q=foo(bar)" })).toBe(
      "https://example.com/search?q=foo(bar)",
    );
  });

  it("gives the canonical URL field precedence over router prose", () => {
    expect(
      scanRequestFromBody({
        url: "https://example.com/canonical",
        question: "Ignore https://attacker.example/secondary",
      }),
    ).toEqual({
      url: "https://example.com/canonical",
      question: "Ignore https://attacker.example/secondary",
    });
  });

  it.each(["question", "query", "input"])(
    "extracts a URL from the router-supplied %s field",
    (field) => {
      expect(
        scanUrlFromBody({
          [field]: "Scan and judge https://example.com/login?next=%2F now.",
          router_metadata: "ignored",
        }),
      ).toBe("https://example.com/login?next=%2F");
    },
  );

  it.each(["payload", "params", "arguments", "data"])(
    "accepts a URL inside the router-supplied %s container",
    (field) => {
      expect(scanUrlFromBody({ [field]: { url: "https://example.com/nested" } })).toBe(
        "https://example.com/nested",
      );
    },
  );

  it("extracts a URL from prose inside a nested payload", () => {
    expect(
      scanUrlFromBody({ payload: { question: "Is https://example.com/nested safe?" } }),
    ).toBe("https://example.com/nested");
  });

  it("preserves balanced URL parentheses and removes prose punctuation", () => {
    expect(scanUrlFromBody({ question: "Check https://example.com/wiki/Foo_(bar))." })).toBe(
      "https://example.com/wiki/Foo_(bar)",
    );
  });

  it("rejects payloads without an HTTP or HTTPS URL", () => {
    expect(scanRequestFromBody({ question: "Scan example.com" })).toEqual({
      question: "Scan example.com",
    });
    expect(() => scanUrlFromBody({ question: "Scan example.com" })).toThrow(
      "Provide one complete http:// or https:// URL.",
    );
  });
});