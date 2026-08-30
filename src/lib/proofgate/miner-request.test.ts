import { describe, expect, it } from "vitest";

import { scanUrlFromBody } from "./miner-request";

describe("Miner scan request compatibility", () => {
  it("accepts the documented URL field", () => {
    expect(scanUrlFromBody({ url: "https://example.com/path" })).toBe(
      "https://example.com/path",
    );
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

  it("rejects payloads without an HTTP or HTTPS URL", () => {
    expect(() => scanUrlFromBody({ question: "Scan example.com" })).toThrow(
      "Provide one complete http:// or https:// URL.",
    );
  });
});