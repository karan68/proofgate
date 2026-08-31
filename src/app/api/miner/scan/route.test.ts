import { beforeEach, describe, expect, it } from "vitest";

import { resetRateLimitsForTests } from "../../../../lib/proofgate/access";

import { POST } from "./route";

function request(body: string): Request {
  return new Request("http://localhost/api/miner/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
}

beforeEach(() => resetRateLimitsForTests());

describe("URL_SCAN route", () => {
  it("answers a documented incident question that contains no URL", async () => {
    const response = await POST(
      request(
        JSON.stringify({
          question: "What is documented about Microsoft's 2020 takedown of Necurs?",
        }),
      ),
    );
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(body).toMatchObject({
      intent: "URL_SCAN",
      verdict: "malicious",
      historical_context: { id: "necurs", matched_by: "question" },
    });
    expect(body.live_scan_performed).toBeUndefined();
    expect(body.answer).toContain("more than nine million computers");
  });

  it("returns a scorer-readable abstention for an unknown no-URL question", async () => {
    const response = await POST(
      request(JSON.stringify({ question: "What domains did Example Nebula use?" })),
    );
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      confidence: 0,
      historical_context: null,
    });
    expect(body.live_scan_performed).toBeUndefined();
    expect(body.malicious).toBeUndefined();
    expect(body.answer).toContain("No URL or campaign verdict is claimed");
  });

  it("rejects malformed JSON without losing CORS headers", async () => {
    const response = await POST(request("{"));
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(body).toMatchObject({ error: "invalid_json" });
  });
});