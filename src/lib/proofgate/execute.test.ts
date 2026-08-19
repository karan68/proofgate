import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { executeGuardedTarget, TargetExecutionError } from "./execute";

const publicLookup = async () => ["93.184.216.34"];

function fetcher(response: Response) {
  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    void input;
    void init;
    return response;
  });
  return mock as typeof mock & typeof fetch;
}

beforeEach(() => {
  vi.stubEnv("TELEGRAPH_EVM_PRIVATE_KEY", `0x${"11".repeat(32)}`);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("executeGuardedTarget", () => {
  it("performs a bounded GET and sanitizes its text preview", async () => {
    const baseFetch = fetcher(
      new Response("safe\u0000 response", {
        status: 200,
        headers: { "content-type": "text/plain" },
      }),
    );

    const result = await executeGuardedTarget("https://example.com/path", {
      lookup: publicLookup,
      baseFetch,
      maxBytes: 64,
    });

    expect(result).toMatchObject({
      attempted: true,
      status: 200,
      bytes: 14,
      final_url: "https://example.com/path",
      preview: "safe response",
    });
    expect(baseFetch).toHaveBeenCalledOnce();
    const request = baseFetch.mock.calls[0][0] as Request;
    expect(request.url).toBe("https://example.com/path");
    expect(request.method).toBe("GET");
    expect(request.redirect).toBe("manual");
  });

  it("does not read a response body for HEAD", async () => {
    const baseFetch = fetcher(
      new Response("body must be ignored", {
        status: 200,
        headers: { "content-type": "text/plain", "content-length": "999999" },
      }),
    );

    const result = await executeGuardedTarget("https://example.com", {
      method: "HEAD",
      lookup: publicLookup,
      baseFetch,
      maxBytes: 1,
    });

    expect(result.bytes).toBe(0);
    const request = baseFetch.mock.calls[0][0] as Request;
    expect(request.url).toBe("https://example.com/");
    expect(request.method).toBe("HEAD");
    expect(request.redirect).toBe("manual");
  });

  it("reports redirects without following them", async () => {
    const baseFetch = fetcher(
      new Response(null, {
        status: 302,
        headers: { location: "https://example.net/next" },
      }),
    );

    const result = await executeGuardedTarget("https://example.com", {
      lookup: publicLookup,
      baseFetch,
    });

    expect(result).toMatchObject({
      status: 302,
      redirect_location: "https://example.net/next",
      bytes: 0,
    });
  });

  it("accepts a response exactly at the configured byte limit", async () => {
    const baseFetch = fetcher(
      new Response("1234", {
        headers: { "content-type": "text/plain", "content-length": "4" },
      }),
    );

    const result = await executeGuardedTarget("https://example.com", {
      lookup: publicLookup,
      baseFetch,
      maxBytes: 4,
    });

    expect(result.bytes).toBe(4);
  });

  it("rejects a declared body larger than the configured limit", async () => {
    const baseFetch = fetcher(
      new Response("12345", {
        headers: { "content-length": "5" },
      }),
    );

    await expect(
      executeGuardedTarget("https://example.com", {
        lookup: publicLookup,
        baseFetch,
        maxBytes: 4,
      }),
    ).rejects.toThrow(new TargetExecutionError("Target response exceeds the 4-byte limit."));
  });

  it("rejects a streamed body once it crosses the configured limit", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]));
        controller.enqueue(new Uint8Array([4, 5]));
        controller.close();
      },
    });
    const baseFetch = fetcher(new Response(body));

    await expect(
      executeGuardedTarget("https://example.com", {
        lookup: publicLookup,
        baseFetch,
        maxBytes: 4,
      }),
    ).rejects.toThrow(new TargetExecutionError("Target response exceeds the 4-byte limit."));
  });

  it("rejects private DNS results before invoking fetch", async () => {
    const baseFetch = fetcher(new Response("must not run"));

    await expect(
      executeGuardedTarget("https://example.com", {
        lookup: async () => ["127.0.0.1"],
        baseFetch,
      }),
    ).rejects.toThrow("private, loopback, or reserved address");
    expect(baseFetch).not.toHaveBeenCalled();
  });
});