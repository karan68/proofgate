import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parse } from "yaml";

import { GET } from "./route";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("miner.yaml route", () => {
  it("rejects a configured non-local HTTP origin", async () => {
    vi.stubEnv("PROOFGATE_PUBLIC_URL", "http://proofgate.example");

    const response = await GET(
      new NextRequest("http://localhost:3000/miner.yaml"),
    );

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: "miner_config_unavailable",
      message: expect.stringContaining("must use HTTPS"),
    });
  });

  it("emits a secure configured public origin", async () => {
    vi.stubEnv("PROOFGATE_PUBLIC_URL", "https://proofgate.example/");

    const response = await GET(
      new NextRequest("http://localhost:3000/miner.yaml"),
    );
    const config = parse(await response.text());

    expect(response.status).toBe(200);
    expect(config.base_url).toBe("https://proofgate.example");
    expect(config.endpoints[0].external_path).toBe("/api/miner/scan");
  });

  it("allows an HTTP localhost origin for development", async () => {
    vi.stubEnv("PROOFGATE_PUBLIC_URL", "http://localhost:3000");

    const response = await GET(
      new NextRequest("http://localhost:3000/miner.yaml"),
    );
    const config = parse(await response.text());

    expect(response.status).toBe(200);
    expect(config.base_url).toBe("http://localhost:3000");
  });
});