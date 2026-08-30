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
    expect(config.endpoints[0].intents).toEqual(["URL_SCAN"]);
    expect(config.endpoints[0].params.body.required).toEqual([
      expect.objectContaining({
        name: "url",
        type: "string",
        intents: ["URL_SCAN"],
      }),
    ]);
    expect(config.input_schema.properties.question).toMatchObject({
      type: "string",
      maxLength: 4096,
    });
    expect(config.output_schema.required).toContain("answer");
    expect(config.semantics.signal_mapping.reason_field).toBe("answer");
    const mappedFields = [
      ...config.on_chain.fields.strings,
      ...config.on_chain.fields.integers,
      ...config.on_chain.fields.bools,
    ];
    expect(mappedFields).toHaveLength(4);
    expect(mappedFields.every((field: { description?: string }) => {
      return typeof field.description === "string" && field.description.length > 0;
    })).toBe(true);
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