import { describe, expect, it } from "vitest";

import {
  findHistoricalUrlIncident,
  historicalUrlIncidents,
} from "./historical-url-intel";

describe("Historical URL intelligence", () => {
  it.each([
    ["SUNBURST avsvmcloud.com", "sunburst"],
    ["Mirai source code release", "mirai"],
    ["WannaCry kill switch", "wannacry-killswitch"],
    ["Conficker DGA", "conficker"],
    ["Microsoft Necurs takedown", "necurs"],
    ["Operation Tovar GameOver Zeus", "operation-tovar"],
    ["British Airways Magecart", "british-airways-magecart"],
    ["Punycode homograph", "punycode-apple"],
    ["Emotet infrastructure", "emotet"],
    ["fake Google login in the DNC hack", "dnc-google-phishing"],
  ])("matches the public recurring case %s", (question, id) => {
    expect(findHistoricalUrlIncident({ question })?.incident.id).toBe(id);
  });

  it("gives the canonical URL hostname precedence over conflicting question context", () => {
    expect(
      findHistoricalUrlIncident({
        url: "https://iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/",
        question: "What is documented about Mirai?",
      }),
    ).toMatchObject({ matched_by: "hostname", incident: { id: "wannacry-killswitch" } });
  });

  it("does not classify a publisher URL from a campaign name in its path", () => {
    expect(
      findHistoricalUrlIncident({
        url: "https://github.com/example/mirai-source-code",
      }),
    ).toBeNull();
  });

  it("treats a campaign in the question as context for an unrelated URL", () => {
    expect(
      findHistoricalUrlIncident({
        url: "https://github.com/example/mirai-source-code",
        question: "What domains were documented after the Mirai source release?",
      }),
    ).toMatchObject({ matched_by: "question", incident: { id: "mirai" } });
  });

  it("abstains for an unknown campaign instead of guessing", () => {
    expect(
      findHistoricalUrlIncident({
        question: "What domains did the Example Nebula campaign use?",
      }),
    ).toBeNull();
  });

  it("keeps every record sourced and bounded", () => {
    expect(historicalUrlIncidents()).toHaveLength(10);
    for (const incident of historicalUrlIncidents()) {
      expect(incident.facts.length).toBeGreaterThanOrEqual(3);
      expect(incident.sources.length).toBeGreaterThanOrEqual(1);
      expect(incident.sources.every((source) => source.url.startsWith("https://"))).toBe(true);
    }
  });
});