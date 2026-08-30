export type HistoricalDisposition = "malicious" | "defensive" | "demonstration";

export interface HistoricalSource {
  name: string;
  url: string;
}

export interface HistoricalUrlIncident {
  id: string;
  name: string;
  disposition: HistoricalDisposition;
  domains: readonly string[];
  terms: readonly string[];
  facts: readonly string[];
  sources: readonly HistoricalSource[];
}

export interface HistoricalUrlMatch {
  incident: HistoricalUrlIncident;
  matched_by: "hostname" | "question";
}

const INCIDENTS: readonly HistoricalUrlIncident[] = [
  {
    id: "sunburst",
    name: "SUNBURST SolarWinds supply-chain compromise",
    disposition: "malicious",
    domains: ["avsvmcloud.com"],
    terms: ["sunburst", "solarwinds", "solorigate", "avsvmcloud.com"],
    facts: [
      "FireEye disclosed SUNBURST on December 13, 2020 after finding the backdoor in trojanized SolarWinds Orion updates.",
      "SUNBURST generated and resolved victim-specific subdomains of avsvmcloud.com; CNAME responses directed selected victims to active command-and-control servers.",
      "The avsvmcloud.com infrastructure was part of the malicious command-and-control chain, not an ordinary SolarWinds service.",
    ],
    sources: [
      {
        name: "Mandiant: SUNBURST backdoor analysis",
        url: "https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor",
      },
    ],
  },
  {
    id: "mirai",
    name: "Mirai botnet source-code release",
    disposition: "malicious",
    domains: [],
    terms: ["mirai", "anna-senpai", "anna senpai"],
    facts: [
      "Mirai was the IoT botnet malware behind record-breaking September 2016 DDoS attacks on KrebsOnSecurity and hosting provider OVH.",
      "A Hack Forums user named Anna-senpai publicly released Mirai's source code on September 30, 2016; KrebsOnSecurity reported the release on October 1.",
      "USENIX Security 2017 research traced command-and-control domains across post-release Mirai variant clusters, including domains whose DNS lookup activity began months before their later use as command-and-control infrastructure.",
    ],
    sources: [
      {
        name: "KrebsOnSecurity: Source Code for IoT Botnet Mirai Released",
        url: "https://krebsonsecurity.com/2016/10/source-code-for-iot-botnet-mirai-released/",
      },
      {
        name: "USENIX Security 2017: Understanding the Mirai Botnet",
        url: "https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis",
      },
    ],
  },
  {
    id: "wannacry-killswitch",
    name: "WannaCry kill-switch domain",
    disposition: "defensive",
    domains: ["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"],
    terms: ["wannacry", "wannacrypt", "kill-switch", "kill switch", "killswitch"],
    facts: [
      "This was the WannaCry ransomware kill-switch domain: security researcher Marcus Hutchins found it hardcoded into the malware as an unregistered connection check.",
      "Hutchins defensively registered and sinkholed it on May 12, 2017, causing WannaCry to treat the response as a signal to exit instead of encrypting files or spreading.",
      "The registration halted the initial outbreak's spread; the domain itself was benign even though the ransomware that queried it was malicious.",
    ],
    sources: [
      {
        name: "Microsoft: WannaCrypt ransomware worm targets out-of-date systems",
        url: "https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/",
      },
      {
        name: "MalwareTech: How to Accidentally Stop a Global Cyber Attack",
        url: "https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html",
      },
    ],
  },
  {
    id: "conficker",
    name: "Conficker domain-generation algorithm",
    disposition: "malicious",
    domains: [],
    terms: ["conficker", "downadup"],
    facts: [
      "Conficker used the current date to generate pseudo-random command-and-control domains instead of relying on fixed addresses.",
      "Its A and B variants generated 250 candidate domains per day across 110 top-level domains.",
      "Conficker.C expanded this on April 1, 2009 to 50,000 candidate domains per day across 116 top-level domains and attempted to contact 500, complicating defensive pre-registration and sinkholing.",
    ],
    sources: [
      {
        name: "ICANN: Conficker Summary and Review",
        url: "https://www.icann.org/en/system/files/files/conficker-summary-review-07may10-en.pdf",
      },
    ],
  },
  {
    id: "necurs",
    name: "Necurs botnet takedown",
    disposition: "malicious",
    domains: [],
    terms: ["necurs"],
    facts: [
      "On March 10, 2020, Microsoft and partners in 35 countries announced legal and technical action against Necurs, a botnet that had infected more than nine million computers.",
      "Microsoft analyzed Necurs' domain-generation algorithm and predicted more than six million unique domains it would create over the following 25 months.",
      "Registries were given the predicted domains so they could be blocked before the botnet operators registered and used them.",
    ],
    sources: [
      {
        name: "Microsoft: New action to disrupt world's largest online criminal network",
        url: "https://blogs.microsoft.com/on-the-issues/2020/03/10/necurs-botnet-cyber-crime-disrupt/",
      },
    ],
  },
  {
    id: "operation-tovar",
    name: "Operation Tovar and GameOver Zeus",
    disposition: "malicious",
    domains: [],
    terms: ["operation tovar", "gameover zeus", "game over zeus", "cryptolocker"],
    facts: [
      "Operation Tovar was executed around May 30, 2014 by the FBI, the UK's National Crime Agency, Europol, and private partners to disrupt the peer-to-peer GameOver Zeus botnet.",
      "GameOver Zeus used a fallback domain-generation algorithm that produced pseudo-random domains as a backup command-and-control channel.",
      "After the takedown, a July 2014 variant replaced peer-to-peer control with a purely DGA-based command model that generated roughly 1,000 new domains each day.",
    ],
    sources: [
      {
        name: "Europol: International action against GameOver Zeus and CryptoLocker",
        url: "https://www.europol.europa.eu/media-press/newsroom/news/international-action-against-gameover-zeus-botnet-and-cryptolocker-ransomware",
      },
      {
        name: "KrebsOnSecurity: GameOver Botnet Back from the Dead",
        url: "https://krebsonsecurity.com/2014/07/gameover-botnet-back-from-the-dead/",
      },
    ],
  },
  {
    id: "british-airways-magecart",
    name: "British Airways Magecart breach",
    disposition: "malicious",
    domains: ["baways.com"],
    terms: ["british airways", "magecart", "baways.com"],
    facts: [
      "In the 2018 British Airways Magecart breach, attackers injected 22 lines of malicious JavaScript into the site's Modernizr.js library.",
      "From August 21 through September 5, the script skimmed payment-page form data and exfiltrated it to baways.com, an attacker-registered lookalike domain hosted from Romania.",
      "The breach exposed payment-card data for roughly 380,000 to 500,000 customers, and the UK Information Commissioner's Office later fined British Airways 20 million pounds.",
    ],
    sources: [
      {
        name: "UK ICO: British Airways monetary penalty notice",
        url: "https://ico.org.uk/media/action-weve-taken/mpns/2618421/ba-penalty-20201016.pdf",
      },
    ],
  },
  {
    id: "punycode-apple",
    name: "Punycode apple.com homograph demonstration",
    disposition: "demonstration",
    domains: ["xn--80ak6aa92e.com"],
    terms: ["punycode", "homograph", "xn--80ak6aa92e.com"],
    facts: [
      "Researcher Xudong Zheng registered xn--80ak6aa92e.com as a proof of concept using all-Cyrillic characters that rendered like apple.com in affected browsers.",
      "Zheng privately reported the issue to Chrome and Firefox on January 20, 2017 and publicly documented it on April 14, 2017.",
      "The domain demonstrated an internationalized-domain homograph risk rather than a documented credential-theft campaign; Chrome's fix shipped in version 58.",
    ],
    sources: [
      {
        name: "Xudong Zheng: Phishing with Unicode Domains",
        url: "https://www.xudongz.com/blog/2017/idn-phishing/",
      },
    ],
  },
  {
    id: "emotet",
    name: "Emotet infrastructure takedown",
    disposition: "malicious",
    domains: [],
    terms: ["emotet", "operation ladybird"],
    facts: [
      "Emotet began as a banking Trojan in 2014 and evolved into a loader that sold access for data theft, banking malware, and ransomware operations including TrickBot and Ryuk.",
      "Its globally distributed infrastructure used several hundred servers to manage infected computers, spread malware, and serve other criminal groups.",
      "On January 27, 2021, Europol announced that authorities in eight countries had taken control of the infrastructure from inside and redirected infected machines to law-enforcement-controlled systems.",
    ],
    sources: [
      {
        name: "Europol: Emotet disrupted through global action",
        url: "https://www.europol.europa.eu/media-press/newsroom/news/world%E2%80%99s-most-dangerous-malware-emotet-disrupted-through-global-action",
      },
    ],
  },
  {
    id: "dnc-google-phishing",
    name: "Fake Google-login phishing targeting the DNC",
    disposition: "malicious",
    domains: [],
    terms: ["dnc hack", "dnc phishing", "john podesta", "podesta", "tg-4127", "fake google-login", "fake google login"],
    facts: [
      "SecureWorks tracked the Russian-linked group as TG-4127, also reported as APT28, Sofacy, Sednit, Fancy Bear, and Pawn Storm.",
      "The group used Bitly-shortened links to hide spoofed Google login pages that harvested credentials from targets connected to Hillary Clinton's campaign and the Democratic National Committee.",
      "SecureWorks analyzed thousands of phishing URLs and documented how the fake login pages prefilled a target's Google account name before collecting entered credentials.",
    ],
    sources: [
      {
        name: "SecureWorks CTU: Threat Group-4127 Targets Google Accounts",
        url: "https://www.sophos.com/en-us/research/threat-group-4127-targets-google-accounts",
      },
    ],
  },
] as const;

function hostnameFromUrl(value?: string): string | null {
  if (!value) return null;
  try {
    return new URL(value).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function containsTerm(text: string, term: string): boolean {
  const start = text.indexOf(term);
  if (start < 0) return false;
  const before = text[start - 1];
  const after = text[start + term.length];
  return (!before || !/[a-z0-9]/.test(before)) && (!after || !/[a-z0-9]/.test(after));
}

export function historicalUrlIncidents(): readonly HistoricalUrlIncident[] {
  return INCIDENTS;
}

export function findHistoricalUrlIncident(input: {
  url?: string;
  question?: string;
}): HistoricalUrlMatch | null {
  const hostname = hostnameFromUrl(input.url);
  if (hostname) {
    for (const incident of INCIDENTS) {
      if (incident.domains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))) {
        return { incident, matched_by: "hostname" };
      }
    }
  }

  const question = input.question?.toLowerCase().replace(/\s+/g, " ").trim();
  if (!question) return null;
  for (const incident of INCIDENTS) {
    if (
      incident.domains.some((domain) => containsTerm(question, domain)) ||
      incident.terms.some((term) => containsTerm(question, term))
    ) {
      return { incident, matched_by: "question" };
    }
  }
  return null;
}