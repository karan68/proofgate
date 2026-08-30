import { lookup as dnsLookup } from "node:dns/promises";

import ipaddr from "ipaddr.js";
import { getDomain } from "tldts";

const BLOCKED_HOST_SUFFIXES = [
  ".home.arpa",
  ".internal",
  ".intranet",
  ".local",
  ".localhost",
];

const BLOCKED_HOSTS = new Set([
  "localhost",
  "metadata.google.internal",
]);

export interface ValidatedTarget {
  url: string;
  hostname: string;
  registrableDomain: string | null;
  protocol: "http:" | "https:";
  port: string;
}

export type AddressLookup = (hostname: string) => Promise<string[]>;
const DNS_LOOKUP_TIMEOUT_MS = 5_000;

export class TargetValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetValidationError";
  }
}

function normalizedHostname(url: URL): string {
  return url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
}

export function isPublicAddress(address: string): boolean {
  if (!ipaddr.isValid(address)) return false;

  let parsed = ipaddr.parse(address);
  if (parsed.kind() === "ipv6") {
    const ipv6 = parsed as ipaddr.IPv6;
    if (ipv6.isIPv4MappedAddress()) {
      parsed = ipv6.toIPv4Address();
    }
  }

  return parsed.range() === "unicast";
}

export function normalizeTargetUrl(input: string): ValidatedTarget {
  let parsed: URL;
  try {
    parsed = new URL(input.trim());
  } catch {
    throw new TargetValidationError("Enter a complete http:// or https:// URL.");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new TargetValidationError("Only HTTP and HTTPS targets are supported.");
  }

  if (parsed.username || parsed.password) {
    throw new TargetValidationError("Credentials embedded in a URL are not allowed.");
  }

  const hostname = normalizedHostname(parsed);
  if (!hostname || BLOCKED_HOSTS.has(hostname)) {
    throw new TargetValidationError("Local targets are not allowed.");
  }

  if (BLOCKED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    throw new TargetValidationError("Private hostnames are not allowed.");
  }

  if (ipaddr.isValid(hostname) && !isPublicAddress(hostname)) {
    throw new TargetValidationError("Private, loopback, and reserved IP targets are blocked.");
  }

  const defaultPort = parsed.protocol === "https:" ? "443" : "80";
  parsed.hash = "";
  parsed.hostname = parsed.hostname.toLowerCase();

  return {
    url: parsed.toString(),
    hostname,
    registrableDomain: ipaddr.isValid(hostname) ? null : getDomain(hostname),
    protocol: parsed.protocol,
    port: parsed.port || defaultPort,
  };
}

const defaultAddressLookup: AddressLookup = async (hostname) => {
  const results = await dnsLookup(hostname, { all: true, verbatim: true });
  return results.map((result) => result.address);
};

export async function assertPublicTarget(
  input: string,
  options: {
    lookup?: AddressLookup;
    allowNonStandardPorts?: boolean;
    allowUnresolved?: boolean;
  } = {},
): Promise<ValidatedTarget & { addresses: string[] }> {
  const target = normalizeTargetUrl(input);
  const standardPort = target.protocol === "https:" ? "443" : "80";

  if (!options.allowNonStandardPorts && target.port !== standardPort) {
    throw new TargetValidationError("Execution is limited to standard HTTP and HTTPS ports.");
  }

  let timeout: ReturnType<typeof setTimeout> | undefined;
  let addresses: string[];
  try {
    addresses = ipaddr.isValid(target.hostname)
      ? [target.hostname]
      : await Promise.race([
          (options.lookup ?? defaultAddressLookup)(target.hostname),
          new Promise<string[]>((_, reject) => {
            timeout = setTimeout(
              () => reject(new TargetValidationError("DNS lookup timed out.")),
              DNS_LOOKUP_TIMEOUT_MS,
            );
          }),
        ]).finally(() => clearTimeout(timeout));
  } catch (error) {
    if (!options.allowUnresolved) throw error;
    addresses = [];
  }

  if (addresses.length === 0 && !options.allowUnresolved) {
    throw new TargetValidationError("The target hostname did not resolve.");
  }

  if (addresses.some((address) => !isPublicAddress(address))) {
    throw new TargetValidationError(
      "The hostname resolves to a private, loopback, or reserved address.",
    );
  }

  return { ...target, addresses };
}