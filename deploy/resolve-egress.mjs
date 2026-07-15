import {mkdirSync, writeFileSync} from "node:fs";
import {resolve4} from "node:dns/promises";

const hosts = (process.env.COVEN_BUILD_EGRESS_HOSTS || "")
  .split(/\s+/)
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);

if (!hosts.length) throw new Error("COVEN_BUILD_EGRESS_HOSTS must not be empty");

function ipv4Number(value) {
  const octets = value.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    throw new Error(`Invalid IPv4 address returned by DNS: ${value}`);
  }
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
}

function inCidr(value, base, prefix) {
  const address = ipv4Number(value);
  const network = ipv4Number(base);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (address & mask) === (network & mask);
}

function isPublic(value) {
  return ![
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10],
    ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
    ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16],
    ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
    ["224.0.0.0", 4], ["240.0.0.0", 4],
  ].some(([base, prefix]) => inCidr(value, base, prefix));
}

for (const host of hosts) {
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) {
    throw new Error(`Invalid egress hostname: ${host}`);
  }
}

const resolved = new Map();
for (const host of hosts) {
  const addresses = [...new Set(await resolve4(host))].sort();
  if (!addresses.length || addresses.some((address) => !isPublic(address))) {
    throw new Error(`Egress hostname did not resolve exclusively to public IPv4 addresses: ${host}`);
  }
  resolved.set(host, addresses);
}

const allAddresses = [...new Set([...resolved.values()].flat())].sort();
mkdirSync("/out", {recursive: true});
writeFileSync(
  "/out/hosts",
  [
    "127.0.0.1 localhost",
    "::1 localhost ip6-localhost ip6-loopback",
    ...[...resolved].flatMap(([host, addresses]) => addresses.map((address) => `${address} ${host}`)),
    "",
  ].join("\n"),
  {encoding: "utf8", mode: 0o644},
);
writeFileSync("/out/egress-ipv4.txt", `${allAddresses.join("\n")}\n`, {encoding: "utf8", mode: 0o444});
writeFileSync("/out/egress-hosts.txt", `${hosts.join("\n")}\n`, {encoding: "utf8", mode: 0o444});
