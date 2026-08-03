import { isIP } from "node:net";

function parseIpv4(address: string): number[] | null {
  if (isIP(address) !== 4) return null;
  const octets = address.split(".").map(Number);
  return octets.length === 4 && octets.every((octet) => octet >= 0 && octet <= 255)
    ? octets
    : null;
}

function expandEmbeddedIpv4(address: string): string | null {
  if (!address.includes(".")) return address;
  const lastColon = address.lastIndexOf(":");
  if (lastColon < 0) return null;
  const ipv4 = parseIpv4(address.slice(lastColon + 1));
  if (!ipv4) return null;
  const high = ((ipv4[0] ?? 0) << 8) | (ipv4[1] ?? 0);
  const low = ((ipv4[2] ?? 0) << 8) | (ipv4[3] ?? 0);
  return `${address.slice(0, lastColon)}:${high.toString(16)}:${low.toString(16)}`;
}

function parseIpv6(address: string): Uint8Array | null {
  const unwrapped = address.startsWith("[") && address.endsWith("]")
    ? address.slice(1, -1)
    : address;
  if (unwrapped.includes("%")) return null;

  const expandedIpv4 = expandEmbeddedIpv4(unwrapped.toLowerCase());
  if (!expandedIpv4 || isIP(expandedIpv4) !== 6) return null;

  const halves = expandedIpv4.split("::");
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;

  const groups = [
    ...left,
    ...(halves.length === 2 ? Array.from({ length: missing }, () => "0") : []),
    ...right,
  ];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    return null;
  }

  const bytes = new Uint8Array(16);
  groups.forEach((group, index) => {
    const value = Number.parseInt(group, 16);
    bytes[index * 2] = value >> 8;
    bytes[index * 2 + 1] = value & 0xff;
  });
  return bytes;
}

function matchesPrefix(
  address: Uint8Array,
  prefix: readonly number[],
  prefixBits: number,
): boolean {
  const fullBytes = Math.floor(prefixBits / 8);
  const remainingBits = prefixBits % 8;
  for (let index = 0; index < fullBytes; index += 1) {
    if (address[index] !== prefix[index]) return false;
  }
  if (remainingBits === 0) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return ((address[fullBytes] ?? 0) & mask) === ((prefix[fullBytes] ?? 0) & mask);
}

function isBlockedIpv4(octets: readonly number[]): boolean {
  const [a = 0, b = 0, c = 0] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function isIpv4Mapped(address: Uint8Array): boolean {
  return (
    address.slice(0, 10).every((byte) => byte === 0) &&
    address[10] === 0xff &&
    address[11] === 0xff
  );
}

function isMetadataIpv4(octets: ArrayLike<number>): boolean {
  return (
    octets[0] === 169 &&
    octets[1] === 254 &&
    octets[2] === 169 &&
    octets[3] === 254
  );
}

/** Metadata servis uçları hiçbir allowlist ile açılamaz. */
export function isMetadataNetworkAddress(address: string): boolean {
  const ipv4 = parseIpv4(address);
  if (ipv4) return isMetadataIpv4(ipv4);

  const ipv6 = parseIpv6(address);
  if (!ipv6) return false;

  if (isIpv4Mapped(ipv6)) {
    return isMetadataIpv4(ipv6.slice(12));
  }

  const awsMetadataIpv6 = new Uint8Array([
    0xfd, 0x00, 0x0e, 0xc2,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x54,
  ]);
  return ipv6.every((byte, index) => byte === awsMetadataIpv6[index]);
}

export function isLoopbackAddress(address: string | undefined): boolean {
  if (!address) return false;
  const ipv4 = parseIpv4(address);
  if (ipv4) return ipv4[0] === 127;

  const ipv6 = parseIpv6(address);
  if (!ipv6) return false;
  const isIpv6Loopback = ipv6.slice(0, 15).every((byte) => byte === 0) && ipv6[15] === 1;
  if (isIpv6Loopback) return true;
  return isIpv4Mapped(ipv6) && ipv6[12] === 127;
}

/**
 * Sunucu tarafındaki açık private-host allowlist'inin açabileceği dar adres kümesi.
 * Link-local, metadata, CGNAT, reserved, multicast ve mapped adresler burada
 * özellikle dışarıda bırakılır.
 */
export function isAllowlistedPrivateNetworkAddress(address: string): boolean {
  const ipv4 = parseIpv4(address);
  if (ipv4) {
    const [a = 0, b = 0] = ipv4;
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }

  const ipv6 = parseIpv6(address);
  if (!ipv6 || isIpv4Mapped(ipv6)) return false;
  const isIpv6Loopback = ipv6.slice(0, 15).every((byte) => byte === 0) && ipv6[15] === 1;
  return isIpv6Loopback || matchesPrefix(ipv6, [0xfc], 7);
}

export function isBlockedNetworkAddress(address: string): boolean {
  const ipv4 = parseIpv4(address);
  if (ipv4) return isBlockedIpv4(ipv4);

  const ipv6 = parseIpv6(address);
  if (!ipv6) return true;

  if (isIpv4Mapped(ipv6)) return true;

  const specialPrefixes: Array<[readonly number[], number]> = [
    [[0x00], 8], // unspecified, loopback and IPv4-compatible space
    [[0x00, 0x64, 0xff, 0x9b], 96], // NAT64 well-known prefix
    [[0x01, 0x00], 64], // discard-only
    [[0x20, 0x01, 0x00], 23], // IETF protocol assignments, including Teredo/ORCHID
    [[0x20, 0x01, 0x0d, 0xb8], 32], // documentation
    [[0x20, 0x02], 16], // 6to4
    [[0x3f, 0xff], 20], // documentation
    [[0xfc], 7], // unique-local
    [[0xfe, 0x80], 10], // link-local
    [[0xfe, 0xc0], 10], // deprecated site-local
    [[0xff], 8], // multicast
  ];
  if (specialPrefixes.some(([prefix, bits]) => matchesPrefix(ipv6, prefix, bits))) {
    return true;
  }

  // Fail closed: currently routable global unicast space is 2000::/3.
  return !matchesPrefix(ipv6, [0x20], 3);
}
