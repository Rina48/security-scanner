import assert from "node:assert/strict";
import test from "node:test";
import {
  isAllowlistedPrivateNetworkAddress,
  isBlockedNetworkAddress,
  isLoopbackAddress,
  isMetadataNetworkAddress,
} from "./networkAddress.js";

test("özel, reserved, multicast ve metadata ağ adresleri engellenir", () => {
  for (const address of [
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "198.18.0.1",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "fd00::1",
    "fe80::1",
    "ff02::1",
    "2001:db8::1",
    "::ffff:127.0.0.1",
  ]) {
    assert.equal(isBlockedNetworkAddress(address), true, address);
  }
  assert.equal(isBlockedNetworkAddress("93.184.216.34"), false);
  assert.equal(isBlockedNetworkAddress("2606:2800:220:1:248:1893:25c8:1946"), false);
});

test("doğrudan loopback kontrolü header bilgisine ihtiyaç duymaz", () => {
  assert.equal(isLoopbackAddress("127.0.0.1"), true);
  assert.equal(isLoopbackAddress("::1"), true);
  assert.equal(isLoopbackAddress("::ffff:127.0.0.1"), true);
  assert.equal(isLoopbackAddress("203.0.113.10"), false);
});

test("private allowlist yalnız dar lab adres sınıflarını açabilir", () => {
  for (const address of ["10.0.0.1", "127.0.0.1", "172.16.0.1", "192.168.1.1", "::1", "fd00::1"]) {
    assert.equal(isAllowlistedPrivateNetworkAddress(address), true, address);
  }
  for (const address of ["100.64.0.1", "169.254.169.254", "224.0.0.1", "fe80::1", "::ffff:127.0.0.1"]) {
    assert.equal(isAllowlistedPrivateNetworkAddress(address), false, address);
  }
});

test("metadata deny-list IPv4, IPv6 ve IPv4-mapped biçimleri tanır", () => {
  for (const address of [
    "169.254.169.254",
    "fd00:ec2::254",
    "::ffff:169.254.169.254",
    "::ffff:a9fe:a9fe",
  ]) {
    assert.equal(isMetadataNetworkAddress(address), true, address);
  }
  assert.equal(isMetadataNetworkAddress("fd00::20"), false);
  assert.equal(isMetadataNetworkAddress("192.168.1.20"), false);
});
