import assert from "node:assert/strict";
import type { LookupAddress, LookupOptions } from "node:dns";
import type { LookupFunction } from "node:net";
import test from "node:test";
import {
  createPinnedLookup,
  createPinnedTransportOptions,
  type ResolvedAddress,
  type ValidatedTarget,
} from "./egressPolicy.js";

interface LookupResult {
  address: string | LookupAddress[];
  family?: number;
}

function invokeLookup(
  lookup: LookupFunction,
  hostname: string,
  options: LookupOptions,
): Promise<LookupResult> {
  return new Promise((resolve, reject) => {
    lookup(hostname, options, (error, address, family) => {
      if (error) {
        reject(error);
        return;
      }
      resolve({ address, family });
    });
  });
}

const IPV4: ResolvedAddress = { address: "93.184.216.34", family: 4 };
const IPV6: ResolvedAddress = {
  address: "2606:2800:220:1:248:1893:25c8:1946",
  family: 6,
};

test("pinned lookup all:true için Node LookupAddress dizisi döndürür", async () => {
  const lookup = createPinnedLookup("example.test", [IPV4, IPV6]);
  const result = await invokeLookup(lookup, "example.test", { all: true });

  assert.deepEqual(result.address, [IPV4, IPV6]);
  assert.equal(result.family, undefined);
});

test("pinned lookup all:false için tek adres ve family döndürür", async () => {
  const lookup = createPinnedLookup("example.test", [IPV6, IPV4]);
  const result = await invokeLookup(lookup, "example.test", { all: false });

  assert.equal(result.address, IPV6.address);
  assert.equal(result.family, 6);
});

test("pinned lookup IPv4, IPv6 ve dual-stack family seçimlerini korur", async () => {
  const dualStack = createPinnedLookup("example.test", [IPV6, IPV4]);
  assert.deepEqual(
    (await invokeLookup(dualStack, "example.test", { all: true, family: 4 })).address,
    [IPV4],
  );
  assert.deepEqual(
    (await invokeLookup(dualStack, "example.test", { all: true, family: 6 })).address,
    [IPV6],
  );
  assert.equal(
    (await invokeLookup(createPinnedLookup("example.test", [IPV4]), "example.test", {
      all: false,
      family: 4,
    })).address,
    IPV4.address,
  );
  assert.equal(
    (await invokeLookup(createPinnedLookup("example.test", [IPV6]), "example.test", {
      all: false,
      family: 6,
    })).address,
    IPV6.address,
  );
});

test("pinned lookup boş veya istenen family bulunmayan listede fail-closed olur", async () => {
  await assert.rejects(
    invokeLookup(createPinnedLookup("example.test", []), "example.test", { all: true }),
    { code: "ENOTFOUND" },
  );
  await assert.rejects(
    invokeLookup(createPinnedLookup("example.test", [IPV4]), "example.test", {
      all: false,
      family: 6,
    }),
    { code: "ENOTFOUND" },
  );
});

test("pinned lookup yalnız doğrulanan hostname ve adresleri transport'a verir", async () => {
  const target: ValidatedTarget = {
    url: new URL("https://example.test:8443/path"),
    hostname: "example.test",
    addresses: [IPV4, IPV6],
    selectedAddress: IPV4,
  };
  const transport = createPinnedTransportOptions(target);

  assert.equal(transport.url.hostname, "example.test");
  assert.equal(transport.url.host, "example.test:8443");
  assert.equal(transport.connect.servername, "example.test");
  assert.equal("rejectUnauthorized" in transport.connect, false);

  const result = await invokeLookup(transport.connect.lookup, "EXAMPLE.TEST.", {
    all: true,
  });
  assert.ok(Array.isArray(result.address));
  assert.deepEqual(result.address, [IPV4, IPV6]);

  await assert.rejects(
    invokeLookup(transport.connect.lookup, "other.test", { all: true }),
    { code: "ENOTFOUND" },
  );
});

test("production transport lookup'u ERR_INVALID_IP_ADDRESS şekli üretmez", async () => {
  const target: ValidatedTarget = {
    url: new URL("https://example.test/"),
    hostname: "example.test",
    addresses: [IPV4, IPV6],
    selectedAddress: IPV4,
  };
  const transport = createPinnedTransportOptions(target);
  const lookupResult = await invokeLookup(transport.connect.lookup, target.hostname, {
    all: true,
    family: 0,
  });

  const transportStub = (addresses: string | LookupAddress[]): void => {
    if (!Array.isArray(addresses)) {
      throw Object.assign(new TypeError("Invalid IP address"), {
        code: "ERR_INVALID_IP_ADDRESS",
      });
    }
    assert.deepEqual(addresses, [IPV4, IPV6]);
  };

  assert.doesNotThrow(() => transportStub(lookupResult.address));
});
