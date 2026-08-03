import assert from "node:assert/strict";
import test from "node:test";
import { Headers } from "undici";
import {
  EgressPolicyError,
  safeFetchText,
  type EgressResolver,
  type ValidatedRequest,
} from "./egressPolicy.js";

function response(status: number, headers?: Record<string, string>, body = "ok") {
  return {
    status,
    headers: new Headers(headers),
    async text() {
      return body;
    },
  };
}

const publicResolver: EgressResolver = async () => [
  { address: "93.184.216.34", family: 4 },
];

test("doğrudan private ve loopback IP fetch yapılmadan reddedilir", async () => {
  for (const url of [
    "http://127.0.0.1",
    "http://10.0.0.1",
    "http://169.254.169.254",
    "http://2130706433",
    "http://0x7f000001",
    "http://017700000001",
    "http://127.1",
  ]) {
    let requestCalls = 0;
    await assert.rejects(
      safeFetchText(url, {}, {
        access: "passive",
        request: async () => {
          requestCalls += 1;
          return response(200);
        },
      }),
      EgressPolicyError,
    );
    assert.equal(requestCalls, 0, url);
  }
});

test("private IP'ye çözülen hostname ve karışık A/AAAA kümesi fetch yapılmadan reddedilir", async () => {
  for (const resolver of [
    async () => [{ address: "192.168.1.20", family: 4 as const }],
    async () => [
      { address: "93.184.216.34", family: 4 as const },
      { address: "fd00::20", family: 6 as const },
    ],
  ]) {
    let requestCalls = 0;
    await assert.rejects(
      safeFetchText("https://mixed.example", {}, {
        access: "passive",
        resolver,
        request: async () => {
          requestCalls += 1;
          return response(200);
        },
      }),
      EgressPolicyError,
    );
    assert.equal(requestCalls, 0);
  }
});

test("izinli public hosttan yasak IP'ye redirect ikinci fetch'ten önce engellenir", async () => {
  let requestCalls = 0;
  const request: ValidatedRequest = async () => {
    requestCalls += 1;
    return response(302, { location: "http://127.0.0.1/internal" }, "");
  };

  await assert.rejects(
    safeFetchText("https://public.example/start", {}, {
      access: "passive",
      resolver: publicResolver,
      request,
    }),
    EgressPolicyError,
  );
  assert.equal(requestCalls, 1);
});

test("IPv6 loopback, link-local ve IPv4-mapped IPv6 engellenir", async () => {
  for (const url of [
    "http://[::1]",
    "http://[fe80::1]",
    "http://[::ffff:127.0.0.1]",
  ]) {
    let requestCalls = 0;
    await assert.rejects(
      safeFetchText(url, {}, {
        access: "passive",
        request: async () => {
          requestCalls += 1;
          return response(200);
        },
      }),
      EgressPolicyError,
    );
    assert.equal(requestCalls, 0, url);
  }
});

test("DNS doğrulaması ve bağlantı aynı sabitlenmiş adresi kullanır", async () => {
  let resolverCalls = 0;
  const resolver: EgressResolver = async () => {
    resolverCalls += 1;
    return resolverCalls === 1
      ? [{ address: "93.184.216.34", family: 4 }]
      : [{ address: "127.0.0.1", family: 4 }];
  };
  const request: ValidatedRequest = async (target) => {
    assert.equal(target.selectedAddress.address, "93.184.216.34");
    assert.deepEqual(target.addresses, [{ address: "93.184.216.34", family: 4 }]);
    return response(200);
  };

  const result = await safeFetchText("https://rebind.example", {}, {
    access: "passive",
    resolver,
    request,
  });
  assert.equal(result.status, 200);
  assert.equal(resolverCalls, 1);
});

test("private lab erişimi yalnız server-side exact active allowlist ile açılır", async () => {
  let requestCalls = 0;
  const request: ValidatedRequest = async () => {
    requestCalls += 1;
    return response(200);
  };
  const resolver: EgressResolver = async () => [
    { address: "192.168.50.10", family: 4 },
  ];

  await safeFetchText("http://lab.internal", {}, {
    access: "active",
    env: {
      ALLOWED_ACTIVE_HOSTS: "LAB.INTERNAL.",
      ALLOWED_ACTIVE_PRIVATE_HOSTS: "lab.internal",
    },
    resolver,
    request,
  });
  assert.equal(requestCalls, 1);

  await assert.rejects(
    safeFetchText("http://lab.internal", {}, {
      access: "active",
      env: { ALLOWED_ACTIVE_HOSTS: "lab.internal" },
      resolver,
      request,
    }),
    EgressPolicyError,
  );
  assert.equal(requestCalls, 1);

  await assert.rejects(
    safeFetchText("http://sub.lab.internal", {}, {
      access: "active",
      env: {
        ALLOWED_ACTIVE_HOSTS: "lab.internal",
        ALLOWED_ACTIVE_PRIVATE_HOSTS: "lab.internal",
      },
      resolver,
      request,
    }),
    EgressPolicyError,
  );
  assert.equal(requestCalls, 1);
});

test("private allowlist metadata ve link-local adresleri açmaz", async () => {
  for (const address of ["169.254.169.254", "100.100.100.200", "fe80::1"]) {
    let requestCalls = 0;
    await assert.rejects(
      safeFetchText("http://lab.internal", {}, {
        access: "active",
        env: {
          ALLOWED_ACTIVE_HOSTS: "lab.internal",
          ALLOWED_ACTIVE_PRIVATE_HOSTS: "lab.internal",
        },
        resolver: async () => [{
          address,
          family: address.includes(":") ? 6 : 4,
        } as const],
        request: async () => {
          requestCalls += 1;
          return response(200);
        },
      }),
      EgressPolicyError,
    );
    assert.equal(requestCalls, 0, address);
  }
});

test("metadata deny-list allowlist varken normalize IP biçimlerini de reddeder", async () => {
  const privateHosts = [
    "169.254.169.254",
    "fd00:ec2::254",
    "::ffff:a9fe:a9fe",
  ].join(",");

  for (const url of [
    "http://169.254.169.254",
    "http://2852039166",
    "http://0xa9fea9fe",
    "http://[fd00:ec2::254]",
    "http://[::ffff:169.254.169.254]",
    "http://[::ffff:a9fe:a9fe]",
  ]) {
    let requestCalls = 0;
    await assert.rejects(
      safeFetchText(url, {}, {
        access: "passive",
        env: { ALLOWED_PASSIVE_HOSTS: privateHosts },
        request: async () => {
          requestCalls += 1;
          return response(200);
        },
      }),
      /Metadata servis/,
    );
    assert.equal(requestCalls, 0, url);
  }
});

test("tek metadata kaydı içeren DNS cevap kümesinin tamamı reddedilir", async () => {
  let requestCalls = 0;
  await assert.rejects(
    safeFetchText("https://mixed-lab.internal", {}, {
      access: "active",
      env: {
        ALLOWED_ACTIVE_HOSTS: "mixed-lab.internal",
        ALLOWED_ACTIVE_PRIVATE_HOSTS: "mixed-lab.internal",
      },
      resolver: async () => [
        { address: "192.168.50.20", family: 4 },
        { address: "fd00:ec2::254", family: 6 },
      ],
      request: async () => {
        requestCalls += 1;
        return response(200);
      },
    }),
    /Metadata servis/,
  );
  assert.equal(requestCalls, 0);
});

test("izinli hedeften metadata adresine redirect ikinci istekten önce engellenir", async () => {
  let requestCalls = 0;
  await assert.rejects(
    safeFetchText("https://public.example/start", {}, {
      access: "passive",
      env: { ALLOWED_PASSIVE_HOSTS: "fd00:ec2::254" },
      resolver: publicResolver,
      request: async () => {
        requestCalls += 1;
        return response(302, { location: "http://[fd00:ec2::254]/latest" }, "");
      },
    }),
    /Metadata servis/,
  );
  assert.equal(requestCalls, 1);
});

test("URL userinfo, HTTP dışı protokol ve redirect üst sınırı fail-closed reddedilir", async () => {
  for (const url of ["https://user:pass@public.example", "ftp://public.example/file"]) {
    await assert.rejects(
      safeFetchText(url, {}, {
        access: "passive",
        resolver: publicResolver,
        request: async () => response(200),
      }),
      EgressPolicyError,
    );
  }

  let requestCalls = 0;
  await assert.rejects(
    safeFetchText("https://public.example/start", {}, {
      access: "passive",
      maxRedirects: 1,
      resolver: publicResolver,
      request: async () => {
        requestCalls += 1;
        return response(302, { location: "/again" }, "");
      },
    }),
    /Redirect üst sınırı/,
  );
  assert.equal(requestCalls, 2);
});
