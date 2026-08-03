import assert from "node:assert/strict";
import test from "node:test";
import { Headers } from "undici";
import {
  assertTlsFixtureClaims,
  startTlsTestFixture,
  type TlsFixtureCertificate,
} from "../testing/tlsTestFixture.js";
import type { ValidatedTarget } from "../security/egressPolicy.js";
import type { ScannerFinding } from "../types.js";
import {
  runAllActiveModules,
  runScan,
  type ActiveModuleDependencies,
  type RunScanDependencies,
} from "./runScan.js";

const originalEnvironment = {
  active: process.env.ALLOWED_ACTIVE_HOSTS,
  activePrivate: process.env.ALLOWED_ACTIVE_PRIVATE_HOSTS,
  passive: process.env.ALLOWED_PASSIVE_HOSTS,
};

test.before(() => {
  process.env.ALLOWED_ACTIVE_HOSTS = "127.0.0.1";
  process.env.ALLOWED_ACTIVE_PRIVATE_HOSTS = "127.0.0.1";
  process.env.ALLOWED_PASSIVE_HOSTS = "127.0.0.1";
  assertTlsFixtureClaims();
});

test.after(() => {
  restoreEnvironment("ALLOWED_ACTIVE_HOSTS", originalEnvironment.active);
  restoreEnvironment(
    "ALLOWED_ACTIVE_PRIVATE_HOSTS",
    originalEnvironment.activePrivate,
  );
  restoreEnvironment("ALLOWED_PASSIVE_HOSTS", originalEnvironment.passive);
});

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function finding(
  id: string,
  category: ScannerFinding["category"] = "tls",
): ScannerFinding {
  return {
    id,
    category,
    title: id,
    severity: "low",
    confidence: "high",
    evidence: id,
    remediation: id,
    endpoint: "https://127.0.0.1",
  };
}

function fixtureTarget(url: string): ValidatedTarget {
  const parsed = new URL(url);
  const address = { address: "127.0.0.1", family: 4 as const };
  return {
    url: parsed,
    hostname: "127.0.0.1",
    addresses: [address],
    selectedAddress: address,
  };
}

async function assertFixtureFinding(
  certificate: TlsFixtureCertificate,
  expectedFindingId: string,
): Promise<void> {
  const fixture = await startTlsTestFixture({ certificate });
  try {
    const result = await runScan(
      { targetUrl: fixture.url, mode: "passive" },
      {
        tlsDependencies: {
          resolveTarget: async () => fixtureTarget(fixture.url),
        },
      },
    );

    assert.ok(
      result.findings.some((entry) => entry.id === expectedFindingId),
      `${expectedFindingId} did not reach the runScan report`,
    );
    assert.equal(fixture.applicationBytesReceived, 0);
  } finally {
    await fixture.close();
  }
}

test("runScan completes with a trust finding when verified fetch rejects a self-signed certificate", async () => {
  await assertFixtureFinding("valid", "tls-certificate-untrusted");
});

test("runScan reports hostname mismatch when verified fetch rejects the certificate", async () => {
  await assertFixtureFinding("mismatch", "tls-certificate-hostname-mismatch");
});

test("runScan reports an expired certificate when verified fetch rejects it", async () => {
  await assertFixtureFinding("expired", "tls-certificate-expired");
});

test("failed fetch skips body scanners and active modules when TLS has a diagnostic", async () => {
  let bodyScannerCalls = 0;
  let activeScannerCalls = 0;
  const dependencies: RunScanDependencies = {
    activeScanner: async () => {
      activeScannerCalls += 1;
      return [];
    },
    cookieScanner: () => {
      bodyScannerCalls += 1;
      return [];
    },
    fetchText: async () => {
      throw new Error("verified fetch failed");
    },
    responseLeakScanner: () => {
      bodyScannerCalls += 1;
      return [];
    },
    securityHeaderScanner: () => {
      bodyScannerCalls += 1;
      return [];
    },
    tlsScanner: async () => [finding("tls-certificate-untrusted")],
  };

  const result = await runScan(
    { targetUrl: "https://127.0.0.1", mode: "active" },
    { dependencies },
  );

  assert.equal(bodyScannerCalls, 0);
  assert.equal(activeScannerCalls, 0);
  assert.deepEqual(
    result.findings.map((entry) => entry.id),
    ["tls-certificate-untrusted"],
  );
});

test("successful verified fetch preserves body, TLS, and active scanner flow", async () => {
  let receivedFetchSignal: AbortSignal | undefined;
  let activeScannerCalls = 0;
  const dependencies: RunScanDependencies = {
    activeScanner: async () => {
      activeScannerCalls += 1;
      return [finding("active-result", "active")];
    },
    cookieScanner: () => [finding("cookie-result", "cookies")],
    fetchText: async (_url, init) => {
      receivedFetchSignal = init?.signal;
      return {
        status: 200,
        headers: new Headers(),
        body: "safe response body",
        url: "https://127.0.0.1/",
      };
    },
    responseLeakScanner: () => [finding("body-result", "leak")],
    securityHeaderScanner: () => [finding("header-result", "headers")],
    tlsScanner: async () => [finding("tls-result")],
  };

  const result = await runScan(
    { targetUrl: "https://127.0.0.1", mode: "active" },
    { dependencies },
  );

  assert.ok(receivedFetchSignal);
  assert.equal(activeScannerCalls, 1);
  assert.deepEqual(
    new Set(result.findings.map((entry) => entry.id)),
    new Set([
      "active-result",
      "body-result",
      "cookie-result",
      "header-result",
      "tls-result",
    ]),
  );
});

test("runScan fails closed when verified fetch and TLS diagnostic both fail", async () => {
  const fetchError = new Error("verified fetch failed");

  await assert.rejects(
    runScan(
      { targetUrl: "https://127.0.0.1", mode: "passive" },
      {
        dependencies: {
          fetchText: async () => {
            throw fetchError;
          },
          tlsScanner: async () => {
            throw new Error("TLS diagnostic failed");
          },
        },
      },
    ),
    (error) => error === fetchError,
  );
});

test("runScan fails closed when TLS returns only a diagnostic failure marker", async () => {
  const fetchError = new Error("verified fetch failed");

  await assert.rejects(
    runScan(
      { targetUrl: "https://127.0.0.1", mode: "passive" },
      {
        dependencies: {
          fetchText: async () => {
            throw fetchError;
          },
          tlsScanner: async () => [finding("tls-scan-failed")],
        },
      },
    ),
    (error) => error === fetchError,
  );
});

test("abort reaches fetch and TLS and prevents later scanners from starting", async () => {
  const controller = new AbortController();
  let bodyScannerCalls = 0;
  let activeScannerCalls = 0;
  let fetchSawAbort = false;
  let tlsSawAbort = false;

  const waitForAbort = (signal: AbortSignal | undefined, branch: "fetch" | "tls") =>
    new Promise<never>((_resolve, reject) => {
      assert.ok(signal);
      const onAbort = (): void => {
        if (branch === "fetch") fetchSawAbort = true;
        else tlsSawAbort = true;
        reject(signal.reason);
      };
      if (signal.aborted) onAbort();
      else signal.addEventListener("abort", onAbort, { once: true });
    });

  const scanPromise = runScan(
    { targetUrl: "https://127.0.0.1", mode: "active" },
    {
      dependencies: {
        activeScanner: async () => {
          activeScannerCalls += 1;
          return [];
        },
        cookieScanner: () => {
          bodyScannerCalls += 1;
          return [];
        },
        fetchText: async (_url, init) => waitForAbort(init?.signal, "fetch"),
        responseLeakScanner: () => {
          bodyScannerCalls += 1;
          return [];
        },
        securityHeaderScanner: () => {
          bodyScannerCalls += 1;
          return [];
        },
        tlsScanner: async (_url, _access, dependencies) =>
          waitForAbort(dependencies?.signal, "tls"),
      },
      signal: controller.signal,
    },
  );

  controller.abort();
  await assert.rejects(scanPromise, { name: "AbortError" });
  assert.equal(fetchSawAbort, true);
  assert.equal(tlsSawAbort, true);
  assert.equal(bodyScannerCalls, 0);
  assert.equal(activeScannerCalls, 0);
});

test("abort after the active phase starts prevents a partial runScan report", async () => {
  const controller = new AbortController();
  let activeSignal: AbortSignal | undefined;
  let reportCalls = 0;
  let markActiveStarted: (() => void) | undefined;
  const activeStarted = new Promise<void>((resolve) => {
    markActiveStarted = resolve;
  });

  const scan = runScan(
    { targetUrl: "https://127.0.0.1", mode: "active" },
    {
      dependencies: {
        activeScanner: async (_url, options) => {
          activeSignal = options.signal;
          markActiveStarted?.();
          return new Promise<never>((_resolve, reject) => {
            assert.ok(activeSignal);
            activeSignal.addEventListener(
              "abort",
              () => reject(activeSignal?.reason),
              { once: true },
            );
          });
        },
        cookieScanner: () => [],
        createReport: () => {
          reportCalls += 1;
          throw new Error("report must not be created after abort");
        },
        fetchText: async () => ({
          status: 200,
          headers: new Headers(),
          body: "safe response body",
          url: "https://127.0.0.1/",
        }),
        responseLeakScanner: () => [],
        securityHeaderScanner: () => [],
        tlsScanner: async () => [],
      },
      signal: controller.signal,
    },
  );

  await activeStarted;
  controller.abort();
  await assert.rejects(scan, { name: "AbortError" });
  assert.equal(activeSignal, controller.signal);
  assert.equal(reportCalls, 0);
});

test("parallel active modules receive and stop on the same signal", async () => {
  const controller = new AbortController();
  const seenSignals: AbortSignal[] = [];
  let startedCount = 0;
  let markAllStarted: (() => void) | undefined;
  const allStarted = new Promise<void>((resolve) => {
    markAllStarted = resolve;
  });

  const waitForAbort = async (
    _targetUrl: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<ScannerFinding[]> => {
    assert.ok(options.signal);
    seenSignals.push(options.signal);
    startedCount += 1;
    if (startedCount === 6) markAllStarted?.();
    return new Promise((_resolve, reject) => {
      options.signal?.addEventListener(
        "abort",
        () => reject(options.signal?.reason),
        { once: true },
      );
    });
  };

  const dependencies: ActiveModuleDependencies = {
    cmdInjectionScanner: waitForAbort,
    httpMethodScanner: waitForAbort,
    localScanner: waitForAbort,
    openRedirectScanner: waitForAbort,
    pathDiscoveryScanner: waitForAbort,
    robotsPaths: async (_origin, options) => {
      assert.equal(options?.signal, controller.signal);
      return [];
    },
    traversalScanner: waitForAbort,
  };

  const activeScan = runAllActiveModules("https://127.0.0.1", {
    dependencies,
    signal: controller.signal,
  });
  await allStarted;
  controller.abort();

  await assert.rejects(activeScan, { name: "AbortError" });
  assert.equal(seenSignals.length, 6);
  assert.ok(seenSignals.every((signal) => signal === controller.signal));
});

test("an abort during module startup prevents the next active module from starting", async () => {
  const controller = new AbortController();
  const startedModules: string[] = [];
  const dependencies: ActiveModuleDependencies = {
    localScanner: async (_url, options) => {
      startedModules.push("local");
      controller.abort();
      throw options?.signal?.reason;
    },
    pathDiscoveryScanner: async () => {
      startedModules.push("path");
      return [];
    },
    robotsPaths: async () => [],
  };

  await assert.rejects(
    runAllActiveModules("https://127.0.0.1", {
      dependencies,
      signal: controller.signal,
    }),
    { name: "AbortError" },
  );
  assert.deepEqual(startedModules, ["local"]);
});
