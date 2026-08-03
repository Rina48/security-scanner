import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { EventEmitter } from "node:events";
import test from "node:test";
import tls from "node:tls";
import {
  assertTlsFixtureClaims,
  readTlsFixturePem,
  startTlsTestFixture,
} from "../../testing/tlsTestFixture.js";
import type { ValidatedTarget } from "../../security/egressPolicy.js";
import {
  classifyLegacyProbeError,
  classifyTlsAuthorizationError,
  connectDiagnosticTls,
  runTlsScanner,
  type DiagnosticTlsConnector,
  type DiagnosticTlsSocket,
} from "./tlsScanner.js";

function codedError(code: string, message = code): Error {
  const error = new Error(message);
  Object.assign(error, { code });
  return error;
}

const validCertificate = new X509Certificate(
  readTlsFixturePem("localhost-valid-cert.pem"),
).toLegacyObject() as tls.PeerCertificate;
const expiredCertificate = new X509Certificate(
  readTlsFixturePem("localhost-expired-cert.pem"),
).toLegacyObject() as tls.PeerCertificate;

class FakeDiagnosticTlsSocket
  extends EventEmitter
  implements DiagnosticTlsSocket
{
  authorized: boolean;
  authorizationError?: Error;
  certificate: tls.PeerCertificate;
  destroyCount = 0;
  protocol: string | null = "TLSv1.3";
  timeoutValues: number[] = [];
  private readonly onDestroy: (socket: FakeDiagnosticTlsSocket) => void;

  constructor(options: {
    authorizationError?: Error;
    authorized?: boolean;
    certificate?: tls.PeerCertificate;
    onDestroy?: (socket: FakeDiagnosticTlsSocket) => void;
  } = {}) {
    super();
    this.authorized = options.authorized ?? false;
    this.authorizationError = options.authorizationError;
    this.certificate = options.certificate ?? validCertificate;
    this.onDestroy = options.onDestroy ?? ((socket) => {
      queueMicrotask(() => socket.emit("close"));
    });
  }

  destroy(): void {
    this.destroyCount += 1;
    this.onDestroy(this);
  }

  getPeerCertificate(): tls.PeerCertificate {
    return this.certificate;
  }

  getProtocol(): string | null {
    return this.protocol;
  }

  setTimeout(timeout: number): void {
    this.timeoutValues.push(timeout);
  }
}

function assertSocketClean(socket: FakeDiagnosticTlsSocket): void {
  for (const event of ["secureConnect", "error", "timeout", "close"]) {
    assert.equal(socket.listenerCount(event), 0, `${event} listener leaked`);
  }
  assert.equal(socket.timeoutValues.at(-1), 0);
  assert.equal(socket.destroyCount, 1);
}

function fakeTarget(hostname = "example.test", port = 443): ValidatedTarget {
  const address = hostname === "127.0.0.1" ? "127.0.0.1" : "203.0.113.10";
  return {
    url: new URL(`https://${hostname}:${port}`),
    hostname,
    addresses: [{ address, family: 4 }],
    selectedAddress: { address, family: 4 },
  };
}

function scannerConnector(options: {
  authorizationError: Error;
  certificate?: tls.PeerCertificate;
  captured?: tls.ConnectionOptions[];
}): DiagnosticTlsConnector {
  return (connectionOptions) => {
    options.captured?.push(connectionOptions);
    const socket = new FakeDiagnosticTlsSocket({
      authorizationError: options.authorizationError,
      certificate: options.certificate,
    });
    if (connectionOptions.minVersion === "TLSv1" ||
        connectionOptions.minVersion === "TLSv1.1") {
      queueMicrotask(() => socket.emit(
        "error",
        codedError("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION"),
      ));
    } else {
      queueMicrotask(() => socket.emit("secureConnect"));
    }
    return socket;
  };
}

async function runClassificationScenario(options: {
  authorizationError: Error;
  certificate?: tls.PeerCertificate;
  identityError?: Error;
}) {
  return runTlsScanner("https://example.test", "passive", {
    checkServerIdentity: () => options.identityError,
    connect: scannerConnector(options),
    resolveTarget: async () => fakeTarget(),
  });
}

type LegacyOutcome = "pending" | "supported" | "timeout" | Error;

function legacyFlowConnector(outcomes: {
  TLSv1: LegacyOutcome;
  "TLSv1.1": LegacyOutcome;
}): DiagnosticTlsConnector {
  return (connectionOptions) => {
    const socket = new FakeDiagnosticTlsSocket({ authorized: true });
    const version = connectionOptions.minVersion;
    if (version !== "TLSv1" && version !== "TLSv1.1") {
      queueMicrotask(() => socket.emit("secureConnect"));
      return socket;
    }

    const outcome = outcomes[version];
    if (outcome === "pending") return socket;
    queueMicrotask(() => {
      if (outcome === "supported") socket.emit("secureConnect");
      else if (outcome === "timeout") socket.emit("timeout");
      else socket.emit("error", outcome);
    });
    return socket;
  };
}

async function runLegacyFlow(
  outcomes: Parameters<typeof legacyFlowConnector>[0],
  signal?: AbortSignal,
) {
  return runTlsScanner("https://example.test", "passive", {
    checkServerIdentity: () => undefined,
    connect: legacyFlowConnector(outcomes),
    resolveTarget: async () => fakeTarget(),
    signal,
  });
}

function legacyOnly(findings: Awaited<ReturnType<typeof runTlsScanner>>) {
  return findings.filter((finding) => finding.id.startsWith("tls-legacy-"));
}

test("TLS fixture certificates have the claimed hostnames and dates", () => {
  assertTlsFixtureClaims();
});

test("authorization errors are classified by stable code and safe fallback", () => {
  const cases = [
    ["ERR_TLS_CERT_ALTNAME_INVALID", "hostname-mismatch"],
    ["CERT_HAS_EXPIRED", "expired"],
    ["CERT_NOT_YET_VALID", "not-yet-valid"],
    ["CERT_REVOKED", "revoked"],
    ["DEPTH_ZERO_SELF_SIGNED_CERT", "trust-chain"],
    ["SOMETHING_NEW", "other"],
  ] as const;

  for (const [code, category] of cases) {
    assert.equal(classifyTlsAuthorizationError(codedError(code)).category, category);
  }
  assert.equal(
    classifyTlsAuthorizationError(new Error("certificate has expired")).category,
    "expired",
  );
});

test("hostname mismatch produces one deduplicated mismatch finding", async () => {
  const error = codedError("ERR_TLS_CERT_ALTNAME_INVALID");
  const findings = await runClassificationScenario({
    authorizationError: error,
    identityError: error,
  });

  assert.deepEqual(
    findings.map((finding) => finding.id),
    ["tls-certificate-hostname-mismatch"],
  );
});

test("expired certificate produces one deduplicated expired finding", async () => {
  const findings = await runClassificationScenario({
    authorizationError: codedError("CERT_HAS_EXPIRED"),
    certificate: expiredCertificate,
  });

  assert.deepEqual(
    findings.map((finding) => finding.id),
    ["tls-certificate-expired"],
  );
});

test("self-signed certificate produces only a trust-chain finding", async () => {
  const findings = await runClassificationScenario({
    authorizationError: codedError("DEPTH_ZERO_SELF_SIGNED_CERT"),
  });

  assert.deepEqual(
    findings.map((finding) => finding.id),
    ["tls-certificate-untrusted"],
  );
});

test("independent chain and hostname failures produce two correctly named findings", async () => {
  const findings = await runClassificationScenario({
    authorizationError: codedError("DEPTH_ZERO_SELF_SIGNED_CERT"),
    identityError: codedError("ERR_TLS_CERT_ALTNAME_INVALID"),
  });

  assert.deepEqual(
    new Set(findings.map((finding) => finding.id)),
    new Set([
      "tls-certificate-hostname-mismatch",
      "tls-certificate-untrusted",
    ]),
  );
});

test("unknown authorization error produces one generic validation finding", async () => {
  const findings = await runClassificationScenario({
    authorizationError: codedError("SOMETHING_NEW", "internal detail"),
  });

  assert.deepEqual(
    findings.map((finding) => finding.id),
    ["tls-certificate-validation-error"],
  );
  assert.equal(findings[0]?.evidence.includes("internal detail"), false);
});

test("modern and legacy probes use separate pinned connection options", async () => {
  const captured: tls.ConnectionOptions[] = [];
  await runTlsScanner("https://example.test", "passive", {
    checkServerIdentity: () => undefined,
    connect: scannerConnector({
      authorizationError: codedError("DEPTH_ZERO_SELF_SIGNED_CERT"),
      captured,
    }),
    resolveTarget: async () => fakeTarget(),
  });

  assert.equal(captured.length, 3);
  const modern = captured.find((entry) => entry.minVersion === undefined);
  assert.ok(modern);
  assert.equal(modern.host, "203.0.113.10");
  assert.equal(modern.servername, "example.test");
  assert.equal(modern.ciphers, undefined);
  assert.equal(modern.maxVersion, undefined);

  for (const version of ["TLSv1", "TLSv1.1"] as const) {
    const legacy = captured.find((entry) => entry.minVersion === version);
    assert.ok(legacy);
    assert.equal(legacy.host, "203.0.113.10");
    assert.equal(legacy.servername, "example.test");
    assert.equal(legacy.maxVersion, version);
    assert.equal(legacy.ciphers, "DEFAULT@SECLEVEL=0");
  }
});

test("IP literal probes omit SNI", async () => {
  const captured: tls.ConnectionOptions[] = [];
  await runTlsScanner("https://127.0.0.1", "passive", {
    checkServerIdentity: () => undefined,
    connect: scannerConnector({
      authorizationError: codedError("DEPTH_ZERO_SELF_SIGNED_CERT"),
      captured,
    }),
    resolveTarget: async () => fakeTarget("127.0.0.1"),
  });

  assert.equal(captured.length, 3);
  assert.ok(captured.every((entry) => entry.servername === undefined));
});

test("legacy classifier reserves not-supported for explicit protocol-version rejection", () => {
  assert.deepEqual(
    classifyLegacyProbeError(
      codedError("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION"),
    ),
    {
      status: "not-supported",
      code: "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION",
    },
  );
  assert.deepEqual(
    classifyLegacyProbeError(
      codedError("EPROTO", "tlsv1 alert protocol version"),
    ),
    { status: "not-supported", code: "EPROTO" },
  );
});

test("ambiguous legacy probe errors are classified inconclusive", () => {
  const cases = [
    new Error("TLS diagnostic timeout"),
    codedError("ECONNRESET"),
    codedError("ERR_SSL_NO_SHARED_CIPHER"),
    codedError("ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED"),
    codedError("ERR_SSL_HANDSHAKE_FAILURE"),
    codedError("ERR_SSL_NO_PROTOCOLS_AVAILABLE"),
    codedError("UNRECOGNIZED_TLS_FAILURE", "sensitive internal detail"),
  ];

  for (const error of cases) {
    assert.equal(classifyLegacyProbeError(error).status, "inconclusive");
  }
});

for (const scenario of [
  { name: "timeout", outcome: "timeout" as const, code: "TLS_DIAGNOSTIC_TIMEOUT" },
  { name: "connection reset", outcome: codedError("ECONNRESET"), code: "ECONNRESET" },
  {
    name: "no shared cipher",
    outcome: codedError("ERR_SSL_NO_SHARED_CIPHER"),
    code: "ERR_SSL_NO_SHARED_CIPHER",
  },
  {
    name: "client certificate required",
    outcome: codedError("ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED"),
    code: "ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED",
  },
  {
    name: "general handshake failure",
    outcome: codedError("ERR_SSL_HANDSHAKE_FAILURE"),
    code: "ERR_SSL_HANDSHAKE_FAILURE",
  },
  {
    name: "local runtime restriction",
    outcome: codedError("ERR_SSL_NO_PROTOCOLS_AVAILABLE"),
    code: "ERR_SSL_NO_PROTOCOLS_AVAILABLE",
  },
  {
    name: "unknown TLS error",
    outcome: codedError("UNRECOGNIZED_TLS_FAILURE", "sensitive internal detail"),
    code: "UNRECOGNIZED_TLS_FAILURE",
  },
]) {
  test(`${scenario.name} remains inconclusive through the production probe flow`, async () => {
    const findings = legacyOnly(await runLegacyFlow({
      TLSv1: scenario.outcome,
      "TLSv1.1": codedError("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION"),
    }));

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.id, "tls-legacy-probe-inconclusive");
    assert.match(findings[0]?.evidence ?? "", new RegExp(scenario.code));
    assert.equal(findings[0]?.evidence.includes("sensitive internal detail"), false);
  });
}

test("TLS 1.0 support produces one legacy finding", async () => {
  const findings = legacyOnly(await runLegacyFlow({
    TLSv1: "supported",
    "TLSv1.1": codedError("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION"),
  }));

  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.id, "tls-legacy-version");
  assert.match(findings[0]?.evidence ?? "", /TLSv1=HANDSHAKE_SUCCEEDED/);
});

test("TLS 1.1 support produces one legacy finding", async () => {
  const findings = legacyOnly(await runLegacyFlow({
    TLSv1: codedError("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION"),
    "TLSv1.1": "supported",
  }));

  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.id, "tls-legacy-version");
  assert.match(findings[0]?.evidence ?? "", /TLSv1\.1=HANDSHAKE_SUCCEEDED/);
});

test("supported plus inconclusive produces only one legacy finding", async () => {
  const findings = legacyOnly(await runLegacyFlow({
    TLSv1: "supported",
    "TLSv1.1": codedError("ECONNRESET"),
  }));

  assert.deepEqual(findings.map((finding) => finding.id), ["tls-legacy-version"]);
  assert.match(findings[0]?.evidence ?? "", /TLSv1\.1=ECONNRESET/);
});

test("two inconclusive probes produce one deduplicated inconclusive finding", async () => {
  const findings = legacyOnly(await runLegacyFlow({
    TLSv1: codedError("ECONNRESET"),
    "TLSv1.1": codedError("ERR_SSL_NO_SHARED_CIPHER"),
  }));

  assert.deepEqual(
    findings.map((finding) => finding.id),
    ["tls-legacy-probe-inconclusive"],
  );
  assert.match(findings[0]?.evidence ?? "", /TLSv1=ECONNRESET/);
  assert.match(findings[0]?.evidence ?? "", /TLSv1\.1=ERR_SSL_NO_SHARED_CIPHER/);
});

test("two explicit protocol-version rejections produce no legacy result", async () => {
  const rejection = codedError("ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION");
  const findings = legacyOnly(await runLegacyFlow({
    TLSv1: rejection,
    "TLSv1.1": rejection,
  }));

  assert.deepEqual(findings, []);
});

test("legacy probe abort propagates instead of becoming inconclusive", async () => {
  const controller = new AbortController();
  const scan = runLegacyFlow(
    { TLSv1: "pending", "TLSv1.1": "pending" },
    controller.signal,
  );
  controller.abort();

  await assert.rejects(scan, { name: "AbortError" });
});

for (const fixtureCase of [
  { name: "TLS 1.0", minVersion: "TLSv1", maxVersion: "TLSv1" },
  { name: "TLS 1.1", minVersion: "TLSv1.1", maxVersion: "TLSv1.1" },
] as const) {
  test(`${fixtureCase.name}-only loopback fixture is detected or explicitly inconclusive`, async () => {
    const fixture = await startTlsTestFixture(fixtureCase);
    try {
      const findings = await runTlsScanner(fixture.url, "passive", {
        resolveTarget: async () => fakeTarget("127.0.0.1", fixture.port),
      });
      const legacy = findings.find((finding) => finding.id === "tls-legacy-version");
      const inconclusive = findings.find(
        (finding) => finding.id === "tls-legacy-probe-inconclusive",
      );

      assert.ok(legacy ?? inconclusive);
      assert.match(
        (legacy ?? inconclusive)?.evidence ?? "",
        new RegExp(fixtureCase.minVersion.replace(".", "\\.")),
      );
      assert.equal(fixture.applicationBytesReceived, 0);
    } finally {
      await fixture.close();
    }
  });
}

test("TLS 1.2+ loopback fixture does not produce a legacy finding", async () => {
  const fixture = await startTlsTestFixture({
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.3",
  });
  try {
    const findings = await runTlsScanner(fixture.url, "passive", {
      resolveTarget: async () => fakeTarget("127.0.0.1", fixture.port),
    });

    assert.equal(findings.some((finding) => finding.id === "tls-legacy-version"), false);
    assert.equal(fixture.applicationBytesReceived, 0);
  } finally {
    await fixture.close();
  }
});

test("combined TLS 1.0/1.1 fixture produces one deduplicated legacy finding", async () => {
  const fixture = await startTlsTestFixture({
    minVersion: "TLSv1",
    maxVersion: "TLSv1.1",
  });
  try {
    const findings = await runTlsScanner(fixture.url, "passive", {
      resolveTarget: async () => fakeTarget("127.0.0.1", fixture.port),
    });
    const legacy = findings.filter((finding) => finding.id === "tls-legacy-version");
    const inconclusive = findings.find(
      (finding) => finding.id === "tls-legacy-probe-inconclusive",
    );

    if (legacy.length > 0) {
      assert.equal(legacy.length, 1);
      assert.match(legacy[0]?.evidence ?? "", /TLSv1=HANDSHAKE_SUCCEEDED/);
      assert.match(legacy[0]?.evidence ?? "", /TLSv1\.1=HANDSHAKE_SUCCEEDED/);
    } else {
      assert.ok(inconclusive);
      assert.match(inconclusive.evidence, /TLSv1=/);
      assert.match(inconclusive.evidence, /TLSv1\.1=/);
    }
    assert.equal(fixture.applicationBytesReceived, 0);
  } finally {
    await fixture.close();
  }
});

test("diagnostic success cleans listeners and timeout before settlement", async () => {
  let socket: FakeDiagnosticTlsSocket | undefined;
  const result = connectDiagnosticTls("127.0.0.1", "example.test", 443, {
    connector: () => {
      socket = new FakeDiagnosticTlsSocket();
      queueMicrotask(() => socket?.emit("secureConnect"));
      return socket;
    },
  });

  assert.equal((await result).protocol, "TLSv1.3");
  assert.ok(socket);
  assertSocketClean(socket);
});

test("diagnostic error cleans listeners and timeout", async () => {
  let socket: FakeDiagnosticTlsSocket | undefined;
  const result = connectDiagnosticTls("127.0.0.1", "example.test", 443, {
    connector: () => {
      socket = new FakeDiagnosticTlsSocket();
      queueMicrotask(() => socket?.emit("error", codedError("ECONNRESET")));
      return socket;
    },
  });

  await assert.rejects(result, /ECONNRESET/);
  assert.ok(socket);
  assertSocketClean(socket);
});

test("diagnostic timeout cleans listeners and timeout", async () => {
  let socket: FakeDiagnosticTlsSocket | undefined;
  const result = connectDiagnosticTls("127.0.0.1", "example.test", 443, {
    connector: () => {
      socket = new FakeDiagnosticTlsSocket();
      queueMicrotask(() => socket?.emit("timeout"));
      return socket;
    },
  });

  await assert.rejects(result, /timeout/);
  assert.ok(socket);
  assertSocketClean(socket);
});

test("diagnostic abort closes the socket and removes listeners", async () => {
  const controller = new AbortController();
  let socket: FakeDiagnosticTlsSocket | undefined;
  const result = connectDiagnosticTls("127.0.0.1", "example.test", 443, {
    connector: () => {
      socket = new FakeDiagnosticTlsSocket();
      return socket;
    },
    signal: controller.signal,
  });

  controller.abort();
  await assert.rejects(result, { name: "AbortError" });
  assert.ok(socket);
  assertSocketClean(socket);
});

test("synchronous connector throw rejects without creating resources", async () => {
  await assert.rejects(
    connectDiagnosticTls("127.0.0.1", "example.test", 443, {
      connector: () => {
        throw codedError("CONNECTOR_THROW");
      },
    }),
    /CONNECTOR_THROW/,
  );
});

test("late error after success is absorbed until close and settles once", async () => {
  let socket: FakeDiagnosticTlsSocket | undefined;
  const result = connectDiagnosticTls("127.0.0.1", "example.test", 443, {
    connector: () => {
      socket = new FakeDiagnosticTlsSocket({
        onDestroy: (current) => {
          queueMicrotask(() => {
            current.emit("error", codedError("LATE_ERROR"));
            current.emit("close");
          });
        },
      });
      queueMicrotask(() => socket?.emit("secureConnect"));
      return socket;
    },
  });

  assert.equal((await result).protocol, "TLSv1.3");
  assert.ok(socket);
  assertSocketClean(socket);
});

test("late secureConnect after error is ignored and does not double settle", async () => {
  let socket: FakeDiagnosticTlsSocket | undefined;
  const result = connectDiagnosticTls("127.0.0.1", "example.test", 443, {
    connector: () => {
      socket = new FakeDiagnosticTlsSocket({
        onDestroy: (current) => {
          queueMicrotask(() => {
            current.emit("secureConnect");
            current.emit("close");
          });
        },
      });
      queueMicrotask(() => socket?.emit("error", codedError("FIRST_ERROR")));
      return socket;
    },
  });

  await assert.rejects(result, /FIRST_ERROR/);
  assert.ok(socket);
  assertSocketClean(socket);
});
