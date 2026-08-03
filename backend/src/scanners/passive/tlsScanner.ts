import { isIP } from "node:net";
import tls from "node:tls";
import { URL } from "node:url";
import {
  getEgressPolicy,
  resolveEgressTarget,
  type EgressAccess,
  type EgressPolicy,
  type ValidatedTarget,
} from "../../security/egressPolicy.js";
import type { ScannerFinding } from "../../types.js";
import { abortError, isAbortError } from "../../utils/abort.js";

const SOCKET_TIMEOUT_MS = 5_000;
const LEGACY_PROBE_TIMEOUT_MS = 2_000;
const CERT_EXPIRY_WARNING_DAYS = 14;
const LEGACY_CIPHERS = "DEFAULT@SECLEVEL=0";
const LEGACY_VERSIONS = ["TLSv1", "TLSv1.1"] as const;

type LegacyTlsVersion = (typeof LEGACY_VERSIONS)[number];

export interface DiagnosticTlsSocket {
  readonly authorized: boolean;
  readonly authorizationError?: Error | string;
  getPeerCertificate(): tls.PeerCertificate;
  getProtocol(): string | null;
  setTimeout(timeout: number): void;
  once(event: "secureConnect", listener: () => void): void;
  once(event: "close", listener: () => void): void;
  on(event: "error", listener: (error: Error) => void): void;
  on(event: "timeout", listener: () => void): void;
  removeListener(event: "secureConnect", listener: () => void): void;
  removeListener(event: "close", listener: () => void): void;
  removeListener(event: "error", listener: (error: Error) => void): void;
  removeListener(event: "timeout", listener: () => void): void;
  destroy(): void;
}

export interface DiagnosticTlsSnapshot {
  authorized: boolean;
  authorizationError?: Error | string;
  certificate: tls.PeerCertificate;
  protocol: string | null;
}

export type DiagnosticTlsConnector = (
  options: tls.ConnectionOptions,
) => DiagnosticTlsSocket;

export type TlsTargetResolver = (
  targetUrl: string,
  policy: EgressPolicy,
) => Promise<ValidatedTarget>;

export interface TlsScannerDependencies {
  connect?: DiagnosticTlsConnector;
  checkServerIdentity?: typeof tls.checkServerIdentity;
  legacyProbeTimeoutMs?: number;
  now?: () => number;
  resolveTarget?: TlsTargetResolver;
  signal?: AbortSignal;
  timeoutMs?: number;
}

interface DiagnosticConnectOptions {
  connector?: DiagnosticTlsConnector;
  signal?: AbortSignal;
  timeoutMs?: number;
  tlsOptions?: Pick<tls.ConnectionOptions, "ciphers" | "maxVersion" | "minVersion">;
}

export type TlsAuthorizationCategory =
  | "hostname-mismatch"
  | "expired"
  | "not-yet-valid"
  | "revoked"
  | "trust-chain"
  | "other";

export interface TlsAuthorizationClassification {
  category: TlsAuthorizationCategory;
  code: string;
}

export type LegacyProbeStatus = "supported" | "not-supported" | "inconclusive";

export interface LegacyProbeClassification {
  status: Exclude<LegacyProbeStatus, "supported">;
  code: string;
}

interface LegacyProbeResult {
  status: LegacyProbeStatus;
  version: LegacyTlsVersion;
  code: string;
}

const defaultDiagnosticTlsConnector: DiagnosticTlsConnector = (options) =>
  tls.connect(options);

function errorFromUnknown(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback);
}

function safeErrorCode(error: unknown): string {
  const normalize = (value: string): string => {
    const normalized = value.trim().toUpperCase();
    return /^[A-Z0-9_-]{1,80}$/.test(normalized)
      ? normalized
      : "UNKNOWN_TLS_VALIDATION_ERROR";
  };
  if (typeof error === "string") {
    return normalize(error);
  }
  if (
    error &&
    typeof error === "object" &&
    "code" in error &&
    typeof error.code === "string"
  ) {
    return normalize(error.code);
  }
  if (error instanceof Error && error.name && error.name !== "Error") {
    return normalize(error.name);
  }
  return "UNKNOWN_TLS_VALIDATION_ERROR";
}

export function classifyTlsAuthorizationError(
  error: Error | string | undefined,
): TlsAuthorizationClassification {
  const code = safeErrorCode(error);
  const fallback = typeof error === "string"
    ? error.toUpperCase()
    : `${error?.name ?? ""} ${error?.message ?? ""}`.toUpperCase();

  if (
    code === "ERR_TLS_CERT_ALTNAME_INVALID" ||
    fallback.includes("ALTNAME") ||
    fallback.includes("HOSTNAME MISMATCH")
  ) {
    return { category: "hostname-mismatch", code };
  }
  if (code === "CERT_HAS_EXPIRED" || fallback.includes("CERTIFICATE HAS EXPIRED")) {
    return { category: "expired", code };
  }
  if (code === "CERT_NOT_YET_VALID" || fallback.includes("NOT YET VALID")) {
    return { category: "not-yet-valid", code };
  }
  if (code === "CERT_REVOKED" || fallback.includes("CERTIFICATE REVOKED")) {
    return { category: "revoked", code };
  }

  const chainCodes = new Set([
    "CERT_SIGNATURE_FAILURE",
    "CERT_UNTRUSTED",
    "DEPTH_ZERO_SELF_SIGNED_CERT",
    "INVALID_CA",
    "SELF_SIGNED_CERT_IN_CHAIN",
    "UNABLE_TO_GET_ISSUER_CERT",
    "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  ]);
  if (
    chainCodes.has(code) ||
    fallback.includes("SELF-SIGNED") ||
    fallback.includes("SELF SIGNED") ||
    fallback.includes("UNABLE TO VERIFY")
  ) {
    return { category: "trust-chain", code };
  }

  return { category: "other", code };
}

export function classifyLegacyProbeError(
  error: unknown,
): LegacyProbeClassification {
  let code = safeErrorCode(error);
  const message = (
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : ""
  ).toUpperCase();

  if (
    code === "UNKNOWN_TLS_VALIDATION_ERROR" &&
    message.includes("TLS DIAGNOSTIC TIMEOUT")
  ) {
    code = "TLS_DIAGNOSTIC_TIMEOUT";
  }

  if (
    code === "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION" ||
    message.includes("ALERT PROTOCOL VERSION")
  ) {
    return { status: "not-supported", code };
  }

  return { status: "inconclusive", code };
}

export function connectDiagnosticTls(
  address: string,
  originalHostname: string,
  port: number,
  options: DiagnosticConnectOptions = {},
): Promise<DiagnosticTlsSnapshot> {
  const signal = options.signal;
  if (signal?.aborted) return Promise.reject(abortError(signal));

  const connector = options.connector ?? defaultDiagnosticTlsConnector;
  const timeoutMs = options.timeoutMs ?? SOCKET_TIMEOUT_MS;
  const connectionOptions: tls.ConnectionOptions = {
    host: address,
    port,
    rejectUnauthorized: false,
    ...(isIP(originalHostname) === 0 ? { servername: originalHostname } : {}),
    ...options.tlsOptions,
  };

  return new Promise((resolve, reject) => {
    let socket: DiagnosticTlsSocket;
    let timeoutHandle: NodeJS.Timeout | undefined;
    let closing = false;
    let settled = false;
    let snapshot: DiagnosticTlsSnapshot | undefined;
    let terminalError: Error | undefined;

    const disableTimeouts = (): void => {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
        timeoutHandle = undefined;
      }
      try {
        socket.setTimeout(0);
      } catch {
        // Socket cleanup continues even if the implementation rejects setTimeout(0).
      }
    };

    const cleanup = (): void => {
      disableTimeouts();
      socket.removeListener("secureConnect", onSecureConnect);
      socket.removeListener("error", onError);
      socket.removeListener("timeout", onTimeout);
      socket.removeListener("close", onClose);
      signal?.removeEventListener("abort", onAbort);
    };

    const settleAfterCleanup = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (terminalError) {
        reject(terminalError);
        return;
      }
      if (snapshot) {
        resolve(snapshot);
        return;
      }
      reject(new Error("TLS socket closed before diagnostic metadata was available"));
    };

    const destroyOnce = (): void => {
      if (closing) return;
      closing = true;
      try {
        socket.destroy();
      } catch (error) {
        terminalError ??= errorFromUnknown(error, "TLS socket cleanup failed");
        settleAfterCleanup();
      }
    };

    const fail = (error: Error): void => {
      if (settled || terminalError) return;
      terminalError = error;
      snapshot = undefined;
      destroyOnce();
    };

    const onSecureConnect = (): void => {
      if (settled || terminalError || snapshot) return;
      try {
        snapshot = {
          authorized: socket.authorized,
          authorizationError: socket.authorizationError,
          certificate: socket.getPeerCertificate(),
          protocol: socket.getProtocol(),
        };
      } catch (error) {
        fail(errorFromUnknown(error, "TLS diagnostic metadata read failed"));
        return;
      }
      disableTimeouts();
      destroyOnce();
    };

    const onError = (error: Error): void => {
      if (settled) return;
      if (snapshot && closing) return;
      fail(error);
    };

    const onTimeout = (): void => {
      if (snapshot && closing) return;
      fail(new Error("TLS diagnostic timeout"));
    };

    const onAbort = (): void => {
      if (!signal) return;
      fail(abortError(signal));
    };

    const onClose = (): void => {
      if (signal?.aborted) {
        terminalError = abortError(signal);
        snapshot = undefined;
      }
      settleAfterCleanup();
    };

    try {
      socket = connector(connectionOptions);
    } catch (error) {
      reject(errorFromUnknown(error, "TLS connector failed"));
      return;
    }

    socket.once("secureConnect", onSecureConnect);
    socket.on("error", onError);
    socket.on("timeout", onTimeout);
    socket.once("close", onClose);
    signal?.addEventListener("abort", onAbort, { once: true });

    try {
      socket.setTimeout(timeoutMs);
      timeoutHandle = setTimeout(onTimeout, timeoutMs);
    } catch (error) {
      fail(errorFromUnknown(error, "TLS timeout setup failed"));
      return;
    }

    if (signal?.aborted) onAbort();
  });
}

async function probeLegacyVersion(
  target: ValidatedTarget,
  port: number,
  version: LegacyTlsVersion,
  dependencies: TlsScannerDependencies,
): Promise<LegacyProbeResult> {
  try {
    await connectDiagnosticTls(
      target.selectedAddress.address,
      target.hostname,
      port,
      {
        connector: dependencies.connect,
        signal: dependencies.signal,
        timeoutMs: dependencies.legacyProbeTimeoutMs ?? LEGACY_PROBE_TIMEOUT_MS,
        tlsOptions: {
          ciphers: LEGACY_CIPHERS,
          minVersion: version,
          maxVersion: version,
        },
      },
    );
    return { status: "supported", version, code: "HANDSHAKE_SUCCEEDED" };
  } catch (error) {
    if (isAbortError(error, dependencies.signal)) throw error;
    return { ...classifyLegacyProbeError(error), version };
  }
}

function addFinding(
  findings: Map<string, ScannerFinding>,
  finding: ScannerFinding,
): void {
  if (!findings.has(finding.id)) findings.set(finding.id, finding);
}

function addHostnameMismatchFinding(
  findings: Map<string, ScannerFinding>,
  targetUrl: string,
  hostname: string,
): void {
  addFinding(findings, {
    id: "tls-certificate-hostname-mismatch",
    category: "tls",
    title: "TLS certificate does not match the target hostname",
    severity: "high",
    confidence: "high",
    evidence: `Certificate identity check failed for ${hostname}.`,
    remediation: "Deploy a certificate whose SAN entries include the exact target hostname.",
    endpoint: targetUrl,
  });
}

function addExpiredFinding(
  findings: Map<string, ScannerFinding>,
  targetUrl: string,
  validTo?: string,
): void {
  addFinding(findings, {
    id: "tls-certificate-expired",
    category: "tls",
    title: "TLS certificate is expired",
    severity: "critical",
    confidence: "high",
    evidence: validTo
      ? `Certificate expiry date: ${validTo}`
      : "TLS authorization failed because the certificate has expired.",
    remediation: "Renew and deploy a valid certificate from a trusted certificate authority.",
    endpoint: targetUrl,
  });
}

function addNotYetValidFinding(
  findings: Map<string, ScannerFinding>,
  targetUrl: string,
  validFrom?: string,
): void {
  addFinding(findings, {
    id: "tls-certificate-not-yet-valid",
    category: "tls",
    title: "TLS certificate is not yet valid",
    severity: "high",
    confidence: "high",
    evidence: validFrom
      ? `Certificate validity starts at: ${validFrom}`
      : "TLS authorization reported a certificate that is not yet valid.",
    remediation: "Deploy a certificate whose validity period includes the current time.",
    endpoint: targetUrl,
  });
}

function inspectModernSnapshot(
  snapshot: DiagnosticTlsSnapshot,
  target: ValidatedTarget,
  targetUrl: string,
  checker: typeof tls.checkServerIdentity,
  now: number,
  findings: Map<string, ScannerFinding>,
): void {
  const certificate = snapshot.certificate;
  const validFromMs = Date.parse(certificate.valid_from);
  const validToMs = Date.parse(certificate.valid_to);

  if (Number.isFinite(validFromMs) && validFromMs > now) {
    addNotYetValidFinding(findings, targetUrl, certificate.valid_from);
  }
  if (Number.isFinite(validToMs) && validToMs <= now) {
    addExpiredFinding(findings, targetUrl, certificate.valid_to);
  } else if (Number.isFinite(validToMs)) {
    const daysToExpire = Math.ceil((validToMs - now) / (24 * 60 * 60 * 1000));
    if (daysToExpire <= CERT_EXPIRY_WARNING_DAYS) {
      addFinding(findings, {
        id: "tls-certificate-expiring-soon",
        category: "tls",
        title: "TLS certificate expires soon",
        severity: "medium",
        confidence: "high",
        evidence: `Certificate expires in ${daysToExpire} day(s)`,
        remediation: "Renew the certificate before expiration to avoid outage.",
        endpoint: targetUrl,
      });
    }
  }

  let identityError: Error | undefined;
  try {
    identityError = checker(target.hostname, certificate);
  } catch (error) {
    identityError = errorFromUnknown(error, "TLS hostname check failed");
  }
  if (identityError) {
    addHostnameMismatchFinding(findings, targetUrl, target.hostname);
  }

  if (snapshot.authorized) return;
  const classification = classifyTlsAuthorizationError(snapshot.authorizationError);
  switch (classification.category) {
    case "hostname-mismatch":
      addHostnameMismatchFinding(findings, targetUrl, target.hostname);
      break;
    case "expired":
      addExpiredFinding(findings, targetUrl, certificate.valid_to);
      break;
    case "not-yet-valid":
      addNotYetValidFinding(findings, targetUrl, certificate.valid_from);
      break;
    case "revoked":
      addFinding(findings, {
        id: "tls-certificate-revoked",
        category: "tls",
        title: "TLS certificate is revoked",
        severity: "critical",
        confidence: "high",
        evidence: `TLS authorization error: ${classification.code}.`,
        remediation: "Replace the revoked certificate and investigate the revocation cause.",
        endpoint: targetUrl,
      });
      break;
    case "trust-chain":
      addFinding(findings, {
        id: "tls-certificate-untrusted",
        category: "tls",
        title: "TLS certificate chain is not trusted",
        severity: "high",
        confidence: "high",
        evidence: `TLS authorization error: ${classification.code}.`,
        remediation: "Deploy a certificate whose full chain is trusted by supported clients.",
        endpoint: targetUrl,
      });
      break;
    case "other":
      addFinding(findings, {
        id: "tls-certificate-validation-error",
        category: "tls",
        title: "TLS certificate validation failed",
        severity: "high",
        confidence: "medium",
        evidence: `TLS authorization error: ${classification.code}.`,
        remediation: "Inspect and correct the certificate validation failure.",
        endpoint: targetUrl,
      });
      break;
  }
}

function addTlsScanFailure(
  findings: Map<string, ScannerFinding>,
  targetUrl: string,
  error: unknown,
): void {
  const normalized = errorFromUnknown(error, "Unknown TLS error");
  addFinding(findings, {
    id: "tls-scan-failed",
    category: "tls",
    title: "TLS scan failed",
    severity: "low",
    confidence: "medium",
    evidence: `TLS diagnostic error: ${safeErrorCode(normalized)}.`,
    remediation: "Verify network connectivity and TLS configuration before repeating the scan.",
    endpoint: targetUrl,
  });
}

export async function runTlsScanner(
  targetUrl: string,
  access: Extract<EgressAccess, "passive" | "active"> = "passive",
  dependencies: TlsScannerDependencies = {},
): Promise<ScannerFinding[]> {
  const findings = new Map<string, ScannerFinding>();
  const parsedUrl = new URL(targetUrl);

  if (parsedUrl.protocol !== "https:") {
    return [{
      id: "non-https-target",
      category: "tls",
      title: "HTTPS is not enabled for target URL",
      severity: "high",
      confidence: "high",
      evidence: `Target protocol: ${parsedUrl.protocol}`,
      remediation: "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
      endpoint: targetUrl,
    }];
  }

  if (dependencies.signal?.aborted) throw abortError(dependencies.signal);

  const resolveTarget = dependencies.resolveTarget ?? resolveEgressTarget;
  let target: ValidatedTarget;
  try {
    target = await resolveTarget(targetUrl, getEgressPolicy(access));
  } catch (error) {
    if (isAbortError(error, dependencies.signal)) throw error;
    addTlsScanFailure(findings, targetUrl, error);
    return [...findings.values()];
  }

  const port = Number(parsedUrl.port) || 443;
  const modernPromise = connectDiagnosticTls(
    target.selectedAddress.address,
    target.hostname,
    port,
    {
      connector: dependencies.connect,
      signal: dependencies.signal,
      timeoutMs: dependencies.timeoutMs ?? SOCKET_TIMEOUT_MS,
    },
  );
  const legacyPromises = LEGACY_VERSIONS.map((version) =>
    probeLegacyVersion(target, port, version, dependencies));

  const [modernResult, ...legacyResults] = await Promise.allSettled([
    modernPromise,
    ...legacyPromises,
  ]);

  if (dependencies.signal?.aborted) throw abortError(dependencies.signal);

  if (modernResult?.status === "fulfilled") {
    inspectModernSnapshot(
      modernResult.value,
      target,
      targetUrl,
      dependencies.checkServerIdentity ?? tls.checkServerIdentity,
      (dependencies.now ?? Date.now)(),
      findings,
    );
  } else if (modernResult) {
    if (isAbortError(modernResult.reason, dependencies.signal)) throw modernResult.reason;
    addTlsScanFailure(findings, targetUrl, modernResult.reason);
  }

  const probeResults: LegacyProbeResult[] = [];
  for (const [index, result] of legacyResults.entries()) {
    const version = LEGACY_VERSIONS[index];
    if (!version || !result) continue;
    if (result.status === "rejected") {
      if (isAbortError(result.reason, dependencies.signal)) throw result.reason;
      probeResults.push({ ...classifyLegacyProbeError(result.reason), version });
    } else {
      probeResults.push(result.value);
    }
  }

  const supportedVersions = probeResults
    .filter((result) => result.status === "supported")
    .map((result) => result.version);
  const hasInconclusive = probeResults.some(
    (result) => result.status === "inconclusive",
  );
  const probeEvidence = probeResults
    .map((result) => `${result.version}=${result.code}`)
    .join("; ");

  if (supportedVersions.length > 0) {
    addFinding(findings, {
      id: "tls-legacy-version",
      category: "tls",
      title: "Legacy TLS version detected",
      severity: "high",
      confidence: "high",
      evidence: `Exact-version probe results: ${probeEvidence}.`,
      remediation: "Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
      endpoint: targetUrl,
    });
  } else if (hasInconclusive) {
    addFinding(findings, {
      id: "tls-legacy-probe-inconclusive",
      category: "tls",
      title: "Legacy TLS support could not be determined",
      severity: "low",
      confidence: "low",
      evidence: `Exact-version probe results: ${probeEvidence}.`,
      remediation: "Repeat the exact-version probes with a TLS runtime that supports legacy diagnostics.",
      endpoint: targetUrl,
    });
  }

  return [...findings.values()];
}
