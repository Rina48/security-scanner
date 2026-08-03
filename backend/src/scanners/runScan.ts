import { isActiveScanAllowed } from "../policy/targetPolicyGuard.js";
import { safeFetchText } from "../security/egressPolicy.js";
import { BROWSER_HEADERS } from "../utils/httpHeaders.js";
import { throwIfAborted, withTimeoutSignal } from "../utils/abort.js";
import { createScanReport } from "../reporting/reportGenerator.js";
import { fetchRobotsPaths } from "../utils/robotsParser.js";
import { INITIAL_FETCH_TIMEOUT_MS } from "./constants.js";
import { runCookieScanner } from "./passive/cookieScanner.js";
import { runResponseLeakScanner } from "./passive/responseLeakScanner.js";
import { runSecurityHeaderScanner } from "./passive/securityHeaderScanner.js";
import {
  runTlsScanner,
  type TlsScannerDependencies,
} from "./passive/tlsScanner.js";
import { runLocalActiveScanner } from "./active/localActiveScanner.js";
import { runPathDiscoveryScanner } from "./active/pathDiscoveryScanner.js";
import { runHttpMethodScanner } from "./active/httpMethodScanner.js";
import { runTraversalScanner } from "./active/traversalScanner.js";
import { runOpenRedirectScanner } from "./active/openRedirectScanner.js";
import { runCmdInjectionScanner } from "./active/cmdInjectionScanner.js";
import { runDefaultCredentialScanner } from "./active/defaultCredentialScanner.js";
import type { ScanRequest, ScanResult, ScannerFinding } from "../types.js";

export interface RunScanDependencies {
  activeScanner?: typeof runAllActiveModules;
  cookieScanner?: typeof runCookieScanner;
  createReport?: typeof createScanReport;
  fetchText?: typeof safeFetchText;
  responseLeakScanner?: typeof runResponseLeakScanner;
  securityHeaderScanner?: typeof runSecurityHeaderScanner;
  tlsScanner?: typeof runTlsScanner;
}

export interface RunScanOptions {
  dependencies?: RunScanDependencies;
  signal?: AbortSignal;
  tlsDependencies?: Omit<TlsScannerDependencies, "signal">;
}

export interface ActiveModuleDependencies {
  cmdInjectionScanner?: typeof runCmdInjectionScanner;
  credentialScanner?: typeof runDefaultCredentialScanner;
  httpMethodScanner?: typeof runHttpMethodScanner;
  localScanner?: typeof runLocalActiveScanner;
  openRedirectScanner?: typeof runOpenRedirectScanner;
  pathDiscoveryScanner?: typeof runPathDiscoveryScanner;
  robotsPaths?: typeof fetchRobotsPaths;
  traversalScanner?: typeof runTraversalScanner;
}

function hasTlsDiagnostic(findings: ScannerFinding[]): boolean {
  return findings.some((finding) => finding.id !== "tls-scan-failed");
}

export async function runAllActiveModules(
  targetUrl: string,
  options: {
    credentialCheck?: boolean;
    dependencies?: ActiveModuleDependencies;
    signal?: AbortSignal;
  },
): Promise<ScannerFinding[]> {
  throwIfAborted(options.signal);
  const dependencies = options.dependencies ?? {};
  const origin = new URL(targetUrl).origin;
  const robotsPaths = await (dependencies.robotsPaths ?? fetchRobotsPaths)(origin, {
    signal: options.signal,
  });
  throwIfAborted(options.signal);

  // Tüm aktif modüller paralel çalışır.
  const moduleFactories: Array<() => Promise<ScannerFinding[]>> = [
    () => (dependencies.localScanner ?? runLocalActiveScanner)(targetUrl, {
      signal: options.signal,
    }),
    () => (dependencies.pathDiscoveryScanner ?? runPathDiscoveryScanner)(targetUrl, {
      extraPaths: robotsPaths,
      signal: options.signal,
    }),
    () => (dependencies.httpMethodScanner ?? runHttpMethodScanner)(targetUrl, {
      signal: options.signal,
    }),
    () => (dependencies.traversalScanner ?? runTraversalScanner)(targetUrl, {
      signal: options.signal,
    }),
    () => (dependencies.openRedirectScanner ?? runOpenRedirectScanner)(targetUrl, {
      signal: options.signal,
    }),
    () => (dependencies.cmdInjectionScanner ?? runCmdInjectionScanner)(targetUrl, {
      signal: options.signal,
    }),
  ];

  if (options.credentialCheck) {
    moduleFactories.push(() =>
      (dependencies.credentialScanner ?? runDefaultCredentialScanner)(
        targetUrl,
        { signal: options.signal },
        robotsPaths,
      ));
  }

  const modules: Promise<ScannerFinding[]>[] = [];
  for (const startModule of moduleFactories) {
    throwIfAborted(options.signal);
    modules.push(startModule());
    if (options.signal?.aborted) {
      await Promise.allSettled(modules);
      throwIfAborted(options.signal);
    }
  }

  const results = await Promise.allSettled(modules);
  throwIfAborted(options.signal);

  return results.flatMap((result) =>
    result.status === "fulfilled" ? result.value : [],
  );
}

export async function runScan(
  scanRequest: ScanRequest,
  options: RunScanOptions = {},
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const canRunActive = isActiveScanAllowed(scanRequest.targetUrl, scanRequest.mode);
  if (scanRequest.mode === "active" && !canRunActive) {
    throw new Error("Active scan target is not authorized.");
  }

  throwIfAborted(options.signal);
  const dependencies = options.dependencies ?? {};
  const fetchText = dependencies.fetchText ?? safeFetchText;
  const tlsScanner = dependencies.tlsScanner ?? runTlsScanner;
  const fetchPromise = withTimeoutSignal(
    options.signal,
    INITIAL_FETCH_TIMEOUT_MS,
    (requestSignal) => fetchText(
      scanRequest.targetUrl,
      {
        method: "GET",
        redirect: "follow",
        headers: BROWSER_HEADERS,
        signal: requestSignal,
      },
      { access: scanRequest.mode },
    ),
  );
  const tlsPromise = tlsScanner(scanRequest.targetUrl, scanRequest.mode, {
    ...options.tlsDependencies,
    signal: options.signal,
  });

  const [fetchResult, tlsResult] = await Promise.allSettled([
    fetchPromise,
    tlsPromise,
  ]);
  throwIfAborted(options.signal);

  const tlsFindings = tlsResult.status === "fulfilled" ? tlsResult.value : [];

  if (fetchResult.status === "rejected") {
    if (!hasTlsDiagnostic(tlsFindings)) throw fetchResult.reason;

    return (dependencies.createReport ?? createScanReport)({
      targetUrl: scanRequest.targetUrl,
      mode: scanRequest.mode,
      findings: tlsFindings,
      isActiveAllowed: canRunActive,
      startedAt,
      severityOverrides: scanRequest.severityOverrides,
      scanId: scanRequest.scanId,
    });
  }

  const passiveResponse = fetchResult.value;
  const responseBody = passiveResponse.body;

  const passiveFindings: ScannerFinding[] = [
    ...(dependencies.responseLeakScanner ?? runResponseLeakScanner)(
      responseBody,
      scanRequest.targetUrl,
    ),
    ...(dependencies.securityHeaderScanner ?? runSecurityHeaderScanner)(
      passiveResponse.headers,
      scanRequest.targetUrl,
    ),
    ...(dependencies.cookieScanner ?? runCookieScanner)(
      passiveResponse.headers,
      scanRequest.targetUrl,
    ),
    ...tlsFindings,
  ];

  throwIfAborted(options.signal);

  // Debug: Aktif tarama politika durumu
  if (scanRequest.mode === "active") {
    console.info(
      "[runScan] Aktif tarama politika:",
      {
        targetUrl: scanRequest.targetUrl,
        credentialCheck: scanRequest.credentialCheck,
        canRunActive,
      }
    );
  }

  const activeFindings =
    scanRequest.mode === "active" && canRunActive
      ? await (dependencies.activeScanner ?? runAllActiveModules)(
          scanRequest.targetUrl,
          {
            credentialCheck: scanRequest.credentialCheck,
            signal: options.signal,
          },
        )
      : [];

  throwIfAborted(options.signal);

  if (scanRequest.mode === "active" && canRunActive) {
    console.info("[runScan] Aktif tarama tamamlandı:", { bulguSayisi: activeFindings.length });
  }

  return (dependencies.createReport ?? createScanReport)({
    targetUrl: scanRequest.targetUrl,
    mode: scanRequest.mode,
    findings: [...passiveFindings, ...activeFindings],
    isActiveAllowed: canRunActive,
    startedAt,
    severityOverrides: scanRequest.severityOverrides,
    responseBody,
    scanId: scanRequest.scanId,
  });
}
