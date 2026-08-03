import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { Socket } from "node:net";
import test from "node:test";
import { scannerFetch } from "../../utils/scannerHttp.js";
import { runTraversalScanner } from "./traversalScanner.js";

const originalEnvironment = {
  active: process.env.ALLOWED_ACTIVE_HOSTS,
  activePrivate: process.env.ALLOWED_ACTIVE_PRIVATE_HOSTS,
};

test.before(() => {
  process.env.ALLOWED_ACTIVE_HOSTS = "127.0.0.1";
  process.env.ALLOWED_ACTIVE_PRIVATE_HOSTS = "127.0.0.1";
});

test.after(() => {
  restoreEnvironment("ALLOWED_ACTIVE_HOSTS", originalEnvironment.active);
  restoreEnvironment(
    "ALLOWED_ACTIVE_PRIVATE_HOSTS",
    originalEnvironment.activePrivate,
  );
});

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

async function withDeadline<T>(promise: Promise<T>, timeoutMs = 2_000): Promise<T> {
  let timeoutHandle: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timeoutHandle = setTimeout(
          () => reject(new Error("Test fixture deadline exceeded")),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timeoutHandle) clearTimeout(timeoutHandle);
  }
}

async function startHoldingHttpFixture(): Promise<{
  readonly requestCount: number;
  readonly url: string;
  close(): Promise<void>;
  requestClosed: Promise<void>;
  requestStarted: Promise<void>;
}> {
  const sockets = new Set<Socket>();
  let requestCount = 0;
  let markRequestStarted: (() => void) | undefined;
  let markRequestClosed: (() => void) | undefined;
  const requestStarted = new Promise<void>((resolve) => {
    markRequestStarted = resolve;
  });
  const requestClosed = new Promise<void>((resolve) => {
    markRequestClosed = resolve;
  });

  const server = createServer((request) => {
    requestCount += 1;
    if (requestCount === 1) {
      request.socket.once("close", () => markRequestClosed?.());
      markRequestStarted?.();
    }
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  server.on("clientError", (_error, socket) => socket.destroy());

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const address = server.address();
  assert.ok(address && typeof address !== "string");

  return {
    get requestCount() {
      return requestCount;
    },
    url: `http://127.0.0.1:${address.port}`,
    requestClosed,
    requestStarted,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) => {
        if (!server.listening) {
          resolve();
          return;
        }
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
      server.removeAllListeners();
    },
  };
}

test("active scanner abort cancels the pending request and sends no next payload", async () => {
  const fixture = await startHoldingHttpFixture();
  const controller = new AbortController();
  try {
    const scan = runTraversalScanner(fixture.url, {
      signal: controller.signal,
    });
    await withDeadline(fixture.requestStarted);
    controller.abort();

    await assert.rejects(scan, { name: "AbortError" });
    await withDeadline(fixture.requestClosed);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(fixture.requestCount, 1);
  } finally {
    await fixture.close();
  }
});

test("scannerFetch per-request timeout still cancels the underlying request", async () => {
  const fixture = await startHoldingHttpFixture();
  try {
    const resultPromise = scannerFetch(fixture.url, {
      scope: "timeoutRegression",
      timeoutMs: 50,
    });
    await withDeadline(fixture.requestStarted);
    const result = await withDeadline(resultPromise);

    assert.equal(result.status, 0);
    assert.ok(result.elapsedMs >= 25);
    assert.ok(result.elapsedMs < 2_000);
    await withDeadline(fixture.requestClosed);
    assert.equal(fixture.requestCount, 1);
  } finally {
    await fixture.close();
  }
});
