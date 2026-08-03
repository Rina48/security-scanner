import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import test from "node:test";
import { safeFetchText } from "./egressPolicy.js";
import { ResourceLimitError } from "./resourceLimits.js";

const BODY_LIMIT = 1_024;

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  return (server.address() as AddressInfo).port;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

async function waitUntil(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("Socket zamanında kapanmadı.");
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
}

test("uzak body byte sınırında kabul edilir, aşımda okuma ve socket durdurulur", async () => {
  const sockets = new Set<Socket>();
  const intervals = new Set<NodeJS.Timeout>();
  const server = createServer((request, response) => {
    if (request.url === "/exact") {
      response.writeHead(200, { "content-length": String(BODY_LIMIT) });
      response.end(Buffer.alloc(BODY_LIMIT, "a"));
      return;
    }

    response.writeHead(200, { "content-type": "text/plain" });
    const interval = setInterval(() => {
      if (response.destroyed) {
        clearInterval(interval);
        intervals.delete(interval);
        return;
      }
      response.write(Buffer.alloc(256, "b"));
    }, 2);
    intervals.add(interval);
    response.once("close", () => {
      clearInterval(interval);
      intervals.delete(interval);
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });

  const port = await listen(server);
  const options = {
    access: "passive" as const,
    env: { ALLOWED_PASSIVE_HOSTS: "127.0.0.1" },
    maxResponseBodyBytes: BODY_LIMIT,
  };

  try {
    const exact = await safeFetchText(`http://127.0.0.1:${port}/exact`, {}, options);
    assert.equal(Buffer.byteLength(exact.body), BODY_LIMIT);

    await assert.rejects(
      safeFetchText(`http://127.0.0.1:${port}/large`, {}, options),
      (error) => error instanceof ResourceLimitError
        && error.code === "response-body-limit",
    );
    await waitUntil(() => sockets.size === 0);
    assert.equal(intervals.size, 0);
  } finally {
    for (const interval of intervals) clearInterval(interval);
    for (const socket of sockets) socket.destroy();
    await close(server);
  }
});
