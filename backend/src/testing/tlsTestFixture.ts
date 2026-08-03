import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import tls from "node:tls";

export type TlsFixtureCertificate = "expired" | "mismatch" | "valid";

export interface TlsFixtureOptions {
  certificate?: TlsFixtureCertificate;
  maxVersion?: tls.SecureVersion;
  minVersion?: tls.SecureVersion;
}

export interface TlsTestFixture {
  readonly applicationBytesReceived: number;
  readonly port: number;
  readonly url: string;
  close(): Promise<void>;
}

const FIXTURE_DIRECTORY = resolve(process.cwd(), "test-fixtures", "tls");

const CERTIFICATE_FILES: Record<TlsFixtureCertificate, string> = {
  expired: "localhost-expired-cert.pem",
  mismatch: "mismatch-valid-cert.pem",
  valid: "localhost-valid-cert.pem",
};

export function readTlsFixturePem(filename: string): string {
  return readFileSync(resolve(FIXTURE_DIRECTORY, filename), "utf8");
}

export function assertTlsFixtureClaims(): void {
  const valid = new X509Certificate(readTlsFixturePem(CERTIFICATE_FILES.valid));
  const mismatch = new X509Certificate(
    readTlsFixturePem(CERTIFICATE_FILES.mismatch),
  );
  const expired = new X509Certificate(
    readTlsFixturePem(CERTIFICATE_FILES.expired),
  );
  const now = Date.now();

  assert.equal(valid.checkHost("localhost"), "localhost");
  assert.equal(valid.checkIP("127.0.0.1"), "127.0.0.1");
  assert.ok(Date.parse(valid.validFrom) < now);
  assert.ok(Date.parse(valid.validTo) > now);

  assert.equal(mismatch.checkHost("localhost"), undefined);
  assert.equal(mismatch.checkIP("127.0.0.1"), undefined);
  assert.equal(mismatch.checkHost("fixture.invalid"), "fixture.invalid");
  assert.ok(Date.parse(mismatch.validFrom) < now);
  assert.ok(Date.parse(mismatch.validTo) > now);

  assert.equal(expired.checkHost("localhost"), "localhost");
  assert.equal(expired.checkIP("127.0.0.1"), "127.0.0.1");
  assert.ok(Date.parse(expired.validTo) < now);
}

export async function startTlsTestFixture(
  options: TlsFixtureOptions = {},
): Promise<TlsTestFixture> {
  const sockets = new Set<tls.TLSSocket>();
  let applicationBytesReceived = 0;
  const minVersion = options.minVersion ?? "TLSv1.2";
  const maxVersion = options.maxVersion ?? "TLSv1.3";
  const legacyVersion = minVersion === "TLSv1" || minVersion === "TLSv1.1";

  const server = tls.createServer({
    cert: readTlsFixturePem(
      CERTIFICATE_FILES[options.certificate ?? "valid"],
    ),
    key: readTlsFixturePem("test-key.pem"),
    minVersion,
    maxVersion,
    ...(legacyVersion ? { ciphers: "DEFAULT@SECLEVEL=0" } : {}),
  });

  server.on("secureConnection", (socket) => {
    sockets.add(socket);
    socket.on("data", (data) => {
      applicationBytesReceived += data.length;
    });
    socket.once("close", () => sockets.delete(socket));
    socket.on("error", () => undefined);
  });
  server.on("tlsClientError", (_error, socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.on("error", () => undefined);
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    const onError = (error: Error): void => {
      server.removeListener("listening", onListening);
      rejectListen(error);
    };
    const onListening = (): void => {
      server.removeListener("error", onError);
      resolveListen();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(0, "127.0.0.1");
  });
  server.on("error", () => undefined);

  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;

  return {
    get applicationBytesReceived() {
      return applicationBytesReceived;
    },
    port,
    url: `https://127.0.0.1:${port}`,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolveClose, rejectClose) => {
        if (!server.listening) {
          resolveClose();
          return;
        }
        server.close((error) => {
          if (error) rejectClose(error);
          else resolveClose();
        });
      });
      server.removeAllListeners();
    },
  };
}
