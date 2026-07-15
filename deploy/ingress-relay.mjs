import {request as httpRequest} from "node:http";
import {createServer} from "node:http";

const upstreamPort = Number.parseInt(process.env.COVEN_INGRESS_UPSTREAM_PORT || "18096", 10);
const revision = String(process.env.COVEN_INGRESS_REVISION || "unknown");
const baseUri = String(process.env.COVEN_GITHUB_BASE_URI || process.env.PASSENGER_BASE_URI || "/github").replace(/\/$/, "");
const maxBodyBytes = 10 * 1024 * 1024;
const hopHeaders = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]);

function normalizedPath(url = "/") {
  const [path, query] = url.split("?", 2);
  let normalized = path;
  if (path === baseUri) normalized = "/";
  else if (path.startsWith(`${baseUri}/`)) normalized = path.slice(baseUri.length) || "/";
  if (normalized.length > 1) normalized = normalized.replace(/\/+$/, "");
  return `${normalized || "/"}${query === undefined ? "" : `?${query}`}`;
}

function jsonError(response, status, message) {
  if (response.writableEnded || response.destroyed) return;
  const body = Buffer.from(JSON.stringify({ok: false, error: message}));
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": body.length,
    "X-Coven-Ingress-Revision": revision,
  });
  response.end(body);
}

const server = createServer((incoming, outgoing) => {
  const declaredLength = Number.parseInt(String(incoming.headers["content-length"] || "0"), 10);
  if (Number.isFinite(declaredLength) && declaredLength > maxBodyBytes) {
    incoming.resume();
    jsonError(outgoing, 413, "payload too large");
    return;
  }
  const headers = Object.fromEntries(
    Object.entries(incoming.headers).filter(([name, value]) => value !== undefined && !hopHeaders.has(name.toLowerCase())),
  );
  headers.host = "127.0.0.1";
  const upstream = httpRequest({
    hostname: "127.0.0.1",
    port: upstreamPort,
    method: incoming.method,
    path: normalizedPath(incoming.url),
    headers,
    timeout: 30_000,
  }, (response) => {
    const responseHeaders = Object.fromEntries(
      Object.entries(response.headers).filter(([name, value]) => value !== undefined && !hopHeaders.has(name.toLowerCase())),
    );
    responseHeaders["x-coven-ingress-revision"] = revision;
    outgoing.writeHead(response.statusCode || 502, responseHeaders);
    response.pipe(outgoing);
  });
  let received = 0;
  incoming.on("data", (chunk) => {
    received += chunk.length;
    if (received > maxBodyBytes) {
      upstream.destroy();
      incoming.destroy();
      jsonError(outgoing, 413, "payload too large");
    }
  });
  upstream.on("timeout", () => upstream.destroy(new Error("upstream timeout")));
  upstream.on("error", () => jsonError(outgoing, 502, "worker unavailable"));
  incoming.pipe(upstream);
});

const port = Number.parseInt(process.env.PORT || "3000", 10);
server.listen(port, () => console.log(`covencat ingress relay ${revision} listening on :${port}`));
