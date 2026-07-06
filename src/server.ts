import {createServer, type IncomingHttpHeaders} from "node:http";
import {pathToFileURL} from "node:url";

import {createConfig, handleRequest, type AdapterConfig} from "./adapter.js";

function headersToMap(headers: IncomingHttpHeaders): Map<string, string> {
  const map = new Map<string, string>();
  for (const [name, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      map.set(name.toLowerCase(), value.join(", "));
    } else if (value !== undefined) {
      map.set(name.toLowerCase(), value);
    }
  }
  return map;
}

async function readBody(req: NodeJS.ReadableStream, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > limit) {
      return Buffer.concat([...chunks, buffer], total);
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, total);
}

export function createWebhookServer(config: AdapterConfig = createConfig()) {
  return createServer(async (req, res) => {
    const rawBody = await readBody(req, config.maxWebhookBodyBytes + 1);
    const response = await handleRequest(config, {
      method: req.method || "GET",
      path: req.url?.split("?")[0] || "/",
      headers: headersToMap(req.headers),
      rawBody,
    });
    const body = Buffer.from(JSON.stringify(response.body));
    res.statusCode = response.status;
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Length", String(body.length));
    res.end(body);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number.parseInt(process.env.PORT || "3000", 10);
  const server = createWebhookServer();
  server.listen(port, () => {
    console.log(`coven-github webhook listening on :${port}`);
  });
}
