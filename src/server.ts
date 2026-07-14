import {createServer, type IncomingHttpHeaders} from "node:http";
import {pathToFileURL} from "node:url";
import {fork} from "node:child_process";

import {createConfig, handleRequest, redactTokenish, runnableTaskIds, taskSchedulingClass, type AdapterConfig} from "./adapter.js";

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

export type TaskScheduler = (taskId: string) => void;

export interface TaskWorkerSchedulerOptions {
  workerUrl?: URL;
  retryBaseMs?: number;
  retryMaxMs?: number;
}

export function createWorkerTaskScheduler(config: AdapterConfig, options: TaskWorkerSchedulerOptions = {}): TaskScheduler {
  type LaneName = "maintenance" | "compute";
  const lanes: Record<LaneName, {pending: Set<string>; active: boolean}> = {
    maintenance: {pending: new Set<string>(), active: false},
    compute: {pending: new Set<string>(), active: false},
  };
  const crashRetries = new Map<string, number>();
  const retryTimers = new Map<string, NodeJS.Timeout>();
  const workerUrl = options.workerUrl || new URL(import.meta.url.endsWith(".ts") ? "./task-worker.ts" : "./task-worker.js", import.meta.url);
  const retryBaseMs = Math.max(1, options.retryBaseMs || 5_000);
  const retryMaxMs = Math.max(retryBaseMs, options.retryMaxMs || 60 * 60 * 1000);

  const enqueue = (taskId: string): void => {
    const laneName = taskSchedulingClass(config, taskId);
    lanes[laneName].pending.add(taskId);
    void drain(laneName);
  };

  const drain = async (laneName: LaneName): Promise<void> => {
    const lane = lanes[laneName];
    if (lane.active) return;
    lane.active = true;
    try {
      while (lane.pending.size) {
        const taskId = lane.pending.values().next().value as string;
        lane.pending.delete(taskId);
        try {
          await new Promise<void>((resolveWorker) => {
            const worker = fork(workerUrl, [], {stdio: ["ignore", "inherit", "inherit", "ipc"]});
            let settled = false;
            let retryableAttempt = 0;
            let retryNotBefore = "";
            let retryCategory = "";
            let followupTaskId = "";
            worker.on("message", (message) => {
              const result = (message && typeof message === "object" ? message : {}) as Record<string, unknown>;
              if (result.followup_task_id) followupTaskId = String(result.followup_task_id);
              if (result.publication_state === "revision_reconciliation_retry_pending" || result.publication_state === "publication_failed") {
                retryableAttempt = Number(result.publication_attempts || result.attempts || 1);
                retryNotBefore = String(result.retry_not_before || "");
                retryCategory = String(result.failure_category || result.publication_state || "retryable_failure");
              }
            });
            const finish = (code: number | null, detail = "") => {
              if (settled) return;
              settled = true;
              if (code !== 0) {
                console.error(`coven-github task worker exited task_id=${taskId} code=${code ?? "spawn-error"}${detail ? ` ${detail}` : ""}`);
                const retries = (crashRetries.get(taskId) || 0) + 1;
                crashRetries.set(taskId, retries);
                if (!retryTimers.has(taskId)) {
                  const delay = Math.min(retryMaxMs, retryBaseMs * (2 ** Math.min(10, Math.max(0, retries - 1))));
                  console.error(`coven-github crashed task retry scheduled task_id=${taskId} retry_at=${new Date(Date.now() + delay).toISOString()}`);
                  const timer = setTimeout(() => {
                    retryTimers.delete(taskId);
                    enqueue(taskId);
                  }, delay);
                  timer.unref();
                  retryTimers.set(taskId, timer);
                }
              } else {
                crashRetries.delete(taskId);
                if (followupTaskId) enqueue(followupTaskId);
                if (retryableAttempt > 0 && !retryTimers.has(taskId)) {
                  const persistedDelay = Date.parse(retryNotBefore) - Date.now();
                  const delay = Number.isFinite(persistedDelay) && persistedDelay > 0
                    ? persistedDelay
                    : Math.min(retryMaxMs, retryBaseMs * (2 ** Math.min(10, Math.max(0, retryableAttempt - 1))));
                  console.error(`coven-github task retry scheduled task_id=${taskId} category=${retryCategory} retry_at=${new Date(Date.now() + delay).toISOString()}`);
                  const timer = setTimeout(() => {
                    retryTimers.delete(taskId);
                    enqueue(taskId);
                  }, delay);
                  timer.unref();
                  retryTimers.set(taskId, timer);
                }
              }
              resolveWorker();
            };
            worker.once("error", (error) => {
              finish(null, redactTokenish(String(error.stack || error)));
            });
            worker.once("exit", (code) => {
              finish(code);
            });
            worker.send({config, taskId}, (error) => {
              if (error) {
                worker.kill("SIGKILL");
                finish(null, `IPC failed: ${redactTokenish(String(error.stack || error))}`);
              }
            });
          });
        } catch (error) {
          console.error(`coven-github task worker could not start task_id=${taskId}: ${redactTokenish(String((error as Error).stack || error))}`);
        }
      }
    } finally {
      lane.active = false;
      if (lane.pending.size) void drain(laneName);
    }
  };
  return (taskId: string) => {
    const retryTimer = retryTimers.get(taskId);
    if (retryTimer) {
      clearTimeout(retryTimer);
      retryTimers.delete(taskId);
    }
    enqueue(taskId);
  };
}

export function createWebhookServer(config: AdapterConfig = createConfig(), scheduleTask: TaskScheduler = createWorkerTaskScheduler(config)) {
  const server = createServer(async (req, res) => {
    try {
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
      if (response.body.queued === true && response.body.task_id) scheduleTask(String(response.body.task_id));
    } catch (error) {
      console.error(`coven-github webhook request failed: ${redactTokenish(String((error as Error).stack || error))}`);
      if (res.writableEnded || res.destroyed) return;
      const body = Buffer.from(JSON.stringify({ok: false, error: "internal server error"}));
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Length", String(body.length));
      res.end(body);
    }
  });
  server.once("listening", () => {
    for (const taskId of runnableTaskIds(config)) scheduleTask(taskId);
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number.parseInt(process.env.PORT || "3000", 10);
  const server = createWebhookServer();
  server.listen(port, () => {
    console.log(`coven-github webhook listening on :${port}`);
  });
}
