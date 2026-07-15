import {redactTokenish, runTask, type AdapterConfig} from "./adapter.js";

interface TaskWorkerData {
  config: AdapterConfig;
  taskId: string;
}

if (!process.send) throw new Error("coven-github task-worker requires a parent IPC channel");

process.once("message", (message) => {
  void (async () => {
    const {config, taskId} = message as TaskWorkerData;
    try {
      const task = await runTask(config, taskId);
      await new Promise<void>((resolveSend) => process.send?.({
          ok: true,
          task_id: taskId,
          state: task.state,
        publication_state: task.publication_state,
        attempts: task.attempts,
        publication_attempts: task.publication_attempts,
        retry_not_before: task.retry_not_before,
        failure_category: task.failure_category,
        followup_task_id: task.followup_task_id,
        }, () => resolveSend()) || resolveSend());
    } catch (error) {
      const detail = redactTokenish(String((error as Error).stack || error));
      await new Promise<void>((resolveSend) => process.send?.({ok: false, task_id: taskId, error: detail}, () => resolveSend()) || resolveSend());
      process.exitCode = 1;
    } finally {
      if (process.connected) process.disconnect();
    }
  })();
});
