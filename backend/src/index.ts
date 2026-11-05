import { app } from "./app";
import { env } from "./config/env";
import { closePool } from "./db/client";

const server = app.listen(env.port, () => {
  console.log(`==> [@dsh/backend] Express server listening on http://localhost:${env.port}`);
  console.log(`==> [@dsh/backend] Health endpoints: /api/v1/health & /api/v1/health/db`);
});

async function shutdown(signal: string): Promise<void> {
  console.log(`\n==> [@dsh/backend] Received ${signal}. Shutting down gracefully...`);
  server.close(async () => {
    await closePool();
    console.log("==> [@dsh/backend] HTTP server and PostgreSQL pool closed.");
    process.exit(0);
  });
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
