// Runs inside the Playwright image when the stand's server is unreachable from it:
// starts another server on the same databases on the container's loopback, then
// walks the dashboard. Paths are mounted at the same locations as on the host.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";

const [credentialsPath, output] = process.argv.slice(2);
const hold = JSON.parse(readFileSync(credentialsPath, "utf8"));
const server = spawn(hold.server, ["serve"], {
  env: { ...process.env, ...Object.fromEntries(hold.env.map((line) => line.split(/=(.*)/s).slice(0, 2))) },
  stdio: "inherit",
});

const deadline = Date.now() + 30_000;
for (;;) {
  try {
    if ((await fetch(`${hold.api}/readyz`)).ok) break;
  } catch {
    // Not listening yet.
  }
  if (Date.now() > deadline) {
    server.kill();
    throw new Error("server did not start");
  }
  await new Promise((resolve) => setTimeout(resolve, 200));
}

const walk = spawn("node", ["e2e/smoke.mjs", credentialsPath, output], { stdio: "inherit" });
const code = await new Promise((resolve) => walk.on("exit", resolve));
server.kill();
process.exit(code ?? 1);
