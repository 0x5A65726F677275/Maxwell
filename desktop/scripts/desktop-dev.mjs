import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";

const targetDir = path.join(
  process.env.LOCALAPPDATA || process.env.HOME || process.cwd(),
  "Maxwell",
  "cargo-target",
);
mkdirSync(targetDir, { recursive: true });
process.env.CARGO_TARGET_DIR = targetDir;

const child = spawn("tauri", ["dev", ...process.argv.slice(2)], {
  stdio: "inherit",
  shell: true,
  env: process.env,
});

child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
