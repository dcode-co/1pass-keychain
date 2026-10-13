#!/usr/bin/env node
// Runs the kc binary from the platform package npm (or bun, pnpm, yarn)
// installed as an optional dependency.
"use strict";

const { spawn } = require("node:child_process");

const PACKAGES = {
  "darwin-arm64": "1pass-keychain-darwin-arm64",
  "darwin-x64": "1pass-keychain-darwin-x64",
  "linux-arm64": "1pass-keychain-linux-arm64",
  "linux-x64": "1pass-keychain-linux-x64",
  "win32-x64": "@1pass/keychain-win32-x64",
};
const INSTALL = "https://github.com/dcode-co/1pass-keychain#install";

const platform = `${process.platform}-${process.arch}`;
const pkg = PACKAGES[platform];
if (!pkg) {
  console.error(`kc: there is no prebuilt binary for ${platform}; see ${INSTALL}`);
  process.exit(1);
}

let bin;
try {
  bin = require.resolve(`${pkg}/bin/kc${process.platform === "win32" ? ".exe" : ""}`);
} catch {
  console.error(
    `kc: ${pkg} is missing. Reinstall 1pass-keychain with optional dependencies enabled; see ${INSTALL}`,
  );
  process.exit(1);
}

const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
// Ctrl-C reaches kc directly from the terminal; stay alive until kc exits.
process.on("SIGINT", () => {});
// A signal sent to this launcher alone (a supervisor, `kill`) is passed on.
for (const signal of ["SIGTERM", "SIGHUP"]) {
  process.on(signal, () => child.kill(signal));
}
child.on("error", (error) => {
  console.error(`kc: ${error.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => {
  if (signal) {
    process.removeAllListeners(signal);
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
