"use strict";

// Engineering-only actual Chromium probe. Uses a new profile and the debugging
// pipe, which remains usable while loopback/network traffic is sealed. Never
// reads the user's browser profile, accounts or cookies. Candidate addresses,
// URLs, response bodies and browser diagnostics are not included in results.
const fs = require("node:fs/promises");
const path = require("node:path");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");

async function main() {
  let input = "";
  for await (const part of process.stdin) {
    input += part;
    if (input.length > 4096) throw new Error("input-size");
  }
  const config = JSON.parse(input);
  if (!/^(OPEN|LOCKED)$/.test(config.phase) || typeof config.expected !== "string" ||
      !/^[0-9.]{7,15}$/.test(config.expected) || !path.isAbsolute(config.scratch)) {
    throw new Error("input-format");
  }
  const directory = await fs.mkdtemp(path.join(config.scratch, "browser-engine-"));
  await fs.chmod(directory, 0o700);
  const child = spawn("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", [
    "--headless=new", "--remote-debugging-pipe", "--user-data-dir=" + directory,
    "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
    "--disable-component-update", "--disable-sync", "--disable-extensions",
    "--disable-features=MediaRouter", "--password-store=basic", "--use-mock-keychain",
    "about:blank",
  ], { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
  const pending = new Map();
  const listeners = new Set();
  let buffer = "", next = 0;
  let exited = false;
  child.once("exit", () => {
    exited = true;
    for (const request of pending.values()) request.reject(new Error("browser-exited"));
    pending.clear();
  });
  child.stdio[4].on("data", data => {
    buffer += data.toString("utf8");
    if (buffer.length > 8 * 1024 * 1024) { child.kill(); return; }
    let boundary;
    while ((boundary = buffer.indexOf("\0")) >= 0) {
      const raw = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 1);
      let message;
      try { message = JSON.parse(raw); } catch { continue; }
      const request = pending.get(message.id);
      if (request) {
        clearTimeout(request.timer);
        pending.delete(message.id);
        if (message.error) request.reject(new Error("protocol-error"));
        else request.resolve(message.result);
      } else if (message.method) {
        for (const listener of listeners) listener(message);
      }
    }
  });
  function send(method, params = {}, sessionId, timeout = 15000) {
    if (exited) return Promise.reject(new Error("browser-exited"));
    const id = ++next;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error("protocol-timeout")); }, timeout);
      pending.set(id, { resolve, reject, timer });
      child.stdio[3].write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + "\0");
    });
  }
  const report = { phase: config.phase, scope: "Actual Chromium engine, fresh isolated profile, anonymous uncached main-document request and new WebRTC connection" };
  try {
    const version = await send("Browser.getVersion");
    report.browser = version.product;
    const { targetId } = await send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    await send("Page.enable", {}, sessionId);
    await send("Network.enable", {}, sessionId);
    await send("Network.setCacheDisabled", { cacheDisabled: true }, sessionId);
    await send("Network.setBypassServiceWorker", { bypass: true }, sessionId);
    await send("Network.setExtraHTTPHeaders", { headers: { "Cache-Control": "no-cache", "Pragma": "no-cache" } }, sessionId);
    // Run the product's exact classifier and collector, with the page UI and
    // loopback submission excluded. No candidate values leave this expression.
    const source = await fs.readFile(path.join(__dirname, "../Resources/BrowserDiagnostics/webrtc.js"), "utf8");
    const classifier = source.slice(source.indexOf("const BrowserChecks ="), source.indexOf('if (typeof module'));
    const collector = source.slice(source.indexOf("  async function collect(config)"), source.indexOf("  runButton.addEventListener"));
    if (!classifier || !collector) throw new Error("collector-source");
    const expression = "(async () => {" + classifier + collector + "return await collect(" +
      JSON.stringify({ expected: config.expected, phase: config.phase, generation: crypto.randomUUID() }) + ");})()";
    const ice = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId, 12000);
    if (ice.exceptionDetails || !ice.result?.value) throw new Error("browser-ice-execution");
    const observation = ice.result.value;
    report.ice = Object.fromEntries(["privateHost", "publicHost", "approvedReflexive", "otherReflexive", "relay", "unknown", "complete"].map(key => [key, observation[key]]));
    const url = "https://claude.ai/?_=" + crypto.randomBytes(12).toString("hex");
    const requestIds = new Set();
    let main = null;
    const listener = message => {
      if (message.sessionId !== sessionId) return;
      const data = message.params;
      if (message.method === "Network.requestWillBeSent" && data.type === "Document" && data.request.url === url) {
        requestIds.add(data.requestId);
      }
      if (message.method === "Network.responseReceived" && requestIds.has(data.requestId)) {
        main = { httpResponse: true, status: data.response.status, fromCache: !!data.response.fromDiskCache,
                 fromServiceWorker: !!data.response.fromServiceWorker };
      }
      if (message.method === "Network.loadingFailed" && requestIds.has(data.requestId)) {
        main = { httpResponse: false, error: /^net::ERR_[A-Z_]+$/.test(data.errorText) ? data.errorText : "network-failed" };
      }
    };
    listeners.add(listener);
    const began = performance.now();
    await send("Page.navigate", { url }, sessionId, 12000).catch(() => {});
    while (!main && performance.now() - began < 12000) await new Promise(resolve => setTimeout(resolve, 50));
    listeners.delete(listener);
    await send("Page.stopLoading", {}, sessionId).catch(() => {});
    report.document = main || { httpResponse: false, error: "bounded-request-timeout" };
    report.document.requestObserved = requestIds.size > 0;
    report.document.seconds = Math.round((performance.now() - began) / 10) / 100;
    report.completed = true;
  } finally {
    await send("Browser.close", {}, undefined, 2000).catch(() => {});
    if (!exited) child.kill("SIGTERM");
    await Promise.race([new Promise(resolve => child.once("exit", resolve)), new Promise(resolve => setTimeout(resolve, 2000))]);
    if (!exited) child.kill("SIGKILL");
    for (const request of pending.values()) clearTimeout(request.timer);
    await fs.rm(directory, { recursive: true, force: true });
  }
  process.stdout.write(JSON.stringify(report) + "\n");
}

main().catch(() => { process.stdout.write(JSON.stringify({ completed: false, failure: "browser-engine-control-failed" }) + "\n"); process.exitCode = 1; });
