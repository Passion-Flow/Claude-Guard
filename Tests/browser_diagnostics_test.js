"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = path.join(__dirname, "../Resources/BrowserDiagnostics/webrtc.js");
const checks = require(source);

assert.equal(checks.classify("host", "10.0.0.1", "8.8.8.8"), "privateHost");
assert.equal(checks.classify("host", "example.local", "8.8.8.8"), "privateHost");
assert.equal(checks.classify("host", "8.8.4.4", "8.8.8.8"), "publicHost");
assert.equal(checks.classify("host", "fd00::1", "8.8.8.8"), "privateHost");
assert.equal(checks.classify("host", "fe80::1", "8.8.8.8"), "privateHost");
assert.equal(checks.classify("host", "2606:4700:4700::1111", "8.8.8.8"), "publicHost");
assert.equal(checks.classify("srflx", "::ffff:8.8.8.8", "8.8.8.8"), "approvedReflexive");
assert.equal(checks.classify("srflx", "8.8.4.4", "8.8.8.8"), "otherReflexive");
assert.equal(checks.classify("relay", "8.8.4.4", "8.8.8.8"), "relay");
assert.equal(checks.classify("srflx", "10.0.0.1", "8.8.8.8"), "unknown");
assert.equal(checks.classify("host", "8.8.8.999", "8.8.8.8"), "unknown");
assert.equal(checks.classify("host", "8.8.08.8", "8.8.8.8"), "unknown");
assert.equal(checks.verdict({ complete: true, relay: 1 }), "Browser evidence unavailable");
assert.equal(checks.verdict({ complete: false, approvedReflexive: 1 }), "Browser evidence unavailable");
assert.equal(checks.verdict({ complete: true, approvedReflexive: 1, otherReflexive: 1 }), "Browser exit differs");

async function exercisePage() {
  const elements = new Map();
  const posts = [];
  const peers = [];
  let phase = "OPEN";
  const element = id => {
    if (!elements.has(id)) elements.set(id, { textContent: "", disabled: true,
      addEventListener: (_, callback) => { elements.get(id).click = callback; } });
    return elements.get(id);
  };
  class Peer {
    constructor(config) {
      assert.deepEqual(JSON.parse(JSON.stringify(config)), { iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }] });
      this.closed = false;
      peers.push(this);
    }
    createDataChannel() {}
    async createOffer() { return {}; }
    async setLocalDescription() {
      this.onicecandidate({ candidate: { type: "host", address: "10.0.0.1" } });
      if (phase === "OPEN") this.onicecandidate({ candidate: { type: "srflx", address: "8.8.8.8" } });
      this.onicecandidate({ candidate: null });
    }
    close() { this.closed = true; }
  }
  const sandbox = {
    URL, setTimeout, clearTimeout, RTCPeerConnection: Peer,
    document: { getElementById: element, documentElement: { dataset: {} } },
    fetch: async (url, options) => {
      assert.equal(options.cache, "no-store");
      assert.equal(options.credentials, "omit");
      if (url === "config") return { ok: true, json: async () => ({ expected: "8.8.8.8",
        generation: "fixture", phase, strings: {}, language: "en", appearance: "dark" }) };
      assert.equal(url, "result");
      assert.equal(options.method, "POST");
      assert.equal(options.headers["Content-Type"], "application/json");
      assert.ok(!options.body.includes("8.8.8.8") && !options.body.includes("10.0.0.1"));
      posts.push(JSON.parse(options.body));
      return { ok: true };
    },
  };
  vm.runInNewContext(fs.readFileSync(source, "utf8"), sandbox);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(peers.length, 0, "Loading the page must not contact STUN");
  await element("run").click();
  assert.equal(posts[0].approvedReflexive, 1);
  assert.equal(element("result").textContent, "Browser exit sample matched");
  phase = "LOCKED";
  await element("run").click();
  assert.equal(peers.length, 2);
  assert.ok(peers.every(peer => peer.closed));
  assert.equal(posts[1].approvedReflexive, 0, "An old candidate must not survive a new phase");
  assert.equal(element("result").textContent, "Browser evidence unavailable");
  delete sandbox.RTCPeerConnection;
  await element("run").click();
  assert.equal(posts[2].complete, false);
  assert.equal(posts[2].unknown, 1);
  assert.equal(element("result").textContent, "Browser evidence unavailable");
}

exercisePage().then(() => console.log("PASS: browser candidate privacy, fresh connection lifecycle and unavailable evidence"))
  .catch(error => { console.error(error); process.exitCode = 1; });
