"use strict";

const BrowserChecks = (() => {
  function ipv4Kind(address) {
    const parts = address.split(".");
    if (parts.length !== 4 || parts.some(part => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) return "unknown";
    const [a, b, c] = parts.map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || b === 0)) ||
        (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
        (a === 203 && b === 0 && c === 113)) return "private";
    return "public";
  }

  function normalizeAddress(input) {
    if (typeof input !== "string") return null;
    const address = input.toLowerCase();
    if (address.endsWith(".local") && /^[a-z0-9.-]+$/.test(address)) return address;
    if (!address.includes(":")) return ipv4Kind(address) === "unknown" ? null : address;
    let normalized;
    try { normalized = new URL(`http://[${address}]/`).hostname.slice(1, -1); }
    catch { return null; }
    const mapped = normalized.match(/^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/);
    if (mapped) {
      const high = parseInt(mapped[1], 16);
      const low = parseInt(mapped[2], 16);
      return [high >>> 8, high & 255, low >>> 8, low & 255].join(".");
    }
    return normalized;
  }

  function addressKind(input) {
    const normalized = normalizeAddress(input);
    if (normalized === null) return "unknown";
    if (normalized.endsWith(".local")) return "private";
    if (!normalized.includes(":")) return ipv4Kind(normalized);
    if (normalized === "::" || normalized === "::1" || /^(fc|fd|fe[89ab]|ff)/.test(normalized) || normalized.startsWith("2001:db8:")) return "private";
    return /^[23][0-9a-f]{3}:/.test(normalized) ? "public" : "unknown";
  }

  function classify(type, address, expected) {
    if (type === "relay") return "relay";
    const kind = addressKind(address);
    if (type === "host") return kind === "private" ? "privateHost" : kind === "public" ? "publicHost" : "unknown";
    if (type === "srflx" && kind === "public") return normalizeAddress(address) === normalizeAddress(expected) ? "approvedReflexive" : "otherReflexive";
    return "unknown";
  }

  function verdict(result) {
    if (result.otherReflexive > 0) return "Browser exit differs";
    if (result.publicHost > 0) return "Public host address exposed";
    if (result.complete && result.approvedReflexive > 0) return "Browser exit sample matched";
    return "Browser evidence unavailable";
  }

  return { addressKind, classify, verdict };
})();

if (typeof module !== "undefined") module.exports = BrowserChecks;

if (typeof document !== "undefined") {
  const runButton = document.getElementById("run");
  const resultLabel = document.getElementById("result");
  let strings = {};
  const text = key => strings[key] || key;

  async function configuration() {
    const response = await fetch("config", { cache: "no-store", credentials: "omit" });
    if (!response.ok) throw new Error("Session unavailable");
    return response.json();
  }

  async function collect(config) {
    const result = { privateHost: 0, publicHost: 0, approvedReflexive: 0, otherReflexive: 0,
                     relay: 0, unknown: 0, complete: false, generation: config.generation, phase: config.phase };
    let peer;
    let timeout;
    try {
      peer = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }] });
      const seen = new Set();
      const completion = new Promise(resolve => {
        timeout = setTimeout(resolve, 8000);
        peer.onicecandidate = event => {
          if (!event.candidate) { result.complete = true; resolve(); return; }
          const candidate = event.candidate;
          const key = `${candidate.type}|${candidate.address}`;
          if (seen.has(key) || seen.size >= 128) return;
          seen.add(key);
          const category = BrowserChecks.classify(candidate.type, candidate.address, config.expected);
          result[category] += 1;
        };
      });
      peer.createDataChannel("guard-check");
      await peer.setLocalDescription(await peer.createOffer());
      await completion;
    } catch {
      result.complete = false;
      result.unknown += 1;
    } finally {
      clearTimeout(timeout);
      if (peer) { peer.onicecandidate = null; peer.close(); }
    }
    return result;
  }

  runButton.addEventListener("click", async () => {
    runButton.disabled = true;
    resultLabel.textContent = text("Checking browser…");
    try {
      const config = await configuration();
      const result = await collect(config);
      const response = await fetch("result", { method: "POST", cache: "no-store", credentials: "omit",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(result) });
      if (!response.ok) throw new Error("Observation context changed");
      resultLabel.textContent = text(BrowserChecks.verdict(result));
    } catch {
      resultLabel.textContent = text("Browser evidence unavailable");
    } finally {
      runButton.disabled = false;
    }
  });

  configuration().then(config => {
    strings = config.strings;
    document.documentElement.lang = config.language;
    document.documentElement.dataset.theme = config.appearance;
    document.getElementById("title").textContent = text("Browser network check");
    document.getElementById("notice").textContent = text("Browser test notice");
    document.getElementById("scope").textContent = text("Browser test scope");
    runButton.textContent = text("Run browser check");
    runButton.disabled = false;
  }).catch(() => { resultLabel.textContent = text("Browser evidence unavailable"); });
}
