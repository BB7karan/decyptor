const GCM_TAG_BYTES = 16;

const els = {
  privateKey: document.getElementById("privateKey"),
  publicKey: document.getElementById("publicKey"),
  requestJson: document.getElementById("requestJson"),
  responseJson: document.getElementById("responseJson"),
  requestOut: document.getElementById("requestOut"),
  responseOut: document.getElementById("responseOut"),
  status: document.getElementById("status"),
  decodeRequest: document.getElementById("decodeRequest"),
  decodeResponse: document.getElementById("decodeResponse"),
  decodeBoth: document.getElementById("decodeBoth"),
  clearAll: document.getElementById("clearAll"),
};

function setStatus(message, kind = "") {
  els.status.textContent = message;
  els.status.className = `status${kind ? ` ${kind}` : ""}`;
}

function base64ToBytes(b64) {
  const normalized = b64.replace(/-/g, "+").replace(/_/g, "/");
  const pad =
    normalized.length % 4 === 0
      ? ""
      : "=".repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toBufferSource(bytes) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function stripKeyNoise(value) {
  return value
    .replace(/^\uFEFF/, "")
    .trim()
    .replace(/^["']|["']$/g, "")
    .replace(
      /^(PAYLOAD_RSA_PRIVATE_KEY|PAYLOAD_RSA_PUBLIC_KEY|PRIVATE_KEY|PUBLIC_KEY)\s*=\s*/i,
      "",
    )
    .trim()
    .replace(/^["']|["']$/g, "");
}

function normalizePem(value) {
  let trimmed = stripKeyNoise(value);
  if (!trimmed) return "";

  trimmed = trimmed.replace(/\\n/g, "\n").replace(/\r\n/g, "\n");

  if (trimmed.includes("-----BEGIN")) {
    return trimmed;
  }

  try {
    const decoded = new TextDecoder().decode(
      base64ToBytes(trimmed.replace(/\s+/g, "")),
    );
    if (decoded.includes("-----BEGIN")) {
      return decoded.replace(/\\n/g, "\n").replace(/\r\n/g, "\n");
    }
  } catch {
    // fall through
  }

  return trimmed;
}

function pemToDer(pem, labelHint) {
  const normalized = normalizePem(pem);
  const match = normalized.match(
    /-----BEGIN ([A-Z0-9 ]+?)-----\r?\n?([\s\S]+?)-----END \1-----/,
  );
  if (!match) {
    const preview = normalized.slice(0, 48).replace(/\s+/g, " ");
    throw new Error(
      `Invalid PEM${labelHint ? ` (${labelHint})` : ""}. ` +
        `Paste the .env value (base64) or a full BEGIN/END block. ` +
        `Got: "${preview}${normalized.length > 48 ? "…" : ""}"`,
    );
  }
  return {
    label: match[1].trim(),
    der: base64ToBytes(match[2].replace(/\s+/g, "")),
  };
}

function classifyPem(raw) {
  if (!raw.trim()) return null;
  const { label, der } = pemToDer(raw);
  if (label === "PRIVATE KEY" || label === "RSA PRIVATE KEY") {
    return { kind: "private", label, der, raw };
  }
  if (label === "PUBLIC KEY" || label === "RSA PUBLIC KEY") {
    return { kind: "public", label, der, raw };
  }
  throw new Error(`Unsupported PEM type: ${label}`);
}

function resolveKeyMaterial() {
  const a = els.privateKey.value.trim()
    ? classifyPem(els.privateKey.value)
    : null;
  const b = els.publicKey.value.trim()
    ? classifyPem(els.publicKey.value)
    : null;

  let privatePem = null;
  let publicPem = null;
  const notes = [];

  for (const item of [a, b]) {
    if (!item) continue;
    if (item.kind === "private") {
      if (privatePem) throw new Error("Two private keys were pasted");
      privatePem = item.raw;
    } else {
      if (publicPem) throw new Error("Two public keys were pasted");
      publicPem = item.raw;
    }
  }

  if (!privatePem) {
    throw new Error(
      "Private key is required. Paste PEM or base64 PEM (BEGIN PRIVATE KEY).",
    );
  }

  if (
    a?.kind === "public" &&
    b?.kind === "private"
  ) {
    notes.push("Detected swapped fields — using private key from the second box.");
  }

  return { privatePem, publicPem, notes };
}

function wrapPkcs1AsPkcs8(pkcs1Der) {
  const rsaOid = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  ];
  const nullParam = [0x05, 0x00];
  const algId = encodeSequence([...rsaOid, ...nullParam]);
  const version = [0x02, 0x01, 0x00];
  const octet = encodeOctetString(pkcs1Der);
  return encodeSequence([...version, ...algId, ...octet]);
}

function encodeLength(length) {
  if (length < 0x80) return [length];
  const bytes = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

function encodeSequence(content) {
  const bytes = content instanceof Uint8Array ? [...content] : content;
  return [0x30, ...encodeLength(bytes.length), ...bytes];
}

function encodeOctetString(content) {
  const bytes = content instanceof Uint8Array ? [...content] : content;
  return [0x04, ...encodeLength(bytes.length), ...bytes];
}

async function importPrivateKey(pem) {
  if (!window.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable in this browser");
  }
  const { label, der } = pemToDer(pem, "private key");
  let pkcs8 = der;
  if (label === "RSA PRIVATE KEY") {
    pkcs8 = new Uint8Array(wrapPkcs1AsPkcs8(der));
  } else if (label !== "PRIVATE KEY") {
    throw new Error(`Unsupported private key type: ${label}`);
  }

  try {
    return await window.crypto.subtle.importKey(
      "pkcs8",
      toBufferSource(pkcs8),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"],
    );
  } catch (err) {
    throw new Error(
      `Failed to import private key (${err?.message || err}). Use PKCS#8 PEM.`,
    );
  }
}

async function importPublicKey(pem) {
  if (!pem?.trim()) return null;
  const { label, der } = pemToDer(pem, "public key");
  if (label !== "PUBLIC KEY") {
    throw new Error(
      `Unsupported public key type: ${label}. Use SPKI PUBLIC KEY PEM.`,
    );
  }
  return window.crypto.subtle.importKey(
    "spki",
    toBufferSource(der),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"],
  );
}

async function assertKeyPair(privateKey, publicKey) {
  if (!publicKey) return;
  const probe = window.crypto.getRandomValues(new Uint8Array(32));
  try {
    const wrapped = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      toBufferSource(probe),
    );
    const unwrapped = new Uint8Array(
      await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        wrapped,
      ),
    );
    if (
      unwrapped.length !== probe.length ||
      unwrapped.some((b, i) => b !== probe[i])
    ) {
      throw new Error("mismatch");
    }
  } catch {
    throw new Error(
      "Public and private keys do not form a matching RSA pair. Use both keys from the same server kid.",
    );
  }
}

function parseJson(raw, label) {
  const text = raw.trim();
  if (!text) throw new Error(`${label} is empty`);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function asEnvelope(value, { requireKey = false } = {}) {
  if (!value || typeof value !== "object") {
    throw new Error("Envelope must be a JSON object");
  }
  const { enc, key, kid, iv, data, tag } = value;
  if (enc != null && String(enc) !== "1") {
    throw new Error('Envelope enc must be "1"');
  }
  if (
    typeof iv !== "string" ||
    typeof data !== "string" ||
    typeof tag !== "string"
  ) {
    throw new Error("Envelope needs string iv, data, and tag");
  }
  if (requireKey && typeof key !== "string") {
    throw new Error("Envelope needs string key (RSA-wrapped AES key)");
  }
  return {
    enc: "1",
    kid: typeof kid === "string" ? kid : undefined,
    key: typeof key === "string" ? key : undefined,
    iv,
    data,
    tag,
  };
}

function explainCryptoError(err, kid) {
  const name = err?.name || "";
  const message = err?.message || String(err);
  if (name === "OperationError" || /oaep|decrypt/i.test(message)) {
    return (
      `RSA unwrap failed${kid ? ` for kid "${kid}"` : ""}. ` +
      "This private key does not match the server public key that wrapped the payload. " +
      "Use PAYLOAD_RSA_PRIVATE_KEY from that same server/environment."
    );
  }
  return message;
}

async function unwrapAesKey(privateKey, wrappedKeyB64, kid) {
  const wrapped = base64ToBytes(wrappedKeyB64);
  try {
    const raw = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      toBufferSource(wrapped),
    );
    if (raw.byteLength !== 32) {
      throw new Error(`Unexpected AES key length: ${raw.byteLength}`);
    }
    return window.crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
  } catch (err) {
    throw new Error(explainCryptoError(err, kid));
  }
}

async function decryptEnvelope(aesKey, envelope) {
  const iv = base64ToBytes(envelope.iv);
  const data = base64ToBytes(envelope.data);
  const tag = base64ToBytes(envelope.tag);
  if (tag.byteLength !== GCM_TAG_BYTES) {
    throw new Error(`Auth tag must be ${GCM_TAG_BYTES} bytes`);
  }
  const combined = new Uint8Array(data.length + tag.length);
  combined.set(data, 0);
  combined.set(tag, data.length);

  try {
    const plaintext = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toBufferSource(iv) },
      aesKey,
      toBufferSource(combined),
    );
    const text = new TextDecoder().decode(plaintext);
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  } catch (err) {
    throw new Error(
      `AES-GCM decrypt failed (${err?.message || err}). iv/data/tag may not belong to this key.`,
    );
  }
}

function pretty(value) {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function loadKeys() {
  const { privatePem, publicPem, notes } = resolveKeyMaterial();
  const privateKey = await importPrivateKey(privatePem);
  const publicKey = publicPem ? await importPublicKey(publicPem) : null;
  await assertKeyPair(privateKey, publicKey);
  return { privateKey, notes };
}

async function decodeRequest() {
  const { privateKey, notes } = await loadKeys();
  const envelope = asEnvelope(parseJson(els.requestJson.value, "Request JSON"), {
    requireKey: true,
  });
  const aesKey = await unwrapAesKey(privateKey, envelope.key, envelope.kid);
  const plaintext = await decryptEnvelope(aesKey, envelope);
  els.requestOut.textContent = pretty(plaintext);
  return { plaintext, notes, kid: envelope.kid };
}

async function decodeResponse() {
  const { privateKey, notes } = await loadKeys();

  let wrappedKey;
  let kid;
  const requestRaw = els.requestJson.value.trim();
  if (requestRaw) {
    const requestEnv = asEnvelope(parseJson(requestRaw, "Request JSON"));
    wrappedKey = requestEnv.key;
    kid = requestEnv.kid;
  }
  const responseEnv = asEnvelope(
    parseJson(els.responseJson.value, "Response JSON"),
  );
  if (!wrappedKey && responseEnv.key) {
    wrappedKey = responseEnv.key;
    kid = responseEnv.kid || kid;
  }
  if (!wrappedKey) {
    throw new Error(
      "Response decode needs the request envelope (or a response that includes key)",
    );
  }

  const aesKey = await unwrapAesKey(privateKey, wrappedKey, kid);
  const plaintext = await decryptEnvelope(aesKey, responseEnv);
  els.responseOut.textContent = pretty(plaintext);
  return { plaintext, notes, kid };
}

async function run(action) {
  setStatus("Decrypting…");
  try {
    let notes = [];
    let kid;
    if (action === "request") {
      ({ notes, kid } = await decodeRequest());
      setStatus(
        `Request decoded${kid ? ` (kid ${kid})` : ""}.${notes[0] ? ` ${notes[0]}` : ""}`,
        "ok",
      );
    } else if (action === "response") {
      ({ notes, kid } = await decodeResponse());
      setStatus(
        `Response decoded${kid ? ` (kid ${kid})` : ""}.${notes[0] ? ` ${notes[0]}` : ""}`,
        "ok",
      );
    } else {
      const req = await decodeRequest();
      const res = await decodeResponse();
      notes = req.notes;
      kid = req.kid || res.kid;
      setStatus(
        `Request and response decoded${kid ? ` (kid ${kid})` : ""}.${notes[0] ? ` ${notes[0]}` : ""}`,
        "ok",
      );
    }
  } catch (err) {
    console.error(err);
    setStatus(err?.message || String(err), "error");
  }
}

els.decodeRequest.addEventListener("click", () => run("request"));
els.decodeResponse.addEventListener("click", () => run("response"));
els.decodeBoth.addEventListener("click", () => run("both"));

els.clearAll.addEventListener("click", () => {
  for (const key of [
    "privateKey",
    "publicKey",
    "requestJson",
    "responseJson",
  ]) {
    els[key].value = "";
  }
  els.requestOut.textContent = "—";
  els.responseOut.textContent = "—";
  setStatus("Cleared.");
});

document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const id = btn.getAttribute("data-copy");
    const text = document.getElementById(id)?.textContent || "";
    try {
      await navigator.clipboard.writeText(text);
      setStatus(`Copied ${id}.`, "ok");
    } catch {
      setStatus("Clipboard copy failed.", "error");
    }
  });
});
