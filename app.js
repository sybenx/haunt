/* ============================================================
   haunt — talks to one bothy relay, in one group, with chat only.
   No voice, no channels, no DMs, no QR login, no invites, no
   profile editing, no group switching. Those are designed
   (see the mocks in the repo root) and they come later.
   ============================================================ */

const GROUP_ID = "_";
const SUB_ID = "haunt";

const S = window.NobleSecp256k1;

/* ---------- elements ---------- */
const statusLine = document.getElementById("statusLine");
const groupLabel = document.getElementById("groupLabel");
const relaySetup = document.getElementById("relaySetup");
const relayInput = document.getElementById("relayInput");
const relayConnect = document.getElementById("relayConnect");
const scrollEl = document.getElementById("scroll");
const msgsEl = document.getElementById("msgs");
const field = document.getElementById("field");
const msgInput = document.getElementById("msgInput");
const sendBtn = document.getElementById("sendBtn");

groupLabel.textContent = GROUP_ID;

/* ============================================================
   identity

   The keypair is minted once and kept in localStorage. That's a
   placeholder: it means the key never leaves this browser profile,
   can be wiped by clearing site data, and can't be carried to a
   second device. The mocks already design what replaces it — the
   "show my code" / "scan a code" QR pairing in client-mobile.html,
   which moves a key between devices instead of minting a new one
   per browser. This build doesn't touch that; it just leaves the
   key sitting in the one place a static page without a signing
   extension has to put it.
   ============================================================ */
function loadOrCreateIdentity() {
  const stored = localStorage.getItem("haunt:privkey");
  if (stored) {
    const privkey = S.utils.hexToBytes(stored);
    const pubkey = S.utils.bytesToHex(S.schnorr.getPublicKey(privkey));
    return { privkey, pubkey };
  }
  const privkey = S.utils.randomPrivateKey();
  localStorage.setItem("haunt:privkey", S.utils.bytesToHex(privkey));
  const pubkey = S.utils.bytesToHex(S.schnorr.getPublicKey(privkey));
  return { privkey, pubkey };
}

const identity = loadOrCreateIdentity();

/* ============================================================
   nostr event helpers (NIP-01)
   ============================================================ */
function serializeEvent(ev) {
  return JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
}

async function finalizeEvent(partial) {
  const ev = {
    pubkey: identity.pubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content: "",
    ...partial,
  };
  const idBytes = await S.utils.sha256(new TextEncoder().encode(serializeEvent(ev)));
  ev.id = S.utils.bytesToHex(idBytes);
  const sigBytes = await S.schnorr.sign(idBytes, identity.privkey);
  ev.sig = S.utils.bytesToHex(sigBytes);
  return ev;
}

function shortName(pubkey) {
  return pubkey.slice(0, 8);
}

function colorFor(pubkey) {
  const hue = parseInt(pubkey.slice(0, 6), 16) % 360;
  return `hsl(${hue}, 42%, 46%)`;
}

/* ============================================================
   relay address

   Priority: ?relay=<host> in the URL, then the page's own origin
   when it was served by the relay itself, then the manual box.
   The manual box is the fallback path, not the front door.
   ============================================================ */
function relayUrlFromHost(host) {
  if (host.includes("://")) return host;
  return "wss://" + host;
}

function resolveRelayUrl() {
  const params = new URLSearchParams(location.search);
  const fromParam = params.get("relay");
  if (fromParam) return relayUrlFromHost(fromParam);

  if (location.protocol === "http:" || location.protocol === "https:") {
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    return scheme + "//" + location.host;
  }

  return null; // opened from disk with nothing to go on — fall back to the manual box
}

/* ============================================================
   connection state
   ============================================================ */
let ws = null;
let authState = "none"; // none | pending | authed | failed
let needsResubscribe = false;
const outbox = new Map(); // event id -> { el, event }
let reconnectDelay = 2000;
let reconnectTimer = null;

function setStatus(text, kind) {
  statusLine.textContent = text;
  statusLine.className = "tSub" + (kind ? " " + kind : "");
}

function setComposerEnabled(enabled) {
  sendBtn.disabled = !enabled || msgInput.value.trim() === "";
}

function connect(relayUrl) {
  setStatus("connecting to " + relayUrl + "…");
  authState = "none";
  needsResubscribe = false;

  ws = new WebSocket(relayUrl);

  ws.addEventListener("open", () => {
    reconnectDelay = 2000;
    setStatus("connected — joining #" + GROUP_ID + "…");
    subscribe();
    setComposerEnabled(true);
  });

  ws.addEventListener("message", (evt) => {
    let frame;
    try {
      frame = JSON.parse(evt.data);
    } catch (e) {
      console.error("haunt: unparseable relay frame", evt.data);
      return;
    }
    handleFrame(frame, relayUrl);
  });

  ws.addEventListener("close", () => {
    setComposerEnabled(false);
    setStatus("disconnected — retrying…", "warn");
    reconnectTimer = setTimeout(() => connect(relayUrl), reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 1.5, 15000);
  });

  ws.addEventListener("error", () => {
    // the close handler fires right after and drives the visible retry state
    console.error("haunt: websocket error");
  });
}

function subscribe() {
  ws.send(JSON.stringify(["REQ", SUB_ID, { kinds: [9], "#h": [GROUP_ID], limit: 50 }]));
}

async function handleFrame(frame, relayUrl) {
  const type = frame[0];

  if (type === "EVENT" && frame[1] === SUB_ID) {
    renderIncoming(frame[2]);
    return;
  }

  if (type === "EOSE" && frame[1] === SUB_ID) {
    if (authState === "authed" || authState === "none") {
      setStatus("connected", "lit");
    }
    return;
  }

  if (type === "CLOSED" && frame[1] === SUB_ID) {
    const reason = frame[2] || "";
    if (reason.startsWith("auth-required")) {
      needsResubscribe = true;
      setStatus("relay wants authentication…");
    } else {
      setStatus("relay closed the room: " + reason, "warn");
    }
    return;
  }

  if (type === "AUTH") {
    const challenge = frame[1];
    authState = "pending";
    setStatus("authenticating with relay…");
    const authEvent = await finalizeEvent({
      kind: 22242,
      tags: [["relay", relayUrl], ["challenge", challenge]],
    });
    outbox.set(authEvent.id, { kind: "auth" });
    ws.send(JSON.stringify(["AUTH", authEvent]));
    return;
  }

  if (type === "OK") {
    const [, eventId, ok, message] = frame;
    const entry = outbox.get(eventId);
    if (!entry) return;

    if (entry.kind === "auth") {
      outbox.delete(eventId);
      if (ok) {
        authState = "authed";
        setStatus("connected", "lit");
        if (needsResubscribe) {
          needsResubscribe = false;
          subscribe();
        }
        for (const [id, e] of outbox) {
          if (e.kind === "message" && e.lastReason && e.lastReason.startsWith("auth-required")) {
            ws.send(JSON.stringify(["EVENT", e.event]));
          }
        }
      } else {
        authState = "failed";
        setStatus("relay refused authentication: " + message, "warn");
      }
      return;
    }

    if (entry.kind === "message") {
      if (ok) {
        markSent(entry.el);
        outbox.delete(eventId);
      } else if (message && message.startsWith("auth-required") && authState !== "failed") {
        entry.lastReason = message;
        // left in the outbox; resent once the pending AUTH above completes
      } else {
        markFailed(entry.el, message || "refused");
        outbox.delete(eventId);
      }
    }
  }
}

/* ============================================================
   rendering
   ============================================================ */
const seenIds = new Set();

function messageRow(pubkey, text, time, mine) {
  const row = document.createElement("div");
  row.className = "m" + (mine ? " mine" : "");

  const av = document.createElement("div");
  av.className = "av";
  av.style.background = colorFor(pubkey);
  av.textContent = shortName(pubkey).slice(0, 2);

  const body = document.createElement("div");
  body.className = "mBody";

  const head = document.createElement("div");
  head.className = "mHead";
  const name = document.createElement("span");
  name.className = "mName";
  name.textContent = shortName(pubkey);
  const tm = document.createElement("span");
  tm.className = "mTime";
  tm.textContent = time;
  head.append(name, tm);

  const textEl = document.createElement("div");
  textEl.className = "mText";
  textEl.textContent = text;

  body.append(head, textEl);
  row.append(av, body);
  return row;
}

function formatTime(unixSeconds) {
  const d = new Date(unixSeconds * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function isAtBottom() {
  return scrollEl.scrollHeight - scrollEl.scrollTop - scrollEl.clientHeight < 80;
}

function appendRow(row) {
  const stick = isAtBottom();
  msgsEl.appendChild(row);
  if (stick) scrollEl.scrollTop = scrollEl.scrollHeight;
}

function renderIncoming(event) {
  if (seenIds.has(event.id)) return;
  seenIds.add(event.id);
  if (outbox.has(event.id)) return; // our own message, already rendered optimistically
  const row = messageRow(event.pubkey, event.content, formatTime(event.created_at), event.pubkey === identity.pubkey);
  appendRow(row);
}

function markSent(el) {
  el.classList.remove("pending");
}

function markFailed(el, reason) {
  el.classList.remove("pending");
  el.classList.add("failed");
  const note = document.createElement("div");
  note.className = "mFail";
  note.textContent = "not sent — " + reason;
  el.querySelector(".mBody").appendChild(note);
}

/* ============================================================
   sending
   ============================================================ */
async function sendMessage(text) {
  const event = await finalizeEvent({ kind: 9, tags: [["h", GROUP_ID]], content: text });
  seenIds.add(event.id);

  const row = messageRow(event.pubkey, event.content, formatTime(event.created_at), true);
  row.classList.add("pending");
  appendRow(row);

  outbox.set(event.id, { kind: "message", el: row, event });
  ws.send(JSON.stringify(["EVENT", event]));
}

msgInput.addEventListener("input", () => {
  field.classList.toggle("hot", msgInput.value.trim() !== "");
  setComposerEnabled(ws && ws.readyState === WebSocket.OPEN);
});

function trySend() {
  const text = msgInput.value.trim();
  if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
  msgInput.value = "";
  field.classList.remove("hot");
  setComposerEnabled(false);
  sendMessage(text);
}

sendBtn.addEventListener("click", trySend);
msgInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") trySend();
});

/* ============================================================
   startup
   ============================================================ */
const resolved = resolveRelayUrl();
if (resolved) {
  connect(resolved);
} else {
  relaySetup.hidden = false;
  setStatus("no relay given");
  relayConnect.addEventListener("click", () => {
    const value = relayInput.value.trim();
    if (!value) return;
    relaySetup.hidden = true;
    connect(relayUrlFromHost(value));
  });
  relayInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") relayConnect.click();
  });
}
