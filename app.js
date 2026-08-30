/* ============================================================
   hearth — talks to one bothy relay, in one group, with chat, a
   voice call, and the way in: invite links the owner mints inside
   the app, redeemed on arrival. No channels, no DMs, no QR device
   pairing, no group switching, no video, no screen share. Those
   are designed (see the mocks in the repo root) and they come
   later. Event kinds live in kinds.js.
   ============================================================ */

const GROUP_ID = "_";
const SUB_ID = "hearth";

const HEARTBEAT_MS = 5000;
const PRESENCE_TIMEOUT_MS = 13000;

// STUN only, no TURN: enough for a 2-4 person mesh to find each
// other through most NATs, with no account, token, or server-side
// component of hearth's own. A mesh that needs to punch through
// symmetric NATs reliably, or that grows past a handful of people,
// is what an SFU is for — not this build.
const ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun.cloudflare.com:3478" },
];

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
const devWarnEl = document.getElementById("devWarn");
const callWarnEl = document.getElementById("callWarn");
const joinRefusedEl = document.getElementById("joinRefused");
const joinRefusedMsgEl = document.getElementById("joinRefusedMsg");
const namePromptEl = document.getElementById("namePrompt");
const nameInput = document.getElementById("nameInput");
const nameSubmitBtn = document.getElementById("nameSubmit");
const inviteBtn = document.getElementById("inviteBtn");
const invitePanelEl = document.getElementById("invitePanel");
const newInviteBtn = document.getElementById("newInviteBtn");
const inviteLinkRowEl = document.getElementById("inviteLinkRow");
const inviteLinkTextEl = document.getElementById("inviteLinkText");
const copyInviteBtn = document.getElementById("copyInviteBtn");
const shareInviteBtn = document.getElementById("shareInviteBtn");
const inviteListEl = document.getElementById("inviteList");
const hearthEl = document.getElementById("hearth");
const hearthLabelEl = document.getElementById("hearthLabel");
const hRingEl = document.getElementById("hRing");
const hCaptionEl = document.getElementById("hCaption");
const micBtn = document.getElementById("micBtn");
const micHintEl = document.getElementById("micHint");
const leaveBtn = document.getElementById("leaveBtn");
const callFullEl = document.getElementById("callFull");
const callFullBackBtn = document.getElementById("callFullBack");
const cfLabelEl = document.getElementById("cfLabel");
const cfRingEl = document.getElementById("cfRing");
const cfCaptionEl = document.getElementById("cfCaption");

groupLabel.textContent = GROUP_ID;

/* ============================================================
   identity

   A keypair, acquired from the first source that has one. The
   sources are an ordered list because acquisition is a seam:
   today a key is found in storage or minted fresh, and later it
   will also arrive by transfer from a device the person already
   owns — that lands as one more entry in the list, not as a
   rewrite of the callers.

   At rest the private key is ciphertext in IndexedDB, sealed
   under a non-extractable AES-GCM key stored beside it. Script
   on this origin can *use* the sealing key but can never read it
   out, so nothing that exfiltrates storage gets a usable key —
   which is as close to "the key never leaves this device" as a
   plain page without hardware keys can get. The key still can't
   be carried to a second device; QR pairing (client-mobile.html)
   is what will do that.
   ============================================================ */
const IDB_NAME = "hearth";
const IDB_STORE = "identity";

function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet(db, key) {
  return new Promise((resolve, reject) => {
    const req = db.transaction(IDB_STORE).objectStore(IDB_STORE).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbPut(db, key, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, "readwrite");
    tx.objectStore(IDB_STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function loadSealedPrivkey() {
  const db = await idbOpen();
  const sealKey = await idbGet(db, "sealKey");
  const sealed = await idbGet(db, "privkey");
  db.close();
  if (!sealKey || !sealed) return null;
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.iv }, sealKey, sealed.ciphertext);
  return new Uint8Array(plain);
}

async function storeSealedPrivkey(privkey) {
  // IndexedDB is evictable under storage pressure unless the origin
  // is persisted, and evicting this store is losing the identity.
  // Best-effort: browsers variously grant silently, prompt, or
  // refuse, and a refusal changes the odds rather than the design.
  if (navigator.storage && navigator.storage.persist) {
    navigator.storage.persist().catch(() => {});
  }
  const sealKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, sealKey, privkey);
  const db = await idbOpen();
  await idbPut(db, "sealKey", sealKey);
  await idbPut(db, "privkey", { iv, ciphertext });
  db.close();
}

function identityFromPrivkey(privkey) {
  return { privkey, pubkey: S.utils.bytesToHex(S.schnorr.getPublicKey(privkey)) };
}

async function storedIdentitySource() {
  // Earlier builds kept the key as plaintext hex in localStorage.
  // Seal it properly and destroy the readable copy, once.
  const legacy = localStorage.getItem("hearth:privkey");
  if (legacy) {
    const privkey = S.utils.hexToBytes(legacy);
    await storeSealedPrivkey(privkey);
    localStorage.removeItem("hearth:privkey");
    return identityFromPrivkey(privkey);
  }
  const privkey = await loadSealedPrivkey();
  return privkey ? identityFromPrivkey(privkey) : null;
}

/* ------------------------------------------------------------
   DEV ONLY. This relay gates group membership by hand — every
   pubkey has to be added by its owner from the command line
   before it can read or write — and a fresh localStorage key on
   every cleared browser profile makes that constant while testing
   with two browsers on one machine. ?dev=1, ?dev=2, etc. pick a
   fixed key by position out of a local dev-keys.json (gitignored,
   never committed, holds real secret keys) instead of generating
   and storing one. There is still no box anywhere in this page for
   pasting a key in: this only reads a file a developer put next to
   the page themselves. It has no reason to exist in a build anyone
   but that one developer runs, and it must never be wired to
   anything reachable from the interface.
   ------------------------------------------------------------ */
async function loadDevIdentity(index) {
  let keys;
  try {
    const res = await fetch("dev-keys.json");
    if (!res.ok) throw new Error("HTTP " + res.status);
    keys = await res.json();
    if (!Array.isArray(keys)) throw new Error("not a JSON array");
  } catch (err) {
    throw new Error("couldn't load dev-keys.json (" + err.message + ")");
  }
  const hex = keys[index - 1];
  if (typeof hex !== "string") {
    throw new Error("dev-keys.json has no entry at index " + index);
  }
  const privkey = S.utils.hexToBytes(hex);
  const pubkey = S.utils.bytesToHex(S.schnorr.getPublicKey(privkey));
  return { privkey, pubkey };
}

async function devIdentitySource() {
  const devParam = new URLSearchParams(location.search).get("dev");
  if (!devParam) return null;
  try {
    return await loadDevIdentity(parseInt(devParam, 10));
  } catch (err) {
    showDevWarning("[dev] " + err.message + " — using a normal identity instead.");
    return null;
  }
}

// Tried in order; device-to-device key transfer will slot in after
// storage when it exists. Minting is the fallthrough rather than a
// source: it is what happens when nobody has this person's key, and
// it happens silently — nobody is ever asked to produce or paste
// key material, in either direction.
const identitySources = [devIdentitySource, storedIdentitySource];

async function acquireIdentity() {
  for (const source of identitySources) {
    const found = await source();
    if (found) return found;
  }
  const privkey = S.utils.randomPrivateKey();
  await storeSealedPrivkey(privkey);
  return identityFromPrivkey(privkey);
}

function showDevWarning(text) {
  devWarnEl.textContent = text;
  devWarnEl.hidden = false;
}

let identity = null;

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
   relay address, and the invite link

   A link looks like "#relay=<host>&code=<code>". Both parts ride
   in the fragment: the code because it is a single-use bearer
   token and a fragment never reaches a server log, a proxy, or a
   Referer header; the relay because it is going the same place
   anyway. When hearth was served by the relay itself the link
   carries no relay at all — the page's own origin says it.

   Relay priority: the fragment, then ?relay=<host> in the query
   (the dev workflow), then the relays this device has connected
   to before, then the page's own origin, then the manual box.
   The manual box is the fallback path, not the front door.

   Remembered relays sit above the origin because the origin is
   only a bootstrap — right when the relay itself served the page,
   wrong when a canonical copy did. A relay this device has
   actually reached is the better guess, and holding the list on
   the device is what will later let a group's second relay be
   tried when its first is down. Trying them in turn isn't built
   yet; the newest one is used.
   ============================================================ */
function parseFragment() {
  return new URLSearchParams(location.hash.slice(1));
}

function rememberedRelays() {
  try {
    const list = JSON.parse(localStorage.getItem("hearth:relays"));
    return Array.isArray(list) ? list : [];
  } catch (e) {
    return [];
  }
}

function rememberRelay(relayUrl) {
  const list = [relayUrl, ...rememberedRelays().filter((u) => u !== relayUrl)];
  localStorage.setItem("hearth:relays", JSON.stringify(list));
}

function relayUrlFromHost(host) {
  if (host.includes("://")) return host;
  return "wss://" + host;
}

// wss -> https, ws -> http: the same server, spoken to over fetch
// instead of a websocket — NIP-11 and the management API live there.
function relayHttpUrl(relayUrl) {
  return relayUrl.replace(/^ws/, "http");
}

function resolveRelayUrl() {
  const fromFragment = parseFragment().get("relay");
  if (fromFragment) return relayUrlFromHost(fromFragment);

  const fromParam = new URLSearchParams(location.search).get("relay");
  if (fromParam) return relayUrlFromHost(fromParam);

  const remembered = rememberedRelays();
  if (remembered.length > 0) return remembered[0];

  if (location.protocol === "http:" || location.protocol === "https:") {
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    return scheme + "//" + location.host;
  }

  return null; // arrived with nothing to go on — fall back to the manual box
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
let currentRelayUrl = null;
let inviteCode = null; // a code from the fragment, pending until the relay answers
let halted = false; // a refused invite is final — no reconnect loop behind it

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
    rememberRelay(relayUrl);
    if (inviteCode) {
      // Redemption comes before anything else — before subscribing,
      // and before the person is asked for so much as a name. Nobody
      // should type their name into a link that turns out to be spent.
      setStatus("presenting your invite…");
      sendJoinRequest(inviteCode);
    } else {
      setStatus("connected — joining #" + GROUP_ID + "…");
      subscribe();
      setComposerEnabled(true);
    }
  });

  ws.addEventListener("message", (evt) => {
    let frame;
    try {
      frame = JSON.parse(evt.data);
    } catch (e) {
      console.error("hearth: unparseable relay frame", evt.data);
      return;
    }
    handleFrame(frame, relayUrl);
  });

  ws.addEventListener("close", () => {
    setComposerEnabled(false);
    if (halted) return;
    setStatus("disconnected — retrying…", "warn");
    reconnectTimer = setTimeout(() => connect(relayUrl), reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 1.5, 15000);
  });

  ws.addEventListener("error", () => {
    // the close handler fires right after and drives the visible retry state
    console.error("hearth: websocket error");
  });
}

function subscribe() {
  ws.send(JSON.stringify(["REQ", SUB_ID,
    { kinds: [KINDS.CHAT], "#h": [GROUP_ID], limit: 50 },
    { kinds: [KINDS.PROFILE], "#h": [GROUP_ID] },
    { kinds: [KINDS.CALL_PRESENCE], "#h": [GROUP_ID] },
    { kinds: [KINDS.CALL_SIGNAL], "#h": [GROUP_ID], "#p": [identity.pubkey] },
  ]));
}

async function handleFrame(frame, relayUrl) {
  const type = frame[0];

  if (type === "EVENT" && frame[1] === SUB_ID) {
    const event = frame[2];
    if (event.kind === KINDS.CHAT) renderIncoming(event);
    else if (event.kind === KINDS.PROFILE) handleProfile(event);
    else if (event.kind === KINDS.CALL_PRESENCE) handlePresence(event);
    else if (event.kind === KINDS.CALL_SIGNAL) handleSignal(event);
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
      kind: KINDS.CLIENT_AUTH,
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
          if (e.lastReason && e.lastReason.startsWith("auth-required")) {
            ws.send(JSON.stringify(["EVENT", e.event]));
          }
        }
      } else {
        authState = "failed";
        setStatus("relay refused authentication: " + message, "warn");
      }
      return;
    }

    if (entry.kind === "join") {
      outbox.delete(eventId);
      if (ok) {
        // An empty message is a fresh admission; "already a member of
        // this group" is this key coming back with a code it didn't
        // need, which leaves the code unspent. Only the fresh member
        // gets asked their name.
        finishJoin(message === "");
      } else {
        // Shown verbatim. The relay's refusal is deliberately uniform
        // across unknown, spent, expired and revoked codes, so nothing
        // is added here: a more specific message would be a guess, and
        // a friendlier one would leak what the relay chose not to.
        refuseJoin(message || "the relay refused the invite");
      }
      return;
    }

    if (entry.kind === "profile") {
      if (ok) {
        outbox.delete(eventId);
      } else if (message && message.startsWith("auth-required") && authState !== "failed") {
        entry.lastReason = message;
      } else {
        outbox.delete(eventId);
        showBanner("your name wasn't saved: " + (message || "no reason given"));
      }
      return;
    }

    if (entry.kind === "invite") {
      if (ok) {
        outbox.delete(eventId);
        newInviteBtn.disabled = false;
        showInviteLink(entry.code);
        refreshInviteList();
      } else if (message && message.startsWith("auth-required") && authState !== "failed") {
        entry.lastReason = message;
      } else {
        outbox.delete(eventId);
        newInviteBtn.disabled = false;
        showBanner("invite refused: " + (message || "no reason given"));
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
      return;
    }

    if (entry.kind === "ephemeral") {
      if (ok) {
        outbox.delete(eventId);
      } else if (message && message.startsWith("auth-required") && authState !== "failed") {
        entry.lastReason = message;
        // left in the outbox; resent once the pending AUTH above completes
      } else {
        outbox.delete(eventId);
        // a dropped ICE candidate or presence beat stalls the call with no
        // error unless we say so here — this is that "say so".
        showBanner("[call] " + entry.label + " refused: " + (message || "no reason given"));
      }
    }
  }
}

/* ============================================================
   profiles — who each pubkey asked to be called

   A kind 0, tagged into the group so only the group can read it.
   Replaceable, so the newest wins; the map tracks created_at to
   keep an old one arriving late from clobbering a rename.
   ============================================================ */
const profiles = new Map(); // pubkey -> { name, at }

function displayName(pubkey) {
  const p = profiles.get(pubkey);
  return p ? p.name : shortName(pubkey);
}

function initials(pubkey) {
  const p = profiles.get(pubkey);
  return (p ? p.name : shortName(pubkey)).slice(0, 2);
}

function handleProfile(event) {
  let name;
  try {
    name = JSON.parse(event.content).name;
  } catch (e) {
    return;
  }
  if (typeof name !== "string" || name.trim() === "") return;
  const existing = profiles.get(event.pubkey);
  if (existing && existing.at >= event.created_at) return;
  profiles.set(event.pubkey, { name: name.trim(), at: event.created_at });
  applyProfile(event.pubkey);
}

// Message rows already on screen were rendered before this name
// arrived (or under an older one) — restyle them in place. The
// hearth rebuilds itself wholesale, so one render call covers it.
function applyProfile(pubkey) {
  for (const el of document.querySelectorAll('[data-name-for="' + pubkey + '"]')) {
    el.textContent = displayName(pubkey);
  }
  for (const el of document.querySelectorAll('[data-av-for="' + pubkey + '"]')) {
    el.textContent = initials(pubkey);
  }
  renderHearth();
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
  av.dataset.avFor = pubkey;
  av.textContent = initials(pubkey);

  const body = document.createElement("div");
  body.className = "mBody";

  const head = document.createElement("div");
  head.className = "mHead";
  const name = document.createElement("span");
  name.className = "mName";
  name.dataset.nameFor = pubkey;
  name.textContent = displayName(pubkey);
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
  const event = await finalizeEvent({ kind: KINDS.CHAT, tags: [["h", GROUP_ID]], content: text });
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
   joining — redeeming the invite a link carried

   The kind-9021 goes to the relay before anything is subscribed
   and before the person is asked anything. The relay's answer is
   the whole decision: admitted means in (with a name prompt if
   the admission was fresh), refused means the relay's message,
   verbatim, and a full stop.
   ============================================================ */
async function sendJoinRequest(code) {
  // A reconnect while the answer was in flight leaves a stale entry
  // behind; the relay treats a re-presented code from a key it
  // already admitted as "already a member", so resending is safe.
  for (const [id, e] of outbox) {
    if (e.kind === "join") outbox.delete(id);
  }
  const event = await finalizeEvent({
    kind: KINDS.JOIN_REQUEST,
    tags: [["h", GROUP_ID], ["code", code]],
  });
  outbox.set(event.id, { kind: "join", event });
  ws.send(JSON.stringify(["EVENT", event]));
}

function finishJoin(fresh) {
  inviteCode = null;
  // The code is spent (or was never needed). A reload shouldn't
  // present it again, and a bookmark of this page shouldn't carry a
  // dead secret — so the code leaves the fragment. The relay stays:
  // it's how a reload of this same page finds its way back.
  const params = parseFragment();
  params.delete("code");
  const rest = params.toString();
  history.replaceState(null, "", location.pathname + location.search + (rest ? "#" + rest : ""));
  setStatus("connected — joining #" + GROUP_ID + "…");
  subscribe();
  setComposerEnabled(true);
  if (fresh) {
    namePromptEl.hidden = false;
    nameInput.focus();
  }
}

function refuseJoin(message) {
  inviteCode = null;
  halted = true;
  joinRefusedMsgEl.textContent = message;
  joinRefusedEl.hidden = false;
  setStatus("not joined", "warn");
  ws.close();
}

/* ---------- the one question a new member is asked ---------- */
async function submitName() {
  const name = nameInput.value.trim();
  namePromptEl.hidden = true;
  if (!name) return; // no name offered — the short pubkey stands in until they give one
  profiles.set(identity.pubkey, { name, at: Math.floor(Date.now() / 1000) });
  applyProfile(identity.pubkey);
  const event = await finalizeEvent({
    kind: KINDS.PROFILE,
    tags: [["h", GROUP_ID]],
    content: JSON.stringify({ name }),
  });
  outbox.set(event.id, { kind: "profile", event });
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(["EVENT", event]));
  }
}

nameSubmitBtn.addEventListener("click", submitName);
nameInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") submitName();
});

/* ============================================================
   invites — the owner handing out the way in

   The control exists only when the relay's NIP-11 document names
   this identity as the owner; everyone else never learns it is
   there. Creating one is a kind-9009 over the websocket. Listing
   the outstanding ones is the relay's own NIP-86 management API,
   because redeemed-or-not lives in the relay's invite table, not
   in any event a subscription could watch.
   ============================================================ */
async function checkOwnership() {
  let info;
  try {
    const res = await fetch(relayHttpUrl(currentRelayUrl), {
      headers: { Accept: "application/nostr+json" },
    });
    if (!res.ok) return;
    info = await res.json();
  } catch (err) {
    return; // no NIP-11 answer just means no invite control appears
  }
  if (info.pubkey === identity.pubkey) inviteBtn.hidden = false;
}

async function createInvite() {
  // 32 hex characters from 16 random bytes: comfortably inside the
  // relay's 16-to-128 bounds, and unguessable, which is the entire
  // security of an invite link. No expiration tag — the relay
  // applies its 7-day default.
  const code = S.utils.bytesToHex(S.utils.randomBytes(16));
  const event = await finalizeEvent({
    kind: KINDS.CREATE_INVITE,
    tags: [["h", GROUP_ID], ["code", code]],
  });
  outbox.set(event.id, { kind: "invite", code, event });
  newInviteBtn.disabled = true;
  ws.send(JSON.stringify(["EVENT", event]));
}

function inviteLinkFor(code) {
  const params = new URLSearchParams();
  // Served by the relay itself, the link needs no relay — the
  // page's own origin says it. A wss relay travels as a bare host;
  // anything else (ws:// in dev) travels whole.
  const wsOrigin = (location.protocol === "https:" ? "wss://" : "ws://") + location.host;
  if (wsOrigin !== currentRelayUrl) {
    params.set("relay", currentRelayUrl.startsWith("wss://") ? currentRelayUrl.slice(6) : currentRelayUrl);
  }
  params.set("code", code);
  return location.origin + location.pathname + "#" + params.toString();
}

let latestInviteLink = null;

function showInviteLink(code) {
  latestInviteLink = inviteLinkFor(code);
  inviteLinkTextEl.textContent = latestInviteLink;
  shareInviteBtn.hidden = !navigator.share;
  inviteLinkRowEl.hidden = false;
}

copyInviteBtn.addEventListener("click", () => {
  navigator.clipboard.writeText(latestInviteLink).then(() => {
    copyInviteBtn.textContent = "copied";
    setTimeout(() => { copyInviteBtn.textContent = "copy"; }, 1500);
  });
});

shareInviteBtn.addEventListener("click", () => {
  navigator.share({ url: latestInviteLink }).catch(() => {});
});

// A NIP-86 call: POST to the relay's HTTPS root, authenticated by a
// NIP-98 event over this exact method, URL and body.
async function manageRelay(method, params) {
  const url = relayHttpUrl(currentRelayUrl);
  const body = JSON.stringify({ method, params });
  const payload = S.utils.bytesToHex(await S.utils.sha256(new TextEncoder().encode(body)));
  const authEvent = await finalizeEvent({
    kind: KINDS.HTTP_AUTH,
    tags: [["u", url], ["method", "POST"], ["payload", payload]],
  });
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/nostr+json+rpc",
      "Authorization": "Nostr " + btoa(JSON.stringify(authEvent)),
    },
    body,
  });
  return res.json();
}

async function refreshInviteList() {
  inviteListEl.textContent = "checking…";
  let response;
  try {
    response = await manageRelay("listunusedinvites", []);
  } catch (err) {
    // The management endpoint sends no CORS headers, so a copy of
    // hearth hosted anywhere but the relay itself can't reach it.
    // Creating invites still works — that goes over the websocket.
    inviteListEl.textContent =
      "couldn’t reach the relay’s management API from this copy of hearth — " +
      "outstanding invites can only be listed from the copy the relay serves itself.";
    return;
  }
  if (response.error) {
    inviteListEl.textContent = "the relay said: " + response.error;
    return;
  }
  const invites = response.result || [];
  inviteListEl.textContent = "";
  if (invites.length === 0) {
    inviteListEl.textContent = "no invites outstanding.";
    return;
  }
  const nowSec = Math.floor(Date.now() / 1000);
  for (const invite of invites) {
    const row = document.createElement("div");
    row.className = "invRow";
    const codeEl = document.createElement("code");
    codeEl.textContent = invite.code.slice(0, 8) + "…";
    const expEl = document.createElement("span");
    const days = Math.ceil((invite.expires_at - nowSec) / 86400);
    expEl.textContent = days <= 1 ? "expires today" : "expires in " + days + " days";
    const copyBtn = document.createElement("button");
    copyBtn.className = "invCopy";
    copyBtn.textContent = "copy link";
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(inviteLinkFor(invite.code)).then(() => {
        copyBtn.textContent = "copied";
        setTimeout(() => { copyBtn.textContent = "copy link"; }, 1500);
      });
    });
    row.append(codeEl, expEl, copyBtn);
    inviteListEl.appendChild(row);
  }
}

inviteBtn.addEventListener("click", () => {
  const opening = invitePanelEl.hidden;
  invitePanelEl.hidden = !opening;
  if (opening) refreshInviteList();
});

newInviteBtn.addEventListener("click", createInvite);

/* ============================================================
   voice call — presence, mesh signalling, and the hearth

   Both call kinds are ephemeral (NIP-01: 20000-29999 aren't
   stored). Signalling is addressed to one peer via a p tag; call
   presence — who's at the hearth right now — is deliberately not
   the same thing as group membership: membership is a standing
   grant from the relay owner, presence is "still sending
   heartbeats in the last few seconds."

   A mesh: every participant connects directly to every other one.
   That works with no server-side component for the two to four
   people this is built for, and needs no account or token, just
   STUN. Larger calls or a shared screen are what an SFU is for —
   switching to one later changes how audio moves, not how offers
   and candidates get exchanged, so nothing here should assume mesh
   is permanent, and nothing here should build toward the SFU either.
   ============================================================ */
const call = {
  joined: false,
  muted: false,
  presence: new Map(), // pubkey -> { lastSeen, muted }
  peers: new Map(), // pubkey -> { pc, audioEl, candidateQueue, remoteSet }
  speaking: new Set(), // pubkeys (including our own) currently over threshold
  localStream: null,
};
let heartbeatTimer = null;
let callWarnTimer = null;

function showBanner(text) {
  callWarnEl.textContent = text;
  callWarnEl.hidden = false;
  clearTimeout(callWarnTimer);
  callWarnTimer = setTimeout(() => { callWarnEl.hidden = true; }, 8000);
}

// Every ephemeral send (signalling and presence alike) is tracked in the
// same outbox as chat messages, so an auth-required refusal gets replayed
// once auth completes and any other refusal surfaces instead of stalling
// a connection silently.
async function sendEphemeral(partial, label) {
  const event = await finalizeEvent(partial);
  outbox.set(event.id, { kind: "ephemeral", label, event });
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(["EVENT", event]));
  }
}

function sendSignal(pubkey, payload) {
  sendEphemeral(
    { kind: KINDS.CALL_SIGNAL, tags: [["h", GROUP_ID], ["p", pubkey]], content: JSON.stringify(payload) },
    "call signal to " + displayName(pubkey)
  );
}

function publishPresence() {
  sendEphemeral(
    { kind: KINDS.CALL_PRESENCE, tags: [["h", GROUP_ID]], content: JSON.stringify({ status: "here", muted: call.muted }) },
    "presence beat"
  );
}

function publishLeavePresence() {
  sendEphemeral(
    { kind: KINDS.CALL_PRESENCE, tags: [["h", GROUP_ID]], content: JSON.stringify({ status: "leave" }) },
    "presence beat"
  );
}

/* ---------- presence: who's at the hearth right now ---------- */
function handlePresence(event) {
  if (event.pubkey === identity.pubkey) return; // our own heartbeat, echoed back
  let payload;
  try {
    payload = JSON.parse(event.content);
  } catch (e) {
    return;
  }
  if (payload.status === "leave") {
    call.presence.delete(event.pubkey);
    teardownPeer(event.pubkey);
  } else {
    const isNew = !call.presence.has(event.pubkey);
    call.presence.set(event.pubkey, { lastSeen: Date.now(), muted: !!payload.muted });
    if (isNew && call.joined) maybeConnectToPeer(event.pubkey);
  }
  renderHearth();
}

// Ephemeral events aren't stored, so "in the call" only exists as long as
// someone keeps saying so. A missed heartbeat past this window means gone,
// which is also the only cleanup an ungraceful exit (closed tab, dropped
// connection) ever gets — there's no other signal for it.
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [pubkey, info] of call.presence) {
    if (now - info.lastSeen > PRESENCE_TIMEOUT_MS) {
      call.presence.delete(pubkey);
      teardownPeer(pubkey);
      changed = true;
    }
  }
  if (changed) renderHearth();
}, 3000);

/* ---------- mesh: one RTCPeerConnection per other participant ---------- */
function maybeConnectToPeer(pubkey) {
  if (call.peers.has(pubkey)) return;
  // Both sides run this independently and need to agree on exactly one
  // offerer without talking it over first — a plain string compare on the
  // pubkeys they already both know does that.
  if (identity.pubkey > pubkey) createPeer(pubkey, true);
}

function createPeer(pubkey, isInitiator) {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  const entry = { pc, audioEl: null, candidateQueue: [], remoteSet: false };
  call.peers.set(pubkey, entry);

  if (call.localStream) {
    for (const track of call.localStream.getTracks()) pc.addTrack(track, call.localStream);
  }

  pc.addEventListener("track", (e) => {
    const audioEl = document.createElement("audio");
    audioEl.autoplay = true;
    audioEl.srcObject = e.streams[0];
    document.body.appendChild(audioEl);
    audioEl.play().catch(() => {});
    entry.audioEl = audioEl;
    attachSpeakingDetector(pubkey, e.streams[0]);
  });

  pc.addEventListener("icecandidate", (e) => {
    if (e.candidate) sendSignal(pubkey, { type: "candidate", candidate: e.candidate.toJSON() });
  });

  pc.addEventListener("connectionstatechange", () => {
    if (pc.connectionState === "failed" || pc.connectionState === "closed") teardownPeer(pubkey);
  });

  if (isInitiator) {
    pc.createOffer()
      .then((offer) => pc.setLocalDescription(offer).then(() => offer))
      .then((offer) => sendSignal(pubkey, { type: "offer", sdp: offer.sdp }));
  }

  return entry;
}

async function flushQueuedCandidates(entry) {
  for (const candidate of entry.candidateQueue.splice(0)) {
    try {
      await entry.pc.addIceCandidate(candidate);
    } catch (err) {
      console.error("hearth: bad ICE candidate", err);
    }
  }
}

async function handleSignal(event) {
  if (event.pubkey === identity.pubkey) return;
  let payload;
  try {
    payload = JSON.parse(event.content);
  } catch (e) {
    return;
  }

  if (payload.type === "offer") {
    if (!call.joined) return; // not at the hearth — nothing to answer with
    const entry = call.peers.get(event.pubkey) || createPeer(event.pubkey, false);
    await entry.pc.setRemoteDescription({ type: "offer", sdp: payload.sdp });
    entry.remoteSet = true;
    await flushQueuedCandidates(entry);
    const answer = await entry.pc.createAnswer();
    await entry.pc.setLocalDescription(answer);
    sendSignal(event.pubkey, { type: "answer", sdp: answer.sdp });
    return;
  }

  const entry = call.peers.get(event.pubkey);
  if (!entry) return; // an answer or candidate with no offer on our side — drop it

  if (payload.type === "answer") {
    await entry.pc.setRemoteDescription({ type: "answer", sdp: payload.sdp });
    entry.remoteSet = true;
    await flushQueuedCandidates(entry);
  } else if (payload.type === "candidate") {
    if (entry.remoteSet) {
      try {
        await entry.pc.addIceCandidate(payload.candidate);
      } catch (err) {
        console.error("hearth: bad ICE candidate", err);
      }
    } else {
      entry.candidateQueue.push(payload.candidate);
    }
  }
}

function teardownPeer(pubkey) {
  const entry = call.peers.get(pubkey);
  if (!entry) return;
  entry.pc.close();
  if (entry.audioEl) entry.audioEl.remove();
  detachSpeakingDetector(pubkey);
  call.peers.delete(pubkey);
  call.speaking.delete(pubkey);
  renderHearth();
}

/* ---------- speaking: a volume gate per stream, ours included ---------- */
const SPEAKING_RMS = 0.025;
const SPEAKING_HOLD_MS = 500;
const analysers = new Map(); // pubkey -> { ctx, interval }

function attachSpeakingDetector(pubkey, stream) {
  detachSpeakingDetector(pubkey);
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  const ctx = new AudioCtx();
  const source = ctx.createMediaStreamSource(stream);
  const analyser = ctx.createAnalyser();
  analyser.fftSize = 512;
  source.connect(analyser);
  const data = new Uint8Array(analyser.frequencyBinCount);
  let lastLoudAt = 0;
  const interval = setInterval(() => {
    analyser.getByteTimeDomainData(data);
    let sumSquares = 0;
    for (let i = 0; i < data.length; i++) {
      const v = (data[i] - 128) / 128;
      sumSquares += v * v;
    }
    if (Math.sqrt(sumSquares / data.length) > SPEAKING_RMS) lastLoudAt = Date.now();
    const speaking = Date.now() - lastLoudAt < SPEAKING_HOLD_MS;
    if (speaking !== call.speaking.has(pubkey)) {
      if (speaking) call.speaking.add(pubkey);
      else call.speaking.delete(pubkey);
      renderHearth();
    }
  }, 200);
  analysers.set(pubkey, { ctx, interval });
}

function detachSpeakingDetector(pubkey) {
  const a = analysers.get(pubkey);
  if (!a) return;
  clearInterval(a.interval);
  a.ctx.close();
  analysers.delete(pubkey);
}

/* ---------- the mic: press to join, press again to mute ---------- */
async function joinCall() {
  try {
    call.localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (err) {
    showBanner("[call] microphone permission refused — " + err.message);
    return;
  }
  call.joined = true;
  call.muted = false;
  attachSpeakingDetector(identity.pubkey, call.localStream);
  publishPresence();
  heartbeatTimer = setInterval(publishPresence, HEARTBEAT_MS);
  for (const pubkey of call.presence.keys()) maybeConnectToPeer(pubkey);
  renderHearth();
}

function toggleMute() {
  call.muted = !call.muted;
  for (const track of call.localStream.getAudioTracks()) track.enabled = !call.muted;
  publishPresence(); // so others' muted badge for us updates promptly
  renderHearth();
}

function leaveCall() {
  if (!call.joined) return;
  publishLeavePresence();
  clearInterval(heartbeatTimer);
  heartbeatTimer = null;
  for (const pubkey of [...call.peers.keys()]) teardownPeer(pubkey);
  detachSpeakingDetector(identity.pubkey);
  for (const track of call.localStream.getTracks()) track.stop();
  call.localStream = null;
  call.joined = false;
  call.muted = false;
  call.speaking.delete(identity.pubkey);
  renderHearth();
}

micBtn.addEventListener("click", () => {
  if (!call.joined) joinCall();
  else toggleMute();
});
leaveBtn.addEventListener("click", leaveCall);

/* ---------- rendering: the inline hearth and its full-screen twin ---------- */
function buildRing(container, pubkeys) {
  container.innerHTML = "";
  if (pubkeys.length === 0) {
    container.innerHTML = '<div style="font-size:12px;color:var(--faint);align-self:center">no one’s by the fire</div>';
    return;
  }
  for (const pubkey of pubkeys) {
    const isMe = pubkey === identity.pubkey;
    const muted = isMe ? call.muted : (call.presence.get(pubkey) || {}).muted;
    const b = document.createElement("button");
    b.className = "hAv" + (call.speaking.has(pubkey) ? " speaking" : "");
    const av = document.createElement("div");
    av.className = "av";
    av.style.background = colorFor(pubkey);
    av.style.borderRadius = "50%";
    av.textContent = initials(pubkey);
    b.appendChild(av);
    if (muted) {
      const badge = document.createElement("span");
      badge.className = "badge mutedB";
      badge.innerHTML = '<svg width="10" height="10" viewBox="0 0 12 12" fill="currentColor"><rect x="4.4" y="1" width="3.2" height="6" rx="1.6"/><path d="M2.5 5.4v.6a3.5 3.5 0 0 0 7 0v-.6h-1v.6a2.5 2.5 0 0 1-5 0v-.6z"/><line x1="1.5" y1="10.5" x2="10.5" y2="1.5" stroke="#d98a56" stroke-width="1.4" stroke-linecap="round"/></svg>';
      b.appendChild(badge);
    }
    const name = document.createElement("span");
    name.className = "hName";
    name.textContent = isMe ? "you" : displayName(pubkey);
    b.appendChild(name);
    container.appendChild(b);
  }
}

function renderHearth() {
  const seatedPubkeys = [...call.presence.keys()];
  if (call.joined) seatedPubkeys.unshift(identity.pubkey);
  const seated = seatedPubkeys.length;

  hearthEl.classList.toggle("cold", seated === 0);
  hearthEl.classList.toggle("youIn", call.joined && !call.muted);
  hearthEl.classList.toggle("youMuted", call.joined && call.muted);
  const label = seated === 0 ? "the hearth" : "at the hearth";
  hearthLabelEl.textContent = label;
  cfLabelEl.textContent = label;

  buildRing(hRingEl, seatedPubkeys);
  buildRing(cfRingEl, seatedPubkeys);

  const speaker = seatedPubkeys.find((p) => call.speaking.has(p));
  let captionText, quiet;
  if (speaker) {
    captionText = speaker === identity.pubkey ? "you’re talking" : displayName(speaker) + " is talking";
    quiet = false;
  } else if (seated > 0) {
    captionText = "quiet crackling";
    quiet = true;
  } else {
    captionText = " ";
    quiet = true;
  }
  hCaptionEl.textContent = captionText;
  hCaptionEl.classList.toggle("quietCap", quiet);
  cfCaptionEl.textContent = captionText;
  cfCaptionEl.classList.toggle("quietCap", quiet);

  if (!call.joined) micHintEl.textContent = seated === 0 ? "the fire is out — tap to light it" : "tap to join them";
  else if (call.muted) micHintEl.textContent = "muted — tap to speak";
  else micHintEl.textContent = "you’re live — tap to hush";
}

/* ---------- tapping the hearth: expand to full screen and back ---------- */
hearthEl.addEventListener("click", (e) => {
  if (e.target.closest(".mic") || e.target.closest(".leaveBtn")) return;
  callFullEl.hidden = false;
});
callFullBackBtn.addEventListener("click", () => {
  callFullEl.hidden = true;
});

/* ============================================================
   startup
   ============================================================ */
function start(relayUrl) {
  currentRelayUrl = relayUrl;
  connect(relayUrl);
  checkOwnership();
}

(async function init() {
  identity = await acquireIdentity();
  renderHearth();

  inviteCode = parseFragment().get("code");

  const resolved = resolveRelayUrl();
  if (resolved) {
    start(resolved);
  } else {
    relaySetup.hidden = false;
    setStatus("no relay given");
    relayConnect.addEventListener("click", () => {
      const value = relayInput.value.trim();
      if (!value) return;
      relaySetup.hidden = true;
      start(relayUrlFromHost(value));
    });
    relayInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") relayConnect.click();
    });
  }
})();
