/* ============================================================
   hearth — talks to one bothy relay, in one group, with chat and
   a voice call. No channels, no DMs, no QR login, no invites, no
   profile editing, no group switching, no video, no screen share.
   Those are designed (see the mocks in the repo root) and they
   come later.
   ============================================================ */

const GROUP_ID = "_";
const SUB_ID = "hearth";

// Ephemeral (NIP-01: kinds 20000-29999 aren't stored by relays)
// signalling for the voice call. 25050 carries offers, answers and
// ICE candidates, addressed to one peer via a p tag. 25051 is call
// presence — who's at the hearth right now — which is deliberately
// not the same thing as group membership: membership is a standing
// kind-9000 grant from the relay owner, presence is "still sending
// heartbeats in the last few seconds." There's no NIP for either of
// these; 25051 just sits next to the signalling kind.
const SIGNAL_KIND = 25050;
const PRESENCE_KIND = 25051;
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
  const stored = localStorage.getItem("hearth:privkey");
  if (stored) {
    const privkey = S.utils.hexToBytes(stored);
    const pubkey = S.utils.bytesToHex(S.schnorr.getPublicKey(privkey));
    return { privkey, pubkey };
  }
  const privkey = S.utils.randomPrivateKey();
  localStorage.setItem("hearth:privkey", S.utils.bytesToHex(privkey));
  const pubkey = S.utils.bytesToHex(S.schnorr.getPublicKey(privkey));
  return { privkey, pubkey };
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

async function resolveIdentity() {
  const devParam = new URLSearchParams(location.search).get("dev");
  if (!devParam) return loadOrCreateIdentity();
  try {
    return await loadDevIdentity(parseInt(devParam, 10));
  } catch (err) {
    showDevWarning("[dev] " + err.message + " — using a normal generated identity instead.");
    return loadOrCreateIdentity();
  }
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
      console.error("hearth: unparseable relay frame", evt.data);
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
    console.error("hearth: websocket error");
  });
}

function subscribe() {
  ws.send(JSON.stringify(["REQ", SUB_ID,
    { kinds: [9], "#h": [GROUP_ID], limit: 50 },
    { kinds: [PRESENCE_KIND], "#h": [GROUP_ID] },
    { kinds: [SIGNAL_KIND], "#h": [GROUP_ID], "#p": [identity.pubkey] },
  ]));
}

async function handleFrame(frame, relayUrl) {
  const type = frame[0];

  if (type === "EVENT" && frame[1] === SUB_ID) {
    const event = frame[2];
    if (event.kind === 9) renderIncoming(event);
    else if (event.kind === PRESENCE_KIND) handlePresence(event);
    else if (event.kind === SIGNAL_KIND) handleSignal(event);
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
          if ((e.kind === "message" || e.kind === "ephemeral") && e.lastReason && e.lastReason.startsWith("auth-required")) {
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
        showCallWarning(entry.label + " refused: " + (message || "no reason given"));
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
   voice call — presence, mesh signalling, and the hearth

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

function showCallWarning(text) {
  callWarnEl.textContent = "[call] " + text;
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
    { kind: SIGNAL_KIND, tags: [["h", GROUP_ID], ["p", pubkey]], content: JSON.stringify(payload) },
    "call signal to " + shortName(pubkey)
  );
}

function publishPresence() {
  sendEphemeral(
    { kind: PRESENCE_KIND, tags: [["h", GROUP_ID]], content: JSON.stringify({ status: "here", muted: call.muted }) },
    "presence beat"
  );
}

function publishLeavePresence() {
  sendEphemeral(
    { kind: PRESENCE_KIND, tags: [["h", GROUP_ID]], content: JSON.stringify({ status: "leave" }) },
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
    showCallWarning("microphone permission refused — " + err.message);
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
    av.textContent = shortName(pubkey).slice(0, 2);
    b.appendChild(av);
    if (muted) {
      const badge = document.createElement("span");
      badge.className = "badge mutedB";
      badge.innerHTML = '<svg width="10" height="10" viewBox="0 0 12 12" fill="currentColor"><rect x="4.4" y="1" width="3.2" height="6" rx="1.6"/><path d="M2.5 5.4v.6a3.5 3.5 0 0 0 7 0v-.6h-1v.6a2.5 2.5 0 0 1-5 0v-.6z"/><line x1="1.5" y1="10.5" x2="10.5" y2="1.5" stroke="#d98a56" stroke-width="1.4" stroke-linecap="round"/></svg>';
      b.appendChild(badge);
    }
    const name = document.createElement("span");
    name.className = "hName";
    name.textContent = isMe ? "you" : shortName(pubkey);
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
    captionText = speaker === identity.pubkey ? "you’re talking" : shortName(speaker) + " is talking";
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
(async function init() {
  identity = await resolveIdentity();
  renderHearth();

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
})();
