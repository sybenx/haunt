/* ============================================================
   carrying a key to another device

   This is QR_SECRET_TRANSFER.md — the qrst specification — under
   its `nostr-nsec` profile, and nothing else in this file knows
   what hearth is. Two devices each make a throwaway keypair, one
   shows a QR carrying its burner's public half, the other scans
   it, and everything after that travels as a NIP-59 gift wrap
   addressed to a burner. Relays see a wrap addressed to a key that
   exists for ten minutes and has never said anything else.

   Both flows are here because a person's devices do not all have
   cameras pointing the same way. In flow A the device receiving
   the key shows the QR and the device holding it scans; in flow B
   it is the other way round. They share the burners, the code, the
   message kinds and the wrap handling, so the second flow is a few
   branches rather than a second protocol.

   The one thing this file will not do is decide. It hands the
   screen a code and waits: a key is only ever released after the
   person holding it says so, and only ever stored after the person
   receiving it says so.
   ============================================================ */
(function (global) {
"use strict";

const S = global.NobleSecp256k1;
const KF = global.NobleKeyFormats;

/* ---------- what is being moved (qrst §5) ----------

   The profile names the kind of secret in the code and is hashed
   into the short code itself, so two devices that disagree about
   what is moving cannot agree on a number to compare. Hearth moves
   whole identity keys and nothing else, so there is one of these
   and it is not configurable. */
const PROFILE = "nostr-nsec";

/* ---------- the relays a transfer travels over ----------

   Not the group's relay. A bothy hands a kind 1059 to its owner
   and to nobody else, and refuses a subscription naming that kind
   from anyone else at all, so a burner subscribed there would sit
   in silence until it expired. These are public relays that take
   a wrap from a key they have never seen, which is what this
   needs and what a bothy deliberately is not. Four is the most a
   QR may carry (§3.2); this list is that long so a person whose
   home connection cannot reach one of them still has three. */
const DEFAULT_RELAYS = [
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://relay.primal.net",
  "wss://offchain.pub",
];

// qrst §11.4. Placeholders in the specification too: they are not
// registered anywhere and are expected to change once they are, so
// a build of hearth pairs with a build of hearth and nothing else
// until that happens.
const KINDS = {
  SEAL: 13,           // NIP-59
  GIFT_WRAP: 1059,    // NIP-59
  CLIENT_AUTH: 22242, // NIP-42, signed by the burner rather than the identity
  HELLO: 24401,
  REQUEST: 24402,
  NONCE: 24403,
  REVEAL: 24404,
  PAYLOAD: 24405,
  ACK: 24406,
  ABORT: 24407,
};

// The kinds this file speaks. Anything else inside a session is the
// caller's own and is handed to it untouched.
const KNOWN_KINDS = new Set([
  KINDS.HELLO, KINDS.REQUEST, KINDS.PAYLOAD,
  KINDS.ACK, KINDS.NONCE, KINDS.REVEAL, KINDS.ABORT,
]);

const VERSION = "1";              // the `v` tag and the QR's v=
const SESSION_SECONDS = 600;      // §2, a session lives ten minutes
const WRAP_EXPIRY_SECONDS = 600;  // §11.4
const SINCE_BACKDATE = 172800;    // §11.5, two days
const ZEROIZE_AFTER_MS = 60000;   // §7 step 18, §8 step 18
const MAX_PENDING = 5;            // §8, pending requests per session
const SAS_LIST_MAX = 3;           // §9, codes shown at once
// §11.4's SLACK, and normative rather than a choice made here: a
// rumor's own created_at is set by the other device's clock, two
// phones disagree by a minute often enough that a window with no
// give in it would throw away honest transfers, and a client that
// accepts what another rejects fails honest pairings in a way that
// looks exactly like interference.
const CLOCK_SLACK = 120;

/* ============================================================
   bytes
   ============================================================ */
const enc = new TextEncoder();

function toHex(bytes) { return S.utils.bytesToHex(bytes); }
function fromHex(hex) { return S.utils.hexToBytes(hex); }

function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

function b64encode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return global.btoa(s);
}

function b64decode(text) {
  const s = global.atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// Not a promise that the bytes are gone — a JavaScript engine may
// have copied them anywhere and this cannot reach those copies.
// It clears the one array this code is holding, which is worth
// doing and is not worth describing as more than it is.
function wipe(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
}

function nowSeconds() { return Math.floor(Date.now() / 1000); }

/* ============================================================
   NIP-44 v2

   The seal and the wrap are both NIP-44 payloads, so this has to
   exist before either of them. Every primitive underneath comes
   from the vendored noble bundle; the only thing written here is
   the arrangement of them, which is what the NIP specifies.
   ============================================================ */

// HKDF-extract over the x coordinate of the ECDH point, which is
// what NIP-44 means by a conversation key: the same value on both
// sides, derived from one side's secret and the other's public.
function conversationKey(privkey, peerPubHex) {
  const shared = S.getSharedSecret(privkey, "02" + peerPubHex, true);
  return KF.extract(KF.sha256, shared.slice(1, 33), enc.encode("nip44-v2"));
}

// NIP-44's padding hides the exact length of short messages by
// rounding it up to a power-of-two-derived boundary. Everything
// this file sends is short and fixed in shape, so in practice the
// padding is doing nothing here, but a payload that skipped it
// would not be a NIP-44 payload.
function paddedLength(len) {
  if (len <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
}

function pad(plaintext) {
  const bytes = enc.encode(plaintext);
  if (bytes.length < 1 || bytes.length > 65535) {
    throw new Error("nip44: plaintext out of range");
  }
  const padded = new Uint8Array(2 + paddedLength(bytes.length));
  padded[0] = (bytes.length >> 8) & 0xff;
  padded[1] = bytes.length & 0xff;
  padded.set(bytes, 2);
  return padded;
}

function unpad(padded) {
  const len = (padded[0] << 8) | padded[1];
  const text = padded.slice(2, 2 + len);
  if (len < 1 || text.length !== len || padded.length !== 2 + paddedLength(len)) {
    throw new Error("nip44: bad padding");
  }
  return new TextDecoder().decode(text);
}

function messageKeys(convKey, nonce) {
  const keys = KF.expand(KF.sha256, convKey, nonce, 76);
  return {
    chachaKey: keys.slice(0, 32),
    chachaNonce: keys.slice(32, 44),
    hmacKey: keys.slice(44, 76),
  };
}

function nip44Encrypt(plaintext, convKey, nonce) {
  const n = nonce || S.utils.randomBytes(32);
  const k = messageKeys(convKey, n);
  const ciphertext = KF.chacha20(k.chachaKey, k.chachaNonce, pad(plaintext));
  const mac = KF.hmac(KF.sha256, k.hmacKey, concat(n, ciphertext));
  return b64encode(concat(new Uint8Array([2]), n, ciphertext, mac));
}

function nip44Decrypt(payload, convKey) {
  if (typeof payload !== "string" || payload.length < 132 || payload[0] === "#") {
    throw new Error("nip44: unreadable payload");
  }
  const bytes = b64decode(payload);
  if (bytes[0] !== 2) throw new Error("nip44: unknown version");
  const nonce = bytes.slice(1, 33);
  const ciphertext = bytes.slice(33, bytes.length - 32);
  const mac = bytes.slice(bytes.length - 32);
  const k = messageKeys(convKey, nonce);
  const expected = KF.hmac(KF.sha256, k.hmacKey, concat(nonce, ciphertext));
  // The MAC is what makes this authenticated rather than merely
  // scrambled, so it is checked before the plaintext is looked at.
  if (toHex(expected) !== toHex(mac)) throw new Error("nip44: bad mac");
  return unpad(KF.chacha20(k.chachaKey, k.chachaNonce, ciphertext));
}

/* ============================================================
   events, signed by a burner

   app.js signs with whatever holds this device's identity. Not
   one event in this file is signed by that key: a transfer is
   carried entirely by keys that exist for one session, which is
   what keeps a relay from learning who is pairing with whom.
   ============================================================ */
function serialize(ev) {
  return JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
}

async function eventId(ev) {
  return toHex(await S.utils.sha256(enc.encode(serialize(ev))));
}

async function signWith(privkey, partial) {
  const ev = {
    pubkey: toHex(S.schnorr.getPublicKey(privkey)),
    created_at: partial.created_at ?? nowSeconds(),
    kind: partial.kind,
    tags: partial.tags || [],
    content: partial.content || "",
  };
  ev.id = await eventId(ev);
  ev.sig = toHex(await S.schnorr.sign(ev.id, privkey));
  return ev;
}

function newBurner() {
  const priv = S.utils.randomPrivateKey();
  return { priv, pub: toHex(S.schnorr.getPublicKey(priv)) };
}

// NIP-59 asks for a timestamp somewhere in the last two days so
// that the moment a wrap was made is not written on the outside of
// it. It is also the reason for two other rules in this file: the
// expiration below is computed from the real clock rather than
// from this, and a subscription has to reach two days back or it
// sees nothing.
function randomizedCreatedAt() {
  return nowSeconds() - Math.floor(Math.random() * SINCE_BACKDATE);
}

/* ---------- NIP-59: rumor, seal, wrap ---------- */

// The rumor is the message itself and is never signed: an unsigned
// event cannot be shown to anyone as proof that its author sent it,
// which is the property NIP-59 is after.
async function makeRumor(senderPub, kind, tags, content) {
  const rumor = {
    pubkey: senderPub,
    created_at: nowSeconds(),
    kind,
    tags,
    content: content || "",
  };
  rumor.id = await eventId(rumor);
  return rumor;
}

async function wrapRumor(rumor, senderPriv, recipientPubHex) {
  const seal = await signWith(senderPriv, {
    kind: KINDS.SEAL,
    created_at: randomizedCreatedAt(),
    tags: [],
    content: nip44Encrypt(JSON.stringify(rumor), conversationKey(senderPriv, recipientPubHex)),
  });
  const onetime = S.utils.randomPrivateKey();
  const wrap = await signWith(onetime, {
    kind: KINDS.GIFT_WRAP,
    created_at: randomizedCreatedAt(),
    tags: [
      ["p", recipientPubHex],
      // Wall-clock now plus ten minutes, and deliberately not the
      // wrap's own created_at, which the line above may have put
      // two days in the past. A relay reading NIP-40 off that
      // would drop the wrap before it was ever delivered.
      ["expiration", String(nowSeconds() + WRAP_EXPIRY_SECONDS)],
    ],
    content: nip44Encrypt(JSON.stringify(seal), conversationKey(onetime, recipientPubHex)),
  });
  wipe(onetime);
  return wrap;
}

// Returns the rumor and the key that sealed it, because the two
// have to be compared: a rumor names its own burner in a tag, and
// a rumor whose tag disagrees with the key that sealed it is
// somebody replaying somebody else's message under their own seal.
async function unwrap(wrapEvent, recipientPriv) {
  const sealJson = nip44Decrypt(wrapEvent.content, conversationKey(recipientPriv, wrapEvent.pubkey));
  const seal = JSON.parse(sealJson);
  if (seal.kind !== KINDS.SEAL) throw new Error("keyxfer: wrap did not hold a seal");
  if (!(await verifyEvent(seal))) throw new Error("keyxfer: seal signature does not check out");
  const rumorJson = nip44Decrypt(seal.content, conversationKey(recipientPriv, seal.pubkey));
  const rumor = JSON.parse(rumorJson);
  return { rumor, sealSigner: seal.pubkey };
}

async function verifyEvent(ev) {
  try {
    if (await eventId(ev) !== ev.id) return false;
    return await S.schnorr.verify(ev.sig, ev.id, ev.pubkey);
  } catch (err) {
    return false;
  }
}

// The `nostr-nsec` profile's P4 check. A scalar of zero or one at
// or above the curve order is not a key, and noble refuses to
// derive from it, so the derivation is the check.
function validPrivkeyHex(hex) {
  if (!/^[0-9a-f]{64}$/.test(hex)) return false;
  try {
    S.schnorr.getPublicKey(fromHex(hex));
    return true;
  } catch (err) {
    return false;
  }
}

function tagValue(tags, name) {
  for (const t of tags || []) if (t[0] === name) return t[1];
  return undefined;
}

/* ============================================================
   the short code (qrst §6)

   Five digits, derived from the profile, both burners and both
   random nonces. The device that made contact commits to its nonce
   before it learns the other's, which is what stops somebody in
   the middle from picking a nonce that makes two different codes
   match: they have to commit to a value before they can see what
   it must match, and each session gives them exactly one guess.

   Five, and not six or four, because no secret anybody holds is
   five digits long. A bank PIN is four and a message code is six,
   so a five-position field matches nothing a person could be
   phished into reaching for.
   ============================================================ */
async function sasCommit(contactingPubHex, nonce) {
  return toHex(await S.utils.sha256(concat(
    enc.encode("qrst-commit-v1"), fromHex(contactingPubHex), nonce)));
}

// The order is the two roles, holder first, and never the order
// the two messages happened to arrive in. The contacting device
// is the holder in flow A and the joiner in flow B, so a version
// of this that hashed "me then them" would agree with itself and
// with nothing else.
//
// The profile goes in first, length-prefixed, so that two devices
// which disagree about what kind of secret is moving cannot arrive
// at the same number — the agreement about that is part of what
// the person checks rather than something checked afterwards.
async function sasCode(holderPubHex, joinerPubHex, nonceHolder, nonceJoiner) {
  const profile = enc.encode(PROFILE);
  const code = await S.utils.sha256(concat(
    enc.encode("qrst-sas-v1"),
    new Uint8Array([profile.length]), profile,
    fromHex(holderPubHex), fromHex(joinerPubHex),
    nonceHolder, nonceJoiner));
  // Five bytes rather than four, so that reducing them to five
  // digits leaves a bias too small to be worth a sentence.
  const n = code[0] * 4294967296 + (((code[1] << 24) | (code[2] << 16) |
    (code[3] << 8) | code[4]) >>> 0);
  const digits = String(n % 100000).padStart(5, "0");
  return { digits, hex: toHex(code) };
}

/* ============================================================
   the QR (qrst §11.2)
   ============================================================ */
const SCHEME = "qrst://";

function buildUri(params) {
  const npub = KF.bech32.encode("npub", KF.bech32.toWords(fromHex(params.burner)), 5000);
  const q = new URLSearchParams();
  q.set("v", VERSION);
  q.set("mode", params.mode);
  // Required, and required even though hearth has exactly one:
  // it is hashed into the code the two devices compare, so a field
  // that is sometimes absent is two implementations disagreeing
  // about how to hash nothing.
  q.set("p", PROFILE);
  for (const relay of params.relays) q.append("relay", relay);
  q.set("plat", "web");
  // Required for plat=web, and the reason the other device's
  // consent prompt can name a host at all.
  q.set("origin", params.origin);
  return SCHEME + npub + "?" + q.toString();
}

function parseUri(text) {
  if (typeof text !== "string" || !text.startsWith(SCHEME)) {
    throw new Error("that code isn't a device code");
  }
  const rest = text.slice(SCHEME.length);
  const cut = rest.indexOf("?");
  const npub = cut === -1 ? rest : rest.slice(0, cut);
  const q = new URLSearchParams(cut === -1 ? "" : rest.slice(cut + 1));
  // A client must refuse a version it does not know, a code that
  // says nothing about which way the key is meant to travel, and a
  // code naming a kind of secret it cannot handle — the last one
  // before a burner exists, rather than at the end of a ceremony
  // somebody has already sat through.
  if (q.get("v") !== VERSION) throw new Error("that code comes from a newer version of hearth");
  const mode = q.get("mode");
  if (mode !== "offer" && mode !== "request") {
    throw new Error("that code doesn't say which device holds the key");
  }
  const profile = q.get("p");
  if (!profile) throw new Error("that code doesn't say what it's offering to move");
  if (profile !== PROFILE) {
    throw new Error("that code is moving something hearth doesn't handle (" + profile + ")");
  }
  const decoded = KF.bech32.decode(npub, 5000);
  if (decoded.prefix !== "npub") throw new Error("that code isn't a device code");
  const burner = toHex(Uint8Array.from(KF.bech32.fromWords(decoded.words)));
  if (burner.length !== 64) throw new Error("that code isn't a device code");
  const relays = q.getAll("relay").slice(0, 4);
  return {
    burner,
    mode,
    profile,
    relays: relays.length > 0 ? relays : DEFAULT_RELAYS.slice(),
    plat: q.get("plat") || null,
    origin: q.get("origin") || null,
  };
}

// Punycode where a host has non-ASCII in it, so that a domain
// built out of letters that look like other letters reads on the
// consent prompt as the address it actually is (§4).
function displayOrigin(origin) {
  if (!origin) return null;
  try {
    const url = new URL("https://" + origin);
    return url.hostname;
  } catch (err) {
    return origin;
  }
}

/* ============================================================
   relays

   One socket per relay, all of them subscribed to the same
   burner and all of them published to. A relay that refuses the
   publish is simply one that did not carry it; the others did.
   ============================================================ */
function relayPool(urls, burner, onEvent, onHealth) {
  const sockets = new Map();
  const seen = new Set();
  // Everything this session has published, kept so that a relay
  // whose socket opened late, or which asked for authentication
  // first, still receives the messages that went out before it was
  // ready. A session publishes a handful of small events, and a
  // relay seeing one twice discards the duplicate by id.
  const outbox = [];
  // One row per relay, for the whole life of the session: what it is
  // doing now, how many times it has been tried, how long it took to
  // open when it did, and what it said when it stopped. This is the
  // record to read when somebody reports that a transfer would not
  // start, because "no relay could be reached" on its own says
  // nothing about which one was slow or why.
  const health = new Map();
  const startedAt = Date.now();
  let closed = false;

  for (const url of urls.slice(0, 4)) {
    health.set(url, {
      status: "connecting", attempts: 0, openMs: null,
      subscribed: false, lastReason: null, retryInMs: null,
    });
  }

  function summary() {
    let live = 0;
    for (const row of health.values()) if (row.status === "open") live++;
    return {
      live,
      total: health.size,
      elapsedMs: Date.now() - startedAt,
      relays: Array.from(health, ([url, row]) => Object.assign({ url }, row)),
    };
  }

  function note(url, change) {
    const row = health.get(url);
    if (!row) return;
    Object.assign(row, change);
    // Logged as it happens rather than summarised at the end,
    // because the interesting case is the one where nothing ever
    // finishes and there is no end to summarise.
    console.info("hearth: transfer relay", url, row.status,
      row.openMs !== null ? row.openMs + "ms" : "",
      row.lastReason || "", "attempt " + row.attempts);
    if (onHealth) onHealth(summary());
  }

  function subscribe(ws) {
    ws.send(JSON.stringify(["REQ", "kx", {
      kinds: [KINDS.GIFT_WRAP],
      "#p": [burner.pub],
      // Two days back, because a wrap's created_at is randomised
      // that far into the past. A subscription starting now is a
      // subscription that receives nothing and looks like a
      // relay that has stopped answering.
      since: nowSeconds() - SINCE_BACKDATE,
    }]));
  }

  function flush(ws) {
    for (const event of outbox) {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(["EVENT", event]));
    }
  }

  // A relay is tried again for as long as the session is alive. The
  // first attempt on a cold connection is the slow one — Safari
  // opening a first socket to a public relay can take longer than
  // anybody would guess — and the second is usually immediate, so
  // giving up on the first would be giving up on the case this most
  // needs to handle. Backoff so a relay that is genuinely down is
  // not hammered for ten minutes.
  function retry(url, reason) {
    if (closed) return;
    const row = health.get(url);
    const delay = Math.min(8000, 1000 * Math.pow(2, Math.min(row.attempts - 1, 3)))
      + Math.floor(Math.random() * 400);
    note(url, { status: "waiting", lastReason: reason, retryInMs: delay, subscribed: false });
    setTimeout(() => connect(url), delay);
  }

  function connect(url) {
    if (closed) return;
    const row = health.get(url);
    row.attempts++;
    const began = Date.now();
    let ws;
    let authId = null;
    // Fires once per socket: an error and a close both arrive for
    // one failure, and scheduling two retries would double the
    // attempts every round.
    let settled = false;

    try {
      ws = new WebSocket(url);
    } catch (err) {
      note(url, { status: "connecting", retryInMs: null });
      retry(url, err.message || "would not open");
      return;
    }
    sockets.set(url, ws);
    note(url, { status: "connecting", retryInMs: null, lastReason: null });

    ws.addEventListener("open", () => {
      if (closed) { try { ws.close(); } catch (e) {} return; }
      note(url, { status: "open", openMs: Date.now() - began, lastReason: null });
      subscribe(ws);
      flush(ws);
    });

    ws.addEventListener("message", async (evt) => {
      let frame;
      try { frame = JSON.parse(evt.data); } catch (e) { return; }
      if (frame[0] === "EVENT" && frame[1] === "kx") {
        const event = frame[2];
        // The same wrap arriving from three relays is one wrap.
        if (seen.has(event.id)) return;
        seen.add(event.id);
        onEvent(event);
        return;
      }
      if (frame[0] === "EOSE" && frame[1] === "kx") {
        note(url, { subscribed: true });
        return;
      }
      if (frame[0] === "CLOSED" && frame[1] === "kx") {
        // The socket is still up; it is the subscription that is
        // not, which is worth knowing apart from a dead connection.
        note(url, { subscribed: false, lastReason: "subscription refused: " + (frame[2] || "") });
        return;
      }
      if (frame[0] === "AUTH") {
        // Signed by the burner, never by this device's identity:
        // the wrap is addressed to the burner, which is what an
        // auth-gated relay wants to see, and it tells the relay
        // nothing it did not already know.
        const auth = await signWith(burner.priv, {
          kind: KINDS.CLIENT_AUTH,
          tags: [["relay", url], ["challenge", frame[1]]],
        });
        authId = auth.id;
        ws.send(JSON.stringify(["AUTH", auth]));
        return;
      }
      if (frame[0] === "OK" && frame[1] === authId && frame[2]) {
        // Authenticated now, so anything this relay refused before
        // it asked goes again, and the subscription it closed is
        // reopened.
        note(url, { lastReason: null });
        subscribe(ws);
        flush(ws);
        return;
      }
    });

    ws.addEventListener("close", (evt) => {
      if (sockets.get(url) === ws) sockets.delete(url);
      if (settled) return;
      settled = true;
      retry(url, "closed" + (evt && evt.code ? " (" + evt.code + ")" : ""));
    });

    ws.addEventListener("error", () => {
      if (settled) return;
      settled = true;
      retry(url, "connection failed");
    });
  }

  for (const url of health.keys()) connect(url);

  return {
    publish(event) {
      outbox.push(event);
      const frame = JSON.stringify(["EVENT", event]);
      let sent = 0;
      for (const ws of sockets.values()) {
        if (ws.readyState === WebSocket.OPEN) { ws.send(frame); sent++; }
      }
      // Nought here is a socket that has not finished opening
      // rather than a failure: the flush above sends it the moment
      // one does, and a relay still being retried will get it when
      // it comes up.
      return sent;
    },
    summary,
    close() {
      closed = true;
      for (const ws of sockets.values()) { try { ws.close(); } catch (e) {} }
      sockets.clear();
    },
  };
}

/* §3.1 and what a browser can do about it.

   The specification probes for a transport before showing any
   transfer screen, and picks between relays, the local network and
   an off-grid code from what comes back. A browser has none of that
   choice: it cannot do the local path in either role, and it cannot
   be the off-grid holder either, so the only two outcomes a probe
   can produce here are "relays" and "nothing at all" — and there is
   no behaviour behind the second one.

   A one-shot probe with a three-second timeout therefore decided the
   fate of a session the specification gives ten minutes, and decided
   it against exactly the case that most needs handling: a first,
   cold WebSocket to a public relay, which Safari can take longer
   over than any timeout worth setting. So there is no probe. The
   pool above starts connecting the moment a session does and keeps
   at it for as long as the session lives, the flow proceeds as soon
   as one relay is up, and how it is getting on is something the
   screen reports rather than something the session rules on. */

/* ============================================================
   a session

   One transfer attempt, ten minutes, one burner. The caller hands
   in what it is (holder or joiner, showing the code or scanning
   one) and a place to send screen updates, and drives it with
   four decisions: approve, deny, choose, accept.
   ============================================================ */
function startSession(opts) {
  const role = opts.role;                   // "holder" | "joiner"
  const showing = !!opts.showing;           // does this device draw the QR
  // Flow A is the joiner showing (§7); flow B is the holder
  // showing (§8). Which one this is decides who commits first,
  // and getting that backwards makes two honest devices show
  // different codes.
  const flow = (role === "joiner") === showing ? "A" : "B";
  const contacting = !showing;              // the device that scanned made contact
  const emit = opts.on || function () {};

  const burner = newBurner();
  const startedAt = nowSeconds();
  const peers = new Map();                  // their burner hex -> peer state
  let ownNonce = null;
  let ownCommit = null;
  let awaitingConsent = null;
  let everLive = false;
  let pool = null;
  let finished = false;
  let multiSeen = false;
  let scanned = opts.scanned || null;       // what the QR said, when we scanned one
  const relays = (scanned ? scanned.relays : (opts.relays || DEFAULT_RELAYS)).slice(0, 4);

  const sessionTimer = setTimeout(() => stop("expired"), SESSION_SECONDS * 1000);
  let zeroizeTimer = null;

  function peerFor(pubHex) {
    let peer = peers.get(pubHex);
    if (!peer) {
      peer = { burner: pubHex, nonce: null, theirNonce: null, commit: null, sas: null, held: null };
      peers.set(pubHex, peer);
    }
    return peer;
  }

  // §13. Counted on the device that showed the code, because that
  // is the code somebody else may have pointed a camera at. The
  // session carries on: the code on the two screens is what
  // settles which of them is real, and this is a notice rather
  // than a refusal.
  function noteResponder() {
    if (!showing || multiSeen || peers.size < 2) return;
    multiSeen = true;
    emit("multi");
  }

  // Nothing here treats "no socket was open at this instant" as a
  // failure. The pool keeps what it was given and sends it to each
  // relay as that relay finishes connecting, which is the ordinary
  // case for the first message of a session: it is composed the
  // moment the QR is scanned, and the sockets are still opening.
  async function send(kind, tags, content, toPubHex) {
    const rumor = await makeRumor(burner.pub, kind, tags.concat([["v", VERSION]]), content);
    const wrap = await wrapRumor(rumor, burner.priv, toPubHex);
    return pool ? pool.publish(wrap) : 0;
  }

  // Everything a rumor has to satisfy before it is looked at as a
  // message rather than as bytes somebody sent.
  function admissible(rumor, sealSigner) {
    // §11.4: all three of the rumor's own pubkey, the burner it
    // names in a tag and the key that sealed it are one key, or
    // somebody is forwarding a message that was not theirs.
    if (tagValue(rumor.tags, "burner") !== sealSigner) return false;
    if (rumor.pubkey !== sealSigner) return false;
    // §13: a rumor whose own created_at is outside this session
    // is discarded here and not anywhere later, so that a
    // backdated timestamp cannot buy its sender a quiet arrival
    // that skips the notice above.
    const at = rumor.created_at;
    if (typeof at !== "number") return false;
    if (at < startedAt - CLOCK_SLACK) return false;
    if (at > startedAt + SESSION_SECONDS + CLOCK_SLACK) return false;
    return true;
  }

  async function onWrap(wrapEvent) {
    if (finished) return;
    let opened;
    try {
      opened = await unwrap(wrapEvent, burner.priv);
    } catch (err) {
      // A wrap that will not open is not a responder (§13). It is
      // most likely addressed to somebody else on a relay that
      // does not filter as tightly as it claims.
      return;
    }
    const { rumor, sealSigner } = opened;
    if (!admissible(rumor, sealSigner)) return;
    // When this device scanned a QR it is talking to exactly one
    // burner, the one the QR named, and anything else is noise.
    if (scanned && sealSigner !== scanned.burner) return;
    try {
      await handleRumor(rumor, sealSigner);
    } catch (err) {
      emit("error", err.message);
    }
  }

  async function handleRumor(rumor, from) {
    /* ---- the contacting device's opening message ---- */
    if (rumor.kind === KINDS.HELLO || rumor.kind === KINDS.REQUEST) {
      const expected = flow === "A" ? KINDS.HELLO : KINDS.REQUEST;
      if (rumor.kind !== expected || contacting) return;
      const existing = peers.get(from);
      // A retransmission from a burner already answered is the
      // same responder, not a second one (§13).
      if (existing && existing.commit) return;
      // §8: at most five pending requests in a session, so a
      // flooder costs the person a handful of taps rather than an
      // unbounded queue.
      if (peers.size >= MAX_PENDING) { noteResponder(); return; }
      const commit = tagValue(rumor.tags, "commit");
      if (!commit) return;
      const peer = peerFor(from);
      peer.commit = commit;
      peer.nonce = S.utils.randomBytes(32);
      noteResponder();
      await send(KINDS.NONCE, [["burner", burner.pub], ["nonce", toHex(peer.nonce)]], "", from);
      return;
    }

    /* ---- the other device's nonce, answering our commit ---- */
    if (rumor.kind === KINDS.NONCE) {
      if (!contacting) return;
      const peer = peerFor(from);
      if (peer.theirNonce) return;
      const nonce = tagValue(rumor.tags, "nonce");
      if (!nonce || nonce.length !== 64) return;
      peer.theirNonce = fromHex(nonce);
      await send(KINDS.REVEAL, [["burner", burner.pub], ["nonce", toHex(ownNonce)]], "", from);
      await settleSas(peer);
      return;
    }

    /* ---- the contacting device opening its commit ---- */
    if (rumor.kind === KINDS.REVEAL) {
      if (contacting) return;
      const peer = peers.get(from);
      if (!peer || !peer.commit || peer.theirNonce) return;
      const nonce = tagValue(rumor.tags, "nonce");
      if (!nonce || nonce.length !== 64) return;
      // The whole point of the commitment: the nonce revealed now
      // has to be the nonce promised before ours was sent.
      const check = await sasCommit(from, fromHex(nonce));
      if (check !== peer.commit) return;
      peer.theirNonce = fromHex(nonce);
      await settleSas(peer);
      return;
    }

    /* ---- the key itself ---- */
    if (rumor.kind === KINDS.PAYLOAD) {
      if (role !== "joiner") return;
      const peer = peers.get(from);
      // Only from a burner this device is already exchanging
      // nonces with. A key from a burner that never did is one
      // nobody asked for.
      if (!peer || !peer.nonce && !peer.theirNonce) return;
      const hex = (rumor.content || "").trim().toLowerCase();
      // The profile's P4 check: sixty-four hex characters that are
      // a scalar in range and give a usable public key. Anything
      // else is not a key and is not held as though it might be.
      if (!validPrivkeyHex(hex)) return;
      // Held, not stored. Nothing is written until the person has
      // picked the code their other device is showing and agreed
      // to the identity that came with it: without that, whoever
      // photographed the QR could race the real holder and put
      // their own key on this device.
      peer.held = { hex, lock: tagValue(rumor.tags, "lock") || "device" };
      maybeArrived(peer);
      return;
    }

    /* ---- anything else this file does not speak ---- */
    // A client may carry its own messages inside a session it has
    // already established — this file has no opinion on what, and
    // hands them up rather than dropping them. Only ever from a
    // burner already talking to us, and only after the same checks
    // every other rumor passes.
    if (!KNOWN_KINDS.has(rumor.kind)) {
      if (peers.has(from)) {
        emit("rumor", { kind: rumor.kind, tags: rumor.tags, content: rumor.content, from });
      }
      return;
    }

    /* ---- the receipt that lets a holder let go ---- */
    if (rumor.kind === KINDS.ACK) {
      if (role !== "holder") return;
      const peer = peers.get(from);
      if (!peer || !peer.sent) return;
      stop("done");
      return;
    }
  }

  // Both nonces are in, so both devices can work out the same five
  // figures. What happens next is the only thing the two roles do
  // differently at this point: a holder is asked to release the
  // key, a joiner is told what to show.
  async function settleSas(peer) {
    // Role order, holder first, whichever of the two this device
    // happens to be and whichever message arrived first. Our own
    // nonce is the one we committed to if we made contact, and the
    // one generated for this peer if we did not.
    const mine = contacting ? ownNonce : peer.nonce;
    const theirs = peer.theirNonce;
    const holderPub = role === "holder" ? burner.pub : peer.burner;
    const joinerPub = role === "joiner" ? burner.pub : peer.burner;
    const nonceHolder = role === "holder" ? mine : theirs;
    const nonceJoiner = role === "joiner" ? mine : theirs;
    peer.sas = await sasCode(holderPub, joinerPub, nonceHolder, nonceJoiner);
    if (role === "holder") {
      askConsent(peer);
    } else {
      emit("sas", { list: sasList(), single: !!scanned });
      maybeArrived(peer);
    }
  }

  // §8: one at a time. A second device asking while the person is
  // reading the first prompt waits its turn rather than replacing
  // what is on screen under their thumb.
  function askConsent(peer) {
    if (awaitingConsent && peers.has(awaitingConsent)) return;
    awaitingConsent = peer.burner;
    emit("consent", {
      peer: peer.burner,
      sas: peer.sas,
      plat: scanned ? scanned.plat : null,
      origin: scanned ? displayOrigin(scanned.origin) : null,
    });
  }

  // A wrap carrying the key and the code that says whose it is can
  // arrive in either order, since they travel as separate events
  // over as many as four relays. The screen is told only once both
  // are in hand.
  function maybeArrived(peer) {
    if (!peer.held || !peer.sas || peer.announced) return;
    peer.announced = true;
    emit("arrived", { peer: peer.burner, sas: peer.sas, single: !!scanned });
  }

  // §9: the three most recent, newest first, so a person
  // whose code was scanned by somebody else still has a short list
  // to find their own device in rather than a long one.
  function sasList() {
    const out = [];
    for (const peer of peers.values()) if (peer.sas) out.push({ peer: peer.burner, sas: peer.sas });
    return out.reverse().slice(0, SAS_LIST_MAX);
  }

  function stop(reason, detail) {
    if (finished) return;
    finished = true;
    clearTimeout(sessionTimer);
    clearTimeout(zeroizeTimer);
    if (pool) pool.close();
    for (const peer of peers.values()) {
      if (peer.held) peer.held.hex = "";
      wipe(peer.nonce);
    }
    wipe(burner.priv);
    wipe(ownNonce);
    emit(reason, detail);
  }

  /* ---- what the screen can ask of a session ---- */
  const session = {
    flow,
    role,
    burner: burner.pub,
    uri: null,

    // Holder, both flows: release the key to this peer. Reached
    // only from a deliberate tap on the device that holds it.
    async approve(peerHex, privkeyHex, lock) {
      const peer = peers.get(peerHex);
      if (!peer || !peer.sas || finished) return;
      peer.sent = true;
      await send(KINDS.PAYLOAD,
        [["burner", burner.pub], ["lock", lock || "device"]], privkeyHex, peerHex);
      emit("sent", { peer: peerHex, sas: peer.sas });
      // §7 step 18 and §8 step 18: the burner goes when the other
      // device says it has the key, or a minute later regardless.
      // A joiner that never acknowledges is one that never
      // stored it, and holding a burner open past that is holding
      // a channel open for nobody.
      zeroizeTimer = setTimeout(() => stop("done"), ZEROIZE_AFTER_MS);
    },

    // Holder, flow B: this request is not mine. The session goes
    // back to waiting, or on to the next request queued behind it.
    deny(peerHex) {
      const peer = peers.get(peerHex);
      if (peer) { peer.denied = true; peers.delete(peerHex); }
      if (awaitingConsent === peerHex) awaitingConsent = null;
      const next = nextPending();
      // §8 step 13: a denial moves on to whoever else is waiting,
      // or back to waiting. It does not end the session, because
      // the person the user is actually adding may be the next one
      // in the queue.
      if (next) askConsent(next);
      else emit("waiting");
    },

    // Joiner, flow A: the code this device is showing matched the
    // one on the other screen, so this is the wrap to open.
    chosen(peerHex) {
      const peer = peers.get(peerHex);
      if (!peer || !peer.held) return null;
      return { pubkey: toHex(S.schnorr.getPublicKey(fromHex(peer.held.hex))), peer: peerHex };
    },

    // Joiner: the identity is the right one, so keep it. Every
    // other pending wrap is dropped unopened.
    async accept(peerHex) {
      const peer = peers.get(peerHex);
      if (!peer || !peer.held || finished) return null;
      const held = peer.held;
      const record = {
        privkeyHex: held.hex,
        lock: held.lock,
        sas: peer.sas,
        peer: peerHex,
        multi: multiSeen,
      };
      await send(KINDS.ACK, [["burner", burner.pub]], "", peerHex);
      // A moment for the acknowledgement to reach a relay before
      // the sockets are closed under it; the holder's own minute
      // covers it either way.
      setTimeout(() => stop("done"), 400);
      return record;
    },

    // The caller's own message, to a burner this session is already
    // talking to. Same seal, same wrap, same session; this file does
    // not look inside it.
    //
    // The burner tag is added here rather than asked of the caller.
    // Every rumor carries it and the far side discards any that does
    // not, so leaving it to a caller that has no reason to know the
    // rule would be a message that vanishes with no error anywhere.
    async sendTo(peerHex, kind, tags, content) {
      if (!peers.has(peerHex) || finished) return 0;
      return await send(kind, [["burner", burner.pub]].concat(tags || []), content, peerHex);
    },

    cancel() { stop("cancelled"); },
    peers() { return sasList(); },

    // How each relay is getting on, for a screen that wants to say
    // so and for anybody reading a report of a transfer that would
    // not start.
    transport() { return pool ? pool.summary() : null; },
  };

  function nextPending() {
    for (const peer of peers.values()) if (peer.sas && !peer.denied && !peer.sent) return peer;
    return null;
  }

  // Getting started: a burner, a subscription, and either a QR to
  // draw or a first message to send.
  (async function begin() {
    pool = relayPool(relays, burner, onWrap, (health) => {
      if (health.live > 0 && !everLive) {
        everLive = true;
        emit("connected", health);
      }
      emit("transport", health);
    });

    if (showing) {
      session.uri = buildUri({
        burner: burner.pub,
        mode: role === "joiner" ? "offer" : "request",
        relays,
        origin: global.location ? global.location.host : "",
      });
      emit("qr", session.uri);
      return;
    }

    // The scanning device is the one that made contact, so it is
    // the one that commits to a nonce before it can see the
    // other's.
    ownNonce = S.utils.randomBytes(32);
    ownCommit = await sasCommit(burner.pub, ownNonce);
    const kind = flow === "A" ? KINDS.HELLO : KINDS.REQUEST;
    // The profile's REQUEST also carries an `enroll` tag naming a
    // threshold enrolment key. Hearth has no threshold signing and
    // so has no such key, and a tag naming a key that does not
    // exist would be worse than an absent one.
    peerFor(scanned.burner);
    await send(kind, [["burner", burner.pub], ["commit", ownCommit]], "", scanned.burner);
    emit("sent-hello");
  })();

  return session;
}

global.Keyxfer = {
  PROFILE,
  DEFAULT_RELAYS,
  KINDS,
  SESSION_SECONDS,
  // The pieces below are exported for the vector checker, which
  // has to be able to reach every step the specification pins a
  // known answer to.
  nip44Encrypt,
  nip44Decrypt,
  conversationKey,
  paddedLength,
  sasCommit,
  sasCode,
  wrapRumor,
  unwrap,
  makeRumor,
  signWith,
  buildUri,
  parseUri,
  displayOrigin,
  startSession,
  toHex,
  fromHex,
};

})(typeof window !== "undefined" ? window : globalThis);
