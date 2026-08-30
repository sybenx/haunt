/* ============================================================
   hearth — talks to one bothy relay, in one group, with chat, a
   voice call, and the way in: invite links the owner mints inside
   the app, redeemed on arrival. One group conversation, one group
   call; private conversations and their private calls come later.
   No QR device pairing, no video, no screen share yet. Event
   kinds live in kinds.js.
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
const KF = window.NobleKeyFormats;

/* ---------- elements ---------- */
const stageEl = document.getElementById("stage");
const mainEl = document.getElementById("main");
const pillSlotEl = document.getElementById("pillSlot");
const tbNameEl = document.getElementById("tbName");
const tbStatusEl = document.getElementById("tbStatus");
const vpNameEl = document.getElementById("vpName");
const vpStatusEl = document.getElementById("vpStatus");
const accountBtn = document.getElementById("accountBtn");
const signInOfferEl = document.getElementById("signInOffer");
const signInExtBtn = document.getElementById("signInExt");
const signInNewBtn = document.getElementById("signInNew");
const signInFailEl = document.getElementById("signInFail");
const relaySetup = document.getElementById("relaySetup");
const relayInput = document.getElementById("relayInput");
const relayConnect = document.getElementById("relayConnect");
const scrollEl = document.getElementById("scroll");
const msgsEl = document.getElementById("msgs");
const composerEl = document.getElementById("composer");
const composerGhostEl = document.getElementById("composerGhost");
const msgInput = document.getElementById("msgInput");
const devWarnEl = document.getElementById("devWarn");
const callWarnEl = document.getElementById("callWarn");
const joinRefusedEl = document.getElementById("joinRefused");
const joinRefusedMsgEl = document.getElementById("joinRefusedMsg");
const namePromptEl = document.getElementById("namePrompt");
const nameInput = document.getElementById("nameInput");
const nameSubmitBtn = document.getElementById("nameSubmit");
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
const micLabelEl = document.getElementById("micLabel");
const micHintEl = document.getElementById("micHint");
const leaveBtn = document.getElementById("leaveBtn");
const mutePillEl = document.getElementById("mutePill");
const mutePillLabelEl = document.getElementById("mutePillLabel");
const jumpChipEl = document.getElementById("jumpChip");
const accountOverlayEl = document.getElementById("accountOverlay");
const accountCloseBtn = document.getElementById("accountClose");
const aoAvatarEl = document.getElementById("aoAvatar");
const aoNameEl = document.getElementById("aoName");
const aoNameInput = document.getElementById("aoNameInput");
const aoNameSaveBtn = document.getElementById("aoNameSave");
const aoPubkeyEl = document.getElementById("aoPubkey");
const aoCopyKeyBtn = document.getElementById("aoCopyKey");
const aoRelaysEl = document.getElementById("aoRelays");
const aoInvitesEl = document.getElementById("aoInvites");
const aoKeyNoteEl = document.getElementById("aoKeyNote");
const aoExtBtn = document.getElementById("aoExtBtn");
const aoImportInput = document.getElementById("aoImportInput");
const aoImportBtn = document.getElementById("aoImportBtn");
const aoPassRow = document.getElementById("aoPassRow");
const aoPassInput = document.getElementById("aoPassInput");
const aoImportFailEl = document.getElementById("aoImportFail");
const aoConfirmEl = document.getElementById("aoConfirm");
const aoConfirmTextEl = document.getElementById("aoConfirmText");
const aoConfirmYesBtn = document.getElementById("aoConfirmYes");
const aoConfirmNoBtn = document.getElementById("aoConfirmNo");

/* ============================================================
   identity

   An identity is a public key and a way to sign with it, acquired
   from the first source that has one. The sources are an ordered
   list because acquisition is a seam: today a key is found in
   storage, offered by a browser extension, or minted fresh, and
   later it will also arrive by transfer from a device the person
   already owns — that lands as one more entry in the list, not as
   a rewrite of the callers.

   Signing is the same kind of seam, which is why an identity
   carries a signEvent rather than a private key. A key held on
   this device is one way to answer that and not the only one: an
   extension signs without ever showing the page a key, and the
   key management this is heading toward has a device holding one
   share and signing through a round with a co-signer. Both of
   those fit behind signEvent and neither fits behind a privkey
   field, so nothing outside this section reads one.

   At rest the private key is ciphertext in IndexedDB, sealed
   under a non-extractable AES-GCM key stored beside it. Script
   on this origin can *use* the sealing key but can never read it
   out, so nothing that exfiltrates storage gets a usable key —
   which is as close to "the key never leaves this device" as a
   plain page without hardware keys can get. The key still can't
   be carried to a second device; QR pairing
   (reference/client-mobile.html) is what will do that.
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

async function loadSealedPrivkey() {
  const db = await idbOpen();
  const sealKey = await idbGet(db, "sealKey");
  const sealed = await idbGet(db, "privkey");
  db.close();
  if (!sealKey && !sealed) return null; // genuinely nothing — a fresh device
  if (!sealKey || !sealed) {
    // Half a store is corruption, not absence. Falling through as "no
    // identity yet" would mint a fresh key over the top and silently
    // replace whoever this device used to be — with no transfer and no
    // backup, that identity would simply be gone. Throw, and let init
    // stop the app with the reason showing.
    throw new Error(
      sealKey
        ? "the sealing key is present but the sealed private key is missing"
        : "a sealed private key is present but the key that seals it is missing"
    );
  }
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
  // Both records in one transaction, so the store is never observably
  // half-written: a tab closing between two separate writes would leave
  // a new sealing key beside old ciphertext, and the private key under
  // the old one would be unrecoverable.
  await new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, "readwrite");
    tx.objectStore(IDB_STORE).put(sealKey, "sealKey");
    tx.objectStore(IDB_STORE).put({ iv, ciphertext }, "privkey");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
  db.close();
}

// A key this device holds. holdsPrivateKey is what a caller is
// really asking when it reaches for a private key, and saying it on
// the signer is what keeps the answer honest: an identity that signs
// somewhere else can never be the device that hands a key over in a
// transfer, and there is nothing here for an export to export.
function localSigner(privkey) {
  return {
    pubkey: S.utils.bytesToHex(S.schnorr.getPublicKey(privkey)),
    kind: "device",
    holdsPrivateKey: true,
    privkey,
    async signEvent(ev) {
      const idBytes = await S.utils.sha256(new TextEncoder().encode(serializeEvent(ev)));
      ev.id = S.utils.bytesToHex(idBytes);
      ev.sig = S.utils.bytesToHex(await S.schnorr.sign(idBytes, privkey));
      return ev;
    },
  };
}

async function storedIdentitySource() {
  // Earlier builds kept the key as plaintext hex in localStorage.
  // Seal it properly and destroy the readable copy, once.
  const legacy = localStorage.getItem("hearth:privkey");
  if (legacy) {
    const privkey = S.utils.hexToBytes(legacy);
    await storeSealedPrivkey(privkey);
    localStorage.removeItem("hearth:privkey");
    return localSigner(privkey);
  }
  const privkey = await loadSealedPrivkey();
  return privkey ? localSigner(privkey) : null;
}

/* ------------------------------------------------------------
   a signing extension (NIP-07)

   Presence is the whole test. An extension is window.nostr and
   nothing else, and asking about the platform, the user agent or
   the size of the screen instead would wrongly hide this from the
   several browsers on Android that have one.

   Hearth asks it for two things: a public key, and a signature on
   each event. That is all hearth needs — what a group says is
   plaintext to the relay it is stored on, and voice signalling is
   plaintext ephemerals — so none of the encryption an extension
   also offers is asked for.
   ------------------------------------------------------------ */
const SIGNER_CHOICE_KEY = "hearth:signer";

function hasExtension() {
  const ext = window.nostr;
  return !!ext && typeof ext.getPublicKey === "function" && typeof ext.signEvent === "function";
}

// There is no private key in the page for this one, and that is a
// fact about where the key lives rather than a rule laid over the
// top: this identity can never be the device that hands a key to
// another in a transfer, and there is nothing here to export.
function extensionSigner(pubkey) {
  return {
    pubkey,
    kind: "extension",
    holdsPrivateKey: false,
    async signEvent(ev) {
      const signed = await window.nostr.signEvent(ev);
      // A signature under a different key would be refused by the
      // relay one event at a time, with nothing on screen saying why.
      if (!signed || !signed.id || !signed.sig) {
        throw new Error("your extension didn't return a signed event");
      }
      if (signed.pubkey !== pubkey) {
        throw new Error("your extension signed as a different identity than the one it gave");
      }
      return signed;
    },
  };
}

async function extensionIdentitySource() {
  if (localStorage.getItem(SIGNER_CHOICE_KEY) !== "extension") return null;
  if (!hasExtension()) {
    // Signed in with an extension that this browser no longer has.
    // Falling through to a key sealed on this device would quietly
    // sign this person in as somebody else, so it stops instead.
    throw new Error("this device signs in with a browser extension, and the extension isn't there");
  }
  return extensionSigner(await window.nostr.getPublicKey());
}

// Offered, never required and never the default. Somebody arriving on
// an invite link is joining as a new person in this group rather than
// as whoever they already are on nostr, so the offer stays out of
// that path entirely and the quiet mint happens as it always did.
async function offerExtensionSignIn() {
  if (!hasExtension()) return null;
  if (parseFragment().get("code")) return null;
  return new Promise((resolve) => {
    signInOfferEl.hidden = false;
    signInExtBtn.addEventListener("click", async () => {
      signInFailEl.hidden = true;
      signInExtBtn.disabled = true;
      try {
        const signer = extensionSigner(await window.nostr.getPublicKey());
        localStorage.setItem(SIGNER_CHOICE_KEY, "extension");
        signInOfferEl.hidden = true;
        resolve(signer);
      } catch (err) {
        signInExtBtn.disabled = false;
        signInFailEl.textContent = "your extension didn't hand over a public key. " +
          "You can try again, or carry on as somebody new.";
        signInFailEl.hidden = false;
      }
    });
    signInNewBtn.addEventListener("click", () => {
      signInOfferEl.hidden = true;
      resolve(null);
    });
  });
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
  return localSigner(S.utils.hexToBytes(hex));
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
// storage when it exists. The extension comes before storage because
// signing in with one is a deliberate choice this device made and a
// sealed key may well still be sitting behind it.
const identitySources = [devIdentitySource, extensionIdentitySource, storedIdentitySource];

// Minting is the fallthrough rather than a source: it is what happens
// when nobody has this person's key. It stays silent, and the one
// thing offered before it is a signing extension this browser already
// has — an offer, taken only by somebody who came to be who they
// already are.
async function acquireIdentity() {
  for (const source of identitySources) {
    const found = await source();
    if (found) return found;
  }
  const chosen = await offerExtensionSignIn();
  if (chosen) return chosen;
  const privkey = S.utils.randomPrivateKey();
  await storeSealedPrivkey(privkey);
  return localSigner(privkey);
}

/* ------------------------------------------------------------
   bringing an identity in

   An nsec and a NIP-49 ncryptsec are both bech32, and bech32's
   own length limit is 90 characters, which an ncryptsec exceeds
   at 162. The limit has to be raised explicitly or every one of
   them is thrown out as too long before it is even looked at.

   Whatever arrives here is stored exactly the way a minted key
   is stored: sealed in IndexedDB under a key this page can use
   but never read out. It does not go to localStorage and it is
   not kept anywhere a script can read it back.
   ------------------------------------------------------------ */
function decodeBech32(text) {
  const decoded = KF.bech32.decode(text, 5000);
  return { prefix: decoded.prefix, bytes: Uint8Array.from(KF.bech32.fromWords(decoded.words)) };
}

// NIP-49: a version byte, the scrypt cost, a 16-byte salt, a 24-byte
// nonce, the byte recording how its owner handles the key, and the
// sealed key itself. scrypt at the cost a key was written with is
// meant to be slow, so this yields to the event loop instead of
// locking the page up while it runs.
async function decryptNcryptsec(bytes, passphrase) {
  const key = await KF.scryptAsync(
    new TextEncoder().encode(passphrase.normalize("NFKC")),
    bytes.slice(2, 18),
    { N: 2 ** bytes[1], r: 8, p: 1, dkLen: 32, asyncTick: 20 }
  );
  return KF.xchacha20poly1305(key, bytes.slice(18, 42), bytes.slice(42, 43)).decrypt(bytes.slice(43));
}

// The private key, or a refusal somebody can act on. A key that isn't
// one and a passphrase that is wrong are the two failures worth
// telling apart, because only one of them is worth trying again.
async function privkeyFromText(text, passphrase) {
  let decoded;
  try {
    decoded = decodeBech32(text);
  } catch (err) {
    throw new Error("that doesn't look like an nsec or an ncryptsec");
  }

  let privkey;
  if (decoded.prefix === "nsec") {
    privkey = decoded.bytes;
  } else if (decoded.prefix === "ncryptsec") {
    if (decoded.bytes.length !== 91 || decoded.bytes[0] !== 0x02) {
      throw new Error("that ncryptsec is written in a way hearth doesn't understand");
    }
    try {
      privkey = await decryptNcryptsec(decoded.bytes, passphrase);
    } catch (err) {
      throw new Error("that passphrase doesn't open this key");
    }
  } else {
    throw new Error("that's " + (decoded.prefix === "npub" ? "a public key" : "an " + decoded.prefix) +
      ", not a key hearth can sign with");
  }

  if (privkey.length !== 32) throw new Error("that key is the wrong length");
  try {
    S.schnorr.getPublicKey(privkey);
  } catch (err) {
    throw new Error("that isn't a usable key");
  }
  return privkey;
}

// Said once, before anything is written over. There is no backup and
// no transfer yet, so a key replaced here is a key gone, and that is
// the fact this has to state rather than imply.
function replacementWarning(bringing) {
  if (bringing === "extension") {
    // Signing in with an extension leaves a sealed key where it is
    // rather than writing over it, so this must not say it is gone.
    return "Hearth will sign as the identity your extension holds. The key on this device now, " +
      shortName(identity.pubkey) + ", stays sealed where it is, but nothing in hearth will use it again.";
  }
  const becoming = "Hearth will sign as the key you are importing, sealed on this device in place of " +
    "the one there now.";
  const losing = identity.kind === "extension"
    ? "Your extension keeps its own key, so nothing of yours is lost there."
    : "The key on this device now, " + shortName(identity.pubkey) + ", is written over and gone. " +
      "There is no backup and no way to carry a key to another device yet, so it is gone for good " +
      "unless you have saved it somewhere else.";
  return becoming + " " + losing;
}

// A reload rather than a swap in place: every message on screen, the
// seats around the fire and the relay's own idea of who is connected
// are all keyed to the identity that was signing a moment ago, and
// startup already knows how to come up as whoever this device is now.
async function replaceIdentityWithPrivkey(privkey) {
  await storeSealedPrivkey(privkey);
  localStorage.removeItem(SIGNER_CHOICE_KEY);
  location.reload();
}

function replaceIdentityWithExtension() {
  localStorage.setItem(SIGNER_CHOICE_KEY, "extension");
  location.reload();
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
  return await identity.signEvent(ev);
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
   to before, then the page's own origin if the origin turns out
   to be a relay, then the manual box. The manual box is the
   fallback path, not the front door.

   Remembered relays sit above the origin because the origin is
   only a bootstrap — right when the relay itself served the page,
   wrong when a canonical copy did. A relay this device has
   actually reached is the better guess, and holding the list on
   the device is what will later let a group's second relay be
   tried when its first is down. Trying them in turn isn't built
   yet; the newest one is used.

   The origin is a candidate rather than an answer, because a URL
   cannot say whether the host that served the page is a relay.
   The same one file is served by every bothy and by a canonical
   copy sitting on a static host that is not a relay at all, and
   inferring a relay from the address bar would send that copy to
   a websocket that does not exist. Asking the origin for its
   NIP-11 document is what settles it, and it is what keeps one
   file correct in both places.
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

// A relay answers a NIP-11 document at its root, which is both how
// the room learns its name and how the page finds out whether the
// host that served it is a relay. Returns null when the answer is
// not a NIP-11 document, and throws when the fetch itself fails.
async function fetchRelayInfo(relayUrl, options) {
  const res = await fetch(relayHttpUrl(relayUrl), {
    headers: { Accept: "application/nostr+json" },
    ...options,
  });
  if (!res.ok) return null;
  const info = await res.json();
  if (!info || typeof info !== "object" || Array.isArray(info)) return null;
  // Any one of NIP-11's own fields is enough. A static host answers
  // HTML and has already failed the JSON parse above; this last check
  // is for the host that answers some unrelated JSON at its root.
  const isRelayDoc = ["name", "pubkey", "supported_nips", "software"].some((k) => k in info);
  return isRelayDoc ? info : null;
}

// The page's own origin, and only once it has proved itself. The four
// second cap is for a host that takes the request and then says
// nothing: the page is waiting on this answer before it shows anyone
// anything, so it cannot wait forever.
async function originRelayUrl() {
  if (location.protocol !== "http:" && location.protocol !== "https:") return null;
  const candidate = (location.protocol === "https:" ? "wss:" : "ws:") + "//" + location.host;
  try {
    const info = await fetchRelayInfo(candidate, { signal: AbortSignal.timeout(4000) });
    return info ? candidate : null;
  } catch (err) {
    return null; // not a relay, or not answering — either way, ask
  }
}

async function resolveRelayUrl() {
  const fromFragment = parseFragment().get("relay");
  if (fromFragment) return relayUrlFromHost(fromFragment);

  const fromParam = new URLSearchParams(location.search).get("relay");
  if (fromParam) return relayUrlFromHost(fromParam);

  const remembered = rememberedRelays();
  if (remembered.length > 0) return remembered[0];

  // Nothing in the link and nothing remembered, so the origin is the
  // last guess before the manual box, and it has to earn it. A null
  // here is someone who arrived with nothing to go on.
  return await originRelayUrl();
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
// Bumped whenever the current connection is deliberately replaced
// (a relay switch). A socket whose epoch is stale ignores its own
// close and message events instead of reconnecting or writing into
// the new connection's state.
let connEpoch = 0;
let roomName = null; // the relay's NIP-11 name — the room's label

// The room's name and the connection's state, in both places they
// appear: under the pill in mode 1, in the top bar in modes 2 and 3.
// A quiet, connected room shows only its name.
function renderChrome() {
  const name = roomName || "#" + GROUP_ID;
  tbNameEl.textContent = name;
  vpNameEl.textContent = name;
  // The tab carries the group's name too, for somebody who has two open.
  document.title = roomName ? "Hearth - " + roomName : "Hearth";
}

function setStatus(text, kind) {
  const hide = kind === "lit"; // connected and quiet — the room's name is enough
  for (const el of [tbStatusEl, vpStatusEl]) {
    el.textContent = text;
    el.classList.toggle("warn", kind === "warn");
    el.hidden = hide;
  }
}

function connect(relayUrl) {
  const epoch = ++connEpoch;
  clearTimeout(reconnectTimer);
  setStatus("connecting");
  authState = "none";
  needsResubscribe = false;

  ws = new WebSocket(relayUrl);

  ws.addEventListener("open", () => {
    if (epoch !== connEpoch) return;
    reconnectDelay = 2000;
    rememberRelay(relayUrl);
    if (inviteCode) {
      // Redemption comes before anything else — before subscribing,
      // and before the person is asked for so much as a name. Nobody
      // should type their name into a link that turns out to be spent.
      setStatus("connecting");
      sendJoinRequest(inviteCode);
    } else {
      setStatus("connecting");
      subscribe();
    }
  });

  ws.addEventListener("message", (evt) => {
    if (epoch !== connEpoch) return;
    let frame;
    try {
      frame = JSON.parse(evt.data);
    } catch (e) {
      console.error("hearth: unparseable relay frame", evt.data);
      return;
    }
    handleFrame(frame, relayUrl, epoch);
  });

  ws.addEventListener("close", () => {
    if (epoch !== connEpoch) return;
    if (halted) return;
    setStatus("reconnecting", "warn");
    reconnectTimer = setTimeout(() => connect(relayUrl), reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 1.5, 15000);
  });

  ws.addEventListener("error", () => {
    // the close handler fires right after and drives the visible retry state
    console.error("hearth: websocket error");
  });
}

// Signing is asynchronous, and when it is a browser extension asking
// its owner for permission it takes as long as they take. The socket
// that was open when an event was composed may not be the socket that
// is open when it comes back signed, and sending on one that is still
// connecting throws, so every event send goes through here.
function sendEvent(event) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(["EVENT", event]));
  }
}

function subscribe() {
  ws.send(JSON.stringify(["REQ", SUB_ID,
    { kinds: [KINDS.CHAT], "#h": [GROUP_ID], limit: 50 },
    { kinds: [KINDS.PROFILE], "#h": [GROUP_ID] },
    { kinds: [KINDS.CALL_PRESENCE], "#h": [GROUP_ID] },
    { kinds: [KINDS.CALL_SIGNAL], "#h": [GROUP_ID], "#p": [identity.pubkey] },
  ]));
}

async function handleFrame(frame, relayUrl, epoch) {
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
      setStatus("connecting");
    } else {
      setStatus("disconnected: " + reason, "warn");
    }
    return;
  }

  if (type === "AUTH") {
    const challenge = frame[1];
    authState = "pending";
    setStatus("connecting");
    const authEvent = await finalizeEvent({
      kind: KINDS.CLIENT_AUTH,
      tags: [["relay", relayUrl], ["challenge", challenge]],
    });
    // A challenge belongs to the socket that issued it. If that socket
    // has been replaced while this was being signed, the answer is
    // worthless and the connection that replaced it will be challenged
    // in its own right.
    if (epoch !== connEpoch) return;
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
        setStatus("the relay refused: " + message, "warn");
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
  if (identity && pubkey === identity.pubkey) renderAccountChrome();
  renderHearth();
}

// The account button in the bar and the header of the overlay both
// wear whatever this identity is currently called.
function renderAccountChrome() {
  accountBtn.style.background = colorFor(identity.pubkey);
  accountBtn.textContent = initials(identity.pubkey);
  aoAvatarEl.style.background = colorFor(identity.pubkey);
  aoAvatarEl.textContent = initials(identity.pubkey);
  aoNameEl.textContent = displayName(identity.pubkey);
  aoKeyNoteEl.textContent = identity.kind === "extension"
    ? "Your extension holds this identity's key, and hearth only ever asks it to sign. " +
      "Nothing here can read that key, save a copy of it, or carry it to another device."
    : "This key is your identity here and it signs everything you say. It stays on this " +
      "device, sealed so that this page can use it but never read it out. There is no " +
      "backup and no way to carry it to another device yet.";
  aoExtBtn.hidden = !(hasExtension() && identity.kind !== "extension");
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

// Rows are kept in created_at order. The relay serves stored history
// newest-first, so a backfilled message usually belongs above what is
// already rendered, while a live one lands at the end.
function appendRow(row, createdAt) {
  // Stick to the newest message only when the person is at the bottom
  // of the conversation; a reader further up (typing or not) keeps
  // their place.
  const stick = distFromBottom() < 80;
  row.dataset.ts = createdAt;
  let node = msgsEl.lastElementChild;
  while (node && Number(node.dataset.ts) > createdAt) node = node.previousElementSibling;
  if (node) node.after(row);
  else msgsEl.prepend(row);
  if (stick) scrollEl.scrollTop = scrollEl.scrollHeight;
}

function renderIncoming(event) {
  if (seenIds.has(event.id)) return;
  seenIds.add(event.id);
  if (outbox.has(event.id)) return; // our own message, already rendered optimistically
  const row = messageRow(event.pubkey, event.content, formatTime(event.created_at), event.pubkey === identity.pubkey);
  appendRow(row, event.created_at);
}

function markSent(el) {
  el.classList.remove("pending");
}

function markFailed(el, reason) {
  el.classList.remove("pending");
  el.classList.add("failed");
  const note = document.createElement("div");
  note.className = "mFail";
  note.textContent = "not sent: " + reason;
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
  appendRow(row, event.created_at);

  outbox.set(event.id, { kind: "message", el: row, event });
  sendEvent(event);
}

function trySend() {
  const text = msgInput.value.trim();
  if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
  msgInput.value = "";
  sendMessage(text);
}

// Return is the send button: the input carries enterkeyhint="send" so
// the on-screen key says so. preventDefault keeps the key from doing
// anything else on the page; a single-line input has no newline to
// insert anyway.
msgInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    trySend();
  }
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
  sendEvent(event);
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
  setStatus("connecting");
  subscribe();
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
  setStatus("you’re not in this group", "warn");
  ws.close();
}

/* ---------- publishing a name: the join prompt and the overlay share this ---------- */
async function publishProfileName(name) {
  profiles.set(identity.pubkey, { name, at: Math.floor(Date.now() / 1000) });
  applyProfile(identity.pubkey);
  const event = await finalizeEvent({
    kind: KINDS.PROFILE,
    tags: [["h", GROUP_ID]],
    content: JSON.stringify({ name }),
  });
  outbox.set(event.id, { kind: "profile", event });
  sendEvent(event);
}

function submitName() {
  const name = nameInput.value.trim();
  namePromptEl.hidden = true;
  if (!name) return; // no name offered — the short pubkey stands in until they give one
  publishProfileName(name);
}

nameSubmitBtn.addEventListener("click", submitName);
nameInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") submitName();
});

/* ============================================================
   the relay's NIP-11 document: the room's name, and whether this
   identity is the owner

   The relay's stated name is the room's label — in bothy's
   one-group world the relay is the group. Ownership decides
   whether the invite section exists inside the account overlay;
   everyone else never learns it is there. Creating an invite is a
   kind-9009 over the websocket. Listing the outstanding ones is
   the relay's own NIP-86 management API, because redeemed-or-not
   lives in the relay's invite table, not in any event a
   subscription could watch.
   ============================================================ */
let isOwner = false;

async function loadRelayInfo() {
  const forUrl = currentRelayUrl;
  let info = null;
  try {
    info = await fetchRelayInfo(forUrl);
  } catch (err) {
    // No NIP-11 answer just means no name and no invite control.
  }
  if (!info) return;
  if (forUrl !== currentRelayUrl) return; // switched relays while the fetch was in flight
  roomName = typeof info.name === "string" && info.name.trim() !== "" ? info.name.trim() : null;
  renderChrome();
  isOwner = info.pubkey === identity.pubkey;
  aoInvitesEl.hidden = !isOwner;
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
  sendEvent(event);
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
    inviteListEl.textContent = "no invites outstanding";
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
  opening: false, // unmuted, but the microphone is not live yet — never shown as hot
  presence: new Map(), // pubkey -> { lastSeen, muted }
  peers: new Map(), // pubkey -> { pc, sender, audioEl, candidateQueue, remoteSet }
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
  sendEvent(event);
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
  const entry = { pc, sender: null, audioEl: null, candidateQueue: [], remoteSet: false };
  call.peers.set(pubkey, entry);

  // Every connection gets an audio sender from birth, track or no
  // track: a peer who joins while we are muted must still have
  // somewhere for a future track to go, and negotiating the m-line as
  // sendrecv up front is what lets replaceTrack turn our audio on and
  // off later without renegotiating the call.
  const transceiver = pc.addTransceiver("audio", { direction: "sendrecv" });
  entry.sender = transceiver.sender;
  const track = call.localStream ? call.localStream.getAudioTracks()[0] : null;
  if (track) {
    entry.sender.replaceTrack(track).catch((err) => console.error("hearth: replaceTrack", err));
  }

  pc.addEventListener("track", (e) => {
    // Transceiver-based senders carry no stream association on the
    // wire, so e.streams can be empty; wrap the bare track so playback
    // and the speaking detector always have a stream to hold.
    const stream = e.streams[0] || new MediaStream([e.track]);
    const audioEl = document.createElement("audio");
    audioEl.autoplay = true;
    audioEl.srcObject = stream;
    document.body.appendChild(audioEl);
    audioEl.play().catch(() => {});
    entry.audioEl = audioEl;
    attachSpeakingDetector(pubkey, stream);
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
  call.opening = false;
  attachSpeakingDetector(identity.pubkey, call.localStream);
  publishPresence();
  heartbeatTimer = setInterval(publishPresence, HEARTBEAT_MS);
  for (const pubkey of call.presence.keys()) maybeConnectToPeer(pubkey);
  renderHearth();
}

/* Muting releases the microphone, so the operating system's indicator
   is truthful: lit only while audio can actually leave this device.
   The track is stopped and every peer's audio sender emptied; unmuting
   acquires a fresh track and puts it back into the same senders. The
   peer connections themselves are never rebuilt for a mute — that
   would renegotiate the call, slowly and visibly to everyone. */
// Bumped by every mute and unmute; an unmute still waiting on
// getUserMedia checks it before wiring the fresh track in, so a person
// who changes their mind mid-open doesn't end up hot.
let micEpoch = 0;

function muteMicrophone() {
  micEpoch++;
  call.muted = true;
  call.opening = false;
  detachSpeakingDetector(identity.pubkey);
  call.speaking.delete(identity.pubkey);
  if (call.localStream) {
    for (const track of call.localStream.getTracks()) track.stop();
  }
  call.localStream = null;
  for (const entry of call.peers.values()) {
    if (entry.sender) entry.sender.replaceTrack(null).catch(() => {});
  }
  publishPresence(); // so others' muted badge for us updates promptly
  renderHearth();
}

async function unmuteMicrophone() {
  const epoch = ++micEpoch;
  call.opening = true;
  renderHearth(); // the mic must not read as hot before the track is live
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (err) {
    if (epoch === micEpoch) {
      call.opening = false;
      renderHearth();
      showBanner("[call] microphone permission refused — " + err.message);
    }
    return;
  }
  if (epoch !== micEpoch || !call.joined) {
    // muted again, or left the call, while the microphone was opening
    for (const track of stream.getTracks()) track.stop();
    return;
  }
  call.localStream = stream;
  call.muted = false;
  call.opening = false;
  attachSpeakingDetector(identity.pubkey, stream);
  const track = stream.getAudioTracks()[0];
  for (const entry of call.peers.values()) {
    if (entry.sender) entry.sender.replaceTrack(track).catch((err) => console.error("hearth: replaceTrack", err));
  }
  publishPresence();
  renderHearth();
}

function toggleMute() {
  // A tap while the microphone is still opening is a change of mind.
  if (call.opening || !call.muted) muteMicrophone();
  else unmuteMicrophone();
}

function leaveCall() {
  if (!call.joined) return;
  micEpoch++; // invalidates any unmute still waiting on getUserMedia
  publishLeavePresence();
  clearInterval(heartbeatTimer);
  heartbeatTimer = null;
  for (const pubkey of [...call.peers.keys()]) teardownPeer(pubkey);
  detachSpeakingDetector(identity.pubkey);
  if (call.localStream) {
    for (const track of call.localStream.getTracks()) track.stop();
  }
  call.localStream = null;
  call.joined = false;
  call.muted = false;
  call.opening = false;
  call.speaking.delete(identity.pubkey);
  renderHearth();
}

micBtn.addEventListener("click", () => {
  if (!call.joined) joinCall();
  else toggleMute();
});
leaveBtn.addEventListener("click", leaveCall);

/* ---------- rendering: the voice screen and the hearth in the scroll ---------- */
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
    av.style.width = "100%";
    av.style.height = "100%";
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

// One hearth, rendered once, whatever its current size.
function renderHearth() {
  const seatedPubkeys = [...call.presence.keys()];
  if (call.joined) seatedPubkeys.unshift(identity.pubkey);
  const seated = seatedPubkeys.length;

  hearthEl.classList.toggle("cold", seated === 0);
  hearthEl.classList.toggle("youIn", call.joined && !call.muted);
  hearthEl.classList.toggle("youMuted", call.joined && call.muted);
  hearthLabelEl.textContent = seated === 0 ? "the hearth" : "at the hearth";

  buildRing(hRingEl, seatedPubkeys);
  measureCompact(); // who is seated changes the hearth's natural height

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

  if (!call.joined) {
    micLabelEl.textContent = seated === 0 ? "join" : "join them";
    micHintEl.textContent = seated === 0 ? "the fire is out — tap to light it" : "tap to join them";
  } else if (call.opening) {
    // The unmute was tapped but the track is not live yet — the mic
    // must say so rather than claim an open microphone.
    micLabelEl.textContent = "opening";
    micHintEl.textContent = "";
  } else if (call.muted) {
    micLabelEl.textContent = "muted";
    micHintEl.textContent = "tap to speak";
  } else {
    micLabelEl.textContent = "live";
    micHintEl.textContent = "tap to mute";
  }

  updateFloaters();
}

/* ============================================================
   the three modes, driven by scroll position

   One vertical axis with the voice at the bottom of it, and one
   voice UI on it: the hearth section at the end of the scroll.
   Compact, it sits under the composer and the conversation
   carries it away like any other content — modes 2 and 3.
   Expanded, its height is the whole main area and the scroll is
   parked at its bottom, so it fills the screen — mode 1. Moving
   between the two animates the one element's height while its own
   CSS transitions grow the microphone and raise the pane; nothing
   is torn down or swapped, which is what lets the detent read as
   one object snapping between two states of itself.

   The detent between modes 1 and 2 is resistive and snaps — it
   completes or it springs back, and it never rests in between. It
   is crossed by dragging the expanded hearth down, or by pulling
   up past the bottom of the conversation, and by nothing else:
   mode 1 is a place you go on purpose. The boundary between modes
   2 and 3 is ordinary scrolling, with separate enter and leave
   thresholds so a position on the line cannot oscillate.
   ============================================================ */
const MODE_VOICE = 1;
const MODE_SPLIT = 2;
const MODE_CHAT = 3;
const CHAT_ENTER = 90; // back within this of the bottom, mode 2 returns

// Mode 3 begins where the hearth has fully left the viewport, so the
// leave threshold follows the hearth's rendered height, which moves
// with how many people are seated.
function chatLeaveThreshold() {
  return hearthEl.offsetHeight + 20;
}

const ui = {
  mode: MODE_VOICE,
  H: 0, // height of the main area, remeasured on resize
  compactH: 340, // the hearth's natural height, cached while measurable
  dragging: false,
  kbFocus: false, // composer focused — the keyboard owns the bottom of the screen
};

const REDUCED_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;

// The hearth's natural height can only be read while no inline height
// overrides it; cache it whenever that is true, because the expanded
// state needs it as the other end of the animation.
function measureCompact() {
  if (!hearthEl.style.height) ui.compactH = hearthEl.offsetHeight;
}

// One knob moves the whole transition: the hearth's height, with the
// scroll pinned to its bottom so growth pushes the conversation up off
// the screen rather than pushing the fire below it.
function setHearthHeight(h) {
  hearthEl.style.height = h + "px";
  scrollEl.scrollTop = scrollEl.scrollHeight;
}

let tweenId = null;
function tweenHearthTo(target, done) {
  cancelAnimationFrame(tweenId);
  if (REDUCED_MOTION) {
    tweenId = null;
    setHearthHeight(target);
    if (done) done();
    return;
  }
  const from = hearthEl.offsetHeight;
  const t0 = performance.now();
  const DUR = 320;
  const ease = (t) => 1 - Math.pow(1 - t, 3);
  const step = (now) => {
    const p = Math.min(1, (now - t0) / DUR);
    setHearthHeight(from + (target - from) * ease(p));
    if (p < 1) {
      tweenId = requestAnimationFrame(step);
    } else {
      tweenId = null;
      if (done) done();
    }
  };
  tweenId = requestAnimationFrame(step);
}

function layout() {
  ui.H = mainEl.clientHeight;
  measureCompact();
  if (!ui.dragging && tweenId === null && ui.mode === MODE_VOICE) setHearthHeight(ui.H);
  // An out-of-flow composer is positioned against measured rects, so a
  // resize means re-measuring where it belongs.
  if (composerState === "docked") placeComposer(slotRect(), 0);
  else if (composerState === "lifted") rideKeyboard();
}

function setMode(mode, animate = true) {
  const wasVoice = ui.mode === MODE_VOICE;
  ui.mode = mode;
  const isVoice = mode === MODE_VOICE;
  stageEl.classList.toggle("mode1", isVoice);
  hearthEl.classList.toggle("expanded", isVoice);
  if (isVoice) {
    if (animate) tweenHearthTo(ui.H);
    else setHearthHeight(ui.H);
  } else if (wasVoice || hearthEl.style.height) {
    // Coming down from the voice screen, or abandoning a part-drawn
    // drag: settle to the natural compact height, then hand the height
    // back to the stylesheet so the hearth can breathe with its ring.
    // The pinning inside the tween is what lands the scroll at the
    // bottom of the conversation — mode 2's one position.
    const settle = () => {
      hearthEl.style.height = "";
      scrollEl.scrollTop = scrollEl.scrollHeight;
    };
    if (animate) tweenHearthTo(ui.compactH, settle);
    else settle();
  }
  updateComposerState(animate);
  updateFloaters();
}

function scrollToBottom(smooth) {
  if (smooth) scrollEl.scrollTo({ top: scrollEl.scrollHeight, behavior: "smooth" });
  else scrollEl.scrollTop = scrollEl.scrollHeight;
}

function distFromBottom() {
  return scrollEl.scrollHeight - scrollEl.scrollTop - scrollEl.clientHeight;
}

/* ---------- the composer: one element in three positions ----------
   In the flow of the scroll (modes 2 and 3), docked into the top bar's
   slot as the pill (mode 1), and lifted above the keyboard while
   focused. Moving between positions is the element travelling: it
   steps out of the flow at its current rect (a ghost holds its place),
   animates top/left/width to the target, and on the way home rejoins
   the flow where the ghost keeps its seat. Each journey's duration
   follows its distance, because the three focus cases move very
   different distances. */
let composerState = "flow"; // flow | docked | lifted
let composerTimer = null;

// The keyboard's upper edge, in the coordinates position:fixed uses.
// Where the keyboard overlays the page (iOS Safari) the visual
// viewport shrinks and can be offset while the layout viewport keeps
// its height; where the layout viewport itself resizes (Chrome
// Android), the two agree and this is simply the viewport's bottom.
function keyboardTop() {
  const vv = window.visualViewport;
  return vv ? vv.offsetTop + vv.height : window.innerHeight;
}

function slotRect() {
  const r = pillSlotEl.getBoundingClientRect();
  return { top: r.top, left: r.left, width: r.width };
}

function liftedRect() {
  const s = stageEl.getBoundingClientRect();
  return { top: keyboardTop() - composerEl.offsetHeight - 6, left: s.left, width: s.width };
}

function placeComposer(rect, ms) {
  composerEl.style.transitionDuration = (REDUCED_MOTION ? 0 : ms) + "ms";
  composerEl.style.top = rect.top + "px";
  composerEl.style.left = rect.left + "px";
  composerEl.style.width = rect.width + "px";
}

function travelMs(from, to) {
  const d = Math.hypot(from.top - to.top, from.left - to.left);
  return Math.round(Math.min(380, Math.max(160, d * 0.45)));
}

// While lifted, the composer's position is DERIVED from the visual
// viewport on every viewport event, so it rides the keyboard's own
// animation instead of racing it on an independent timer. The short
// transition only smooths the gaps between viewport samples.
function rideKeyboard() {
  if (composerState !== "lifted") return;
  placeComposer(liftedRect(), 150);
}
if (window.visualViewport) {
  window.visualViewport.addEventListener("resize", rideKeyboard);
  window.visualViewport.addEventListener("scroll", rideKeyboard);
}

function updateComposerState(animate = true) {
  const want = ui.kbFocus ? "lifted" : ui.mode === MODE_VOICE ? "docked" : "flow";
  if (want === composerState) return;
  clearTimeout(composerTimer);
  const from = composerEl.getBoundingClientRect();

  if (composerState === "flow") {
    // Step out of the flow without a visual jump: freeze at the current
    // rect and leave the ghost holding the space behind.
    composerGhostEl.style.height = composerEl.offsetHeight + "px";
    composerGhostEl.hidden = false;
    composerEl.classList.add("outOfFlow");
    placeComposer(from, 0);
    void composerEl.offsetWidth; // commit the starting rect before travelling
  }
  composerState = want;
  composerEl.classList.toggle("docked", want === "docked");
  composerEl.classList.toggle("lifted", want === "lifted");

  if (want === "flow") {
    // Travel home to the ghost's rect, then rejoin the flow there. The
    // scroll is deliberately untouched: a reader who focused from mode 3
    // gets their exact place back, even if home is off the screen.
    const target = composerGhostEl.getBoundingClientRect();
    const ms = animate ? travelMs(from, target) : 0;
    placeComposer({ top: target.top, left: target.left, width: target.width }, ms);
    composerTimer = setTimeout(() => {
      composerEl.classList.remove("outOfFlow");
      composerEl.style.top = "";
      composerEl.style.left = "";
      composerEl.style.width = "";
      composerEl.style.transitionDuration = "";
      composerGhostEl.hidden = true;
    }, ms + 40);
  } else {
    const target = want === "docked" ? slotRect() : liftedRect();
    placeComposer(target, animate ? travelMs(from, target) : 0);
  }
}

/* ---------- the floating controls over the conversation ---------- */
function updateFloaters() {
  const away = ui.mode === MODE_CHAT; // scrolled away from the bottom
  // Neither floater shows under the keyboard: the lifted composer
  // occupies the same corner of the screen.
  mutePillEl.hidden = !(call.joined && away && !ui.kbFocus);
  mutePillEl.classList.toggle("muted", call.muted);
  mutePillLabelEl.textContent = call.opening ? "opening…" : call.muted ? "muted" : "live";
  jumpChipEl.hidden = !(away && !ui.kbFocus);
}

mutePillEl.addEventListener("click", () => toggleMute());

// The arrow returns to the bottom of the conversation — mode 2 — and
// only by scrolling. It never carries anyone through the detent into
// mode 1: a button should not push someone through a resistive gesture.
jumpChipEl.addEventListener("click", () => scrollToBottom(true));

/* ---------- the detent, side one: dragging the expanded hearth down ---------- */
let drag = null;
let justDragged = false;

hearthEl.addEventListener("pointerdown", (e) => {
  if (ui.mode !== MODE_VOICE || e.button > 0) return;
  drag = { id: e.pointerId, y0: e.clientY, t0: performance.now(), moved: false };
});

hearthEl.addEventListener("pointermove", (e) => {
  if (!drag || e.pointerId !== drag.id) return;
  const dy = drag.y0 - e.clientY; // finger up = positive = toward the voice
  if (!drag.moved) {
    if (Math.abs(dy) < 8) return; // still a tap
    drag.moved = true;
    ui.dragging = true;
    cancelAnimationFrame(tweenId);
    tweenId = null;
    // Capture so the drag survives leaving the hearth's bounds. A
    // pointer that cannot be captured (synthetic events in tests)
    // still drags.
    try { hearthEl.setPointerCapture(drag.id); } catch (err) {}
  }
  // Resistive: the hearth follows the finger at a discount, and past
  // its two rest heights it turns to rubber.
  let h = ui.H + dy * 0.85; // dy is negative when pulling down toward chat
  if (h > ui.H) h = ui.H + (h - ui.H) * 0.2;
  if (h < ui.compactH) h = ui.compactH + (h - ui.compactH) * 0.2;
  setHearthHeight(h);
});

function endDrag(e) {
  if (!drag || e.pointerId !== drag.id) return;
  if (drag.moved) {
    ui.dragging = false;
    const dy = drag.y0 - e.clientY;
    const speed = Math.abs(dy) / Math.max(1, performance.now() - drag.t0); // px per ms
    const flick = speed > 0.5;
    // Completes into chat, or springs back — never rests in between.
    setMode(dy < -70 || (flick && dy < -20) ? MODE_SPLIT : MODE_VOICE);
    justDragged = true;
    setTimeout(() => { justDragged = false; }, 80);
  }
  drag = null;
}
hearthEl.addEventListener("pointerup", endDrag);
hearthEl.addEventListener("pointercancel", endDrag);

// A drag that ends on a button must not also press it.
scrollEl.addEventListener("click", (e) => {
  if (justDragged) {
    e.stopPropagation();
    e.preventDefault();
  }
}, true);

/* ---------- the detent, side two: pulling up past the bottom ---------- */
// The detent is a hard stop, not just resistance: only a touch that
// BEGINS at rest at the bottom of the conversation can cross it. A
// gesture that arrives at the bottom mid-scroll, and any momentum from
// a fling out of mode 3, ends there — reaching the voice screen takes
// a separate, deliberate pull. That is what keeps mode 1 a place
// someone goes on purpose rather than overshoots into.
let pull = null;

scrollEl.addEventListener("touchstart", (e) => {
  if (ui.mode === MODE_VOICE || ui.kbFocus) return;
  if (distFromBottom() >= 2) return; // not at rest at the bottom — this touch only scrolls
  pull = { y0: e.touches[0].clientY, t0: performance.now(), engaged: false };
}, { passive: true });

scrollEl.addEventListener("touchmove", (e) => {
  if (!pull) return;
  const y = e.touches[0].clientY;
  const dy = pull.y0 - y;
  if (!pull.engaged) {
    if (dy > 8 && distFromBottom() < 2) {
      pull.engaged = true;
      pull.y0 = y;
      pull.t0 = performance.now();
      ui.dragging = true;
    } else if (dy < -8) {
      pull = null; // scrolling up into history — native scrolling's business
      return;
    } else {
      return;
    }
  }
  e.preventDefault();
  let h = ui.compactH + (pull.y0 - y) * 0.85;
  if (h > ui.H) h = ui.H + (h - ui.H) * 0.2;
  if (h < ui.compactH) h = ui.compactH + (h - ui.compactH) * 0.2;
  setHearthHeight(h);
}, { passive: false });

function endPull(e) {
  if (!pull) return;
  if (pull.engaged) {
    ui.dragging = false;
    const dy = pull.y0 - e.changedTouches[0].clientY;
    const speed = Math.abs(dy) / Math.max(1, performance.now() - pull.t0);
    const flick = speed > 0.5;
    setMode(dy > 70 || (flick && dy > 20) ? MODE_VOICE : MODE_SPLIT);
    justDragged = true;
    setTimeout(() => { justDragged = false; }, 80);
  }
  pull = null;
}
scrollEl.addEventListener("touchend", endPull);
scrollEl.addEventListener("touchcancel", endPull);

// The wheel has no sustained gesture to resist, so the detent asks for
// a deliberate accumulation in one direction and then snaps. On the
// voice screen the wheel speaks to the detent, never to the parked
// conversation beneath it.
let wheelAcc = 0;
let wheelTimer = null;
let bottomAcc = 0;
let bottomTimer = null;
let lastWheelAt = 0; // when the previous wheel event arrived, wherever it scrolled
scrollEl.addEventListener("wheel", (e) => {
  if (ui.mode === MODE_VOICE) {
    e.preventDefault();
    wheelAcc += e.deltaY;
    clearTimeout(wheelTimer);
    wheelTimer = setTimeout(() => { wheelAcc = 0; }, 250);
    if (wheelAcc < -120) {
      wheelAcc = 0;
      setMode(MODE_SPLIT);
    }
    return;
  }
  const gap = e.timeStamp - lastWheelAt;
  lastWheelAt = e.timeStamp;
  if (ui.mode !== MODE_SPLIT || ui.kbFocus || e.deltaY <= 0 || distFromBottom() > 2) {
    bottomAcc = 0; // any scrolling that is not at the bottom disarms the detent
    return;
  }
  // Wheeling down with nothing left to scroll is the desktop's way of
  // pulling up past the bottom — but the detent is a hard stop that
  // inertia cannot cross. A wheel stream that was already running when
  // it reached the bottom (a trackpad fling out of mode 3, still
  // emitting momentum events) never starts the accumulation; only a
  // fresh gesture, begun after the stream has come to rest, arms it.
  if (bottomAcc === 0 && gap < 250) return;
  bottomAcc += e.deltaY;
  clearTimeout(bottomTimer);
  bottomTimer = setTimeout(() => { bottomAcc = 0; }, 250);
  if (bottomAcc > 160) {
    bottomAcc = 0;
    setMode(MODE_VOICE);
  }
}, { passive: false });

/* ---------- modes 2 and 3: ordinary scrolling, with hysteresis ---------- */
scrollEl.addEventListener("scroll", () => {
  if (ui.dragging || ui.mode === MODE_VOICE) return;
  const dist = distFromBottom();
  if (ui.mode !== MODE_CHAT && dist > chatLeaveThreshold()) setMode(MODE_CHAT);
  else if (ui.mode === MODE_CHAT && dist < CHAT_ENTER) setMode(MODE_SPLIT);
});

/* ---------- focusing: the composer travels, three distances ---------- */
msgInput.addEventListener("focus", () => {
  ui.kbFocus = true;
  const preFocusScrollTop = scrollEl.scrollTop;
  if (ui.mode === MODE_VOICE) {
    // The largest journey: the composer leaves the top bar for the
    // keyboard while the voice recedes and the conversation comes in
    // behind it — one continuous transformation, not a screen swap.
    // setMode re-derives the composer's position, which kbFocus makes
    // "lifted".
    setMode(MODE_SPLIT);
  } else {
    // From mode 2 a short lift while the voice block stays below; from
    // mode 3 the smallest move of all, and nothing else on screen
    // stirs.
    updateComposerState();
    // Browsers may scroll a container to reveal a focused input, but
    // the input has just left the flow — a reader keeps their place.
    requestAnimationFrame(() => {
      if (ui.kbFocus) scrollEl.scrollTop = preFocusScrollTop;
    });
  }
  updateFloaters();
});

msgInput.addEventListener("focusout", () => {
  setTimeout(() => {
    if (document.activeElement === msgInput) return;
    ui.kbFocus = false;
    // Dismissal lands where the person came from. Arrivals from mode 1
    // are already in mode 2 — deliberately asymmetric, since putting
    // the keyboard away means done typing, not "back to the voice
    // screen" — and a reader in mode 3 keeps their scroll position;
    // the composer simply travels home to its seat in the flow.
    updateComposerState();
    updateFloaters();
  }, 0);
});

msgInput.addEventListener("keydown", (e) => {
  if (e.key === "Escape") msgInput.blur();
});

/* ============================================================
   the account overlay — everything that is not the conversation:
   name, key, the relays this device knows, and (for the owner)
   the invite control. Relay switching lives here rather than
   behind its own surface because most people have exactly one
   relay, and a navigation surface for a list of one reads as
   broken. Private conversations will need their own
   frequent-access surface later; this overlay is not it and
   nothing here grows toward being it.
   ============================================================ */
function renderRelayList() {
  aoRelaysEl.innerHTML = "";
  const relays = rememberedRelays();
  if (relays.length === 0) {
    const none = document.createElement("div");
    none.className = "secNote";
    none.textContent = "no relays yet";
    aoRelaysEl.appendChild(none);
    return;
  }
  for (const url of relays) {
    const row = document.createElement("button");
    row.className = "relayItem" + (url === currentRelayUrl ? " current" : "");
    const dot = document.createElement("span");
    dot.className = "dot";
    const host = document.createElement("span");
    host.className = "host";
    host.textContent = url.startsWith("wss://") ? url.slice(6) : url;
    row.append(dot, host);
    if (url === currentRelayUrl) {
      const tag = document.createElement("span");
      tag.className = "tag";
      tag.textContent = "connected";
      row.appendChild(tag);
    }
    row.addEventListener("click", () => {
      switchRelay(url);
      renderRelayList();
    });
    aoRelaysEl.appendChild(row);
  }
}

// Everything shown is per-relay — the messages, the names, the
// presence, the room's own name — so a switch clears it all and lets
// the new relay say who and what this room is.
function switchRelay(url) {
  if (url === currentRelayUrl) return;
  if (call.joined) leaveCall();
  clearTimeout(reconnectTimer);
  connEpoch++; // orphans the old socket: its close event no longer reconnects
  try { if (ws) ws.close(); } catch (e) {}
  outbox.clear();
  seenIds.clear();
  profiles.clear();
  call.presence.clear();
  msgsEl.innerHTML = "";
  halted = false;
  isOwner = false;
  aoInvitesEl.hidden = true;
  inviteLinkRowEl.hidden = true;
  roomName = null;
  renderChrome();
  renderAccountChrome();
  renderHearth();
  start(url);
}

function openAccount() {
  renderAccountChrome();
  aoNameInput.value = (profiles.get(identity.pubkey) || {}).name || "";
  aoPubkeyEl.textContent = identity.pubkey;
  renderRelayList();
  if (isOwner) refreshInviteList();
  accountOverlayEl.hidden = false;
}

accountBtn.addEventListener("click", openAccount);
accountCloseBtn.addEventListener("click", () => {
  accountOverlayEl.hidden = true;
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !accountOverlayEl.hidden) accountOverlayEl.hidden = true;
});

aoNameSaveBtn.addEventListener("click", () => {
  const name = aoNameInput.value.trim();
  if (!name) return;
  publishProfileName(name);
  aoNameSaveBtn.textContent = "saved";
  setTimeout(() => { aoNameSaveBtn.textContent = "save"; }, 1500);
});

aoCopyKeyBtn.addEventListener("click", () => {
  navigator.clipboard.writeText(identity.pubkey).then(() => {
    aoCopyKeyBtn.textContent = "copied";
    setTimeout(() => { aoCopyKeyBtn.textContent = "copy public key"; }, 1500);
  });
});

/* ---------- bringing an identity in, from the overlay ---------- */
// Held between checking what was pasted and the person agreeing to
// what it replaces, so the warning is never shown for a key that
// turns out not to be one.
let pendingReplacement = null;

function showImportFailure(message) {
  aoImportFailEl.textContent = message;
  aoImportFailEl.hidden = false;
  aoConfirmEl.hidden = true;
}

function askToReplace(bringing, apply) {
  aoImportFailEl.hidden = true;
  aoConfirmTextEl.textContent = replacementWarning(bringing);
  aoConfirmEl.hidden = false;
  pendingReplacement = apply;
}

// Only one of the two formats has a passphrase, so only one of them
// is asked for one.
aoImportInput.addEventListener("input", () => {
  aoPassRow.hidden = !aoImportInput.value.trim().toLowerCase().startsWith("ncryptsec1");
});

aoImportBtn.addEventListener("click", async () => {
  const text = aoImportInput.value.trim();
  if (!text) return;
  aoImportFailEl.hidden = true;
  aoConfirmEl.hidden = true;
  aoImportBtn.disabled = true;
  // Opening an ncryptsec takes seconds by design, and a button that
  // goes quiet for that long reads as nothing having happened.
  aoImportBtn.textContent = "checking";
  let privkey;
  try {
    privkey = await privkeyFromText(text, aoPassInput.value);
  } catch (err) {
    showImportFailure(err.message);
    return;
  } finally {
    aoImportBtn.disabled = false;
    aoImportBtn.textContent = "import";
  }
  askToReplace("key", () => replaceIdentityWithPrivkey(privkey));
});

aoExtBtn.addEventListener("click", async () => {
  aoImportFailEl.hidden = true;
  try {
    await window.nostr.getPublicKey();
  } catch (err) {
    showImportFailure("your extension didn't hand over a public key");
    return;
  }
  askToReplace("extension", replaceIdentityWithExtension);
});

aoConfirmYesBtn.addEventListener("click", () => {
  const apply = pendingReplacement;
  pendingReplacement = null;
  aoConfirmEl.hidden = true;
  if (apply) apply();
});

aoConfirmNoBtn.addEventListener("click", () => {
  pendingReplacement = null;
  aoConfirmEl.hidden = true;
  aoImportInput.value = "";
  aoPassInput.value = "";
  aoPassRow.hidden = true;
});

/* ============================================================
   startup
   ============================================================ */
function start(relayUrl) {
  currentRelayUrl = relayUrl;
  connect(relayUrl);
  loadRelayInfo();
}

(async function init() {
  try {
    identity = await acquireIdentity();
  } catch (err) {
    // A corrupted identity store is a stop, not a shrug: minting a
    // fresh key here would silently replace whoever this device used
    // to be, and cost them their membership with no error anywhere.
    devWarnEl.textContent =
      "This device's identity can't be loaded — " + err.message +
      ". Hearth has stopped rather than sign you in as somebody else.";
    devWarnEl.hidden = false;
    // True of a sealed key that will not open and of an extension that
    // is no longer there; the banner above says which.
    setStatus("couldn’t sign you in", "warn");
    return;
  }
  renderAccountChrome();
  renderChrome();
  renderHearth();

  layout();
  setMode(MODE_VOICE, false); // the room's face is the fire
  new ResizeObserver(layout).observe(mainEl);

  inviteCode = parseFragment().get("code");

  // Resolving can mean asking the origin whether it is a relay, and
  // that wait is part of connecting as far as the top bar is concerned.
  setStatus("connecting");
  const resolved = await resolveRelayUrl();
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
