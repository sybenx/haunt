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
const landingExtRowEl = document.getElementById("landingExtRow");
const landingExtBtn = document.getElementById("landingExt");
const landingDeviceBtn = document.getElementById("landingDevice");
const loginScreenEl = document.getElementById("loginScreen");
const loginDeviceBtn = document.getElementById("loginDevice");
const loginExtRowEl = document.getElementById("loginExtRow");
const loginExtBtn = document.getElementById("loginExt");
const loginFailEl = document.getElementById("loginFail");
const loginRelayInput = document.getElementById("loginRelayInput");
const loginRelayGoBtn = document.getElementById("loginRelayGo");
const landingNoteEl = document.getElementById("landingNote");
const landingFailEl = document.getElementById("landingFail");
const aoAddDeviceBtn = document.getElementById("aoAddDevice");
const aoFromDeviceBtn = document.getElementById("aoFromDevice");
const aoReceiveOnlyEl = document.getElementById("aoReceiveOnly");
const aoAllowSendBtn = document.getElementById("aoAllowSend");
const aoTransfersEl = document.getElementById("aoTransfers");
const xferEl = document.getElementById("xfer");
const xCloseBtn = document.getElementById("xClose");
const xTitleEl = document.getElementById("xTitle");
const xNoteEl = document.getElementById("xNote");
const xPromptEl = document.getElementById("xPrompt");
const xQrEl = document.getElementById("xQr");
const xQrCanvas = document.getElementById("xQrCanvas");
const xCamEl = document.getElementById("xCam");
const xVideoEl = document.getElementById("xVideo");
const xSasEl = document.getElementById("xSas");
const xEmojiEl = document.getElementById("xEmoji");
const xDigitsEl = document.getElementById("xDigits");
const xListEl = document.getElementById("xList");
const xMultiEl = document.getElementById("xMulti");
const xButtonsEl = document.getElementById("xButtons");
const xSpinEl = document.getElementById("xSpin");
const xTransportEl = document.getElementById("xTransport");
const xFailEl = document.getElementById("xFail");
const xAltBtn = document.getElementById("xAlt");
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
const aoNotifyBtn = document.getElementById("aoNotifyBtn");
const aoNotifyNoteEl = document.getElementById("aoNotifyNote");
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
   plain page without hardware keys can get. The one way a key
   leaves is a transfer the person asks for and confirms on both
   devices, which is keyxfer.js.
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

/* ============================================================
   the name somebody already has

   Signing in with an extension says who this person is; it does not
   say what to call them. That is in their kind 0, and their kind 0 is
   on the public relays rather than on the group's, so this is the one
   place Hearth reads from the wider network. It reads one thing about
   one pubkey, and only when somebody has just chosen to sign in.

   Nothing here is trusted. A public relay can serve any JSON it likes
   under any pubkey, so the profile it returns is checked against its
   own id and signature before a word of it is used.
   ============================================================ */
const NAME_LOOKUP_RELAYS = [
  // purplepag.es exists to hold exactly these two kinds and answers
  // fastest. nostr.band indexes broadly, which is what finds somebody
  // whose profile lives nowhere anybody would have guessed. The rest
  // are big enough to be worth asking.
  "wss://purplepag.es",
  "wss://relay.nostr.band",
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://relay.primal.net",
];
const NAME_LOOKUP_TIMEOUT = 5000;

// One relay, one subscription, whatever came back before EOSE or the
// timeout. A relay that refuses, drops or never opens returns nothing
// rather than failing: this whole lookup is an improvement on asking,
// and every part of it is allowed to come up empty.
function queryRelay(url, filters) {
  return new Promise((resolve) => {
    const found = [];
    let socket = null;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { if (socket) socket.close(); } catch (err) {}
      resolve(found);
    };
    const timer = setTimeout(finish, NAME_LOOKUP_TIMEOUT);
    try {
      socket = new WebSocket(url);
    } catch (err) {
      finish();
      return;
    }
    socket.addEventListener("open", () => {
      socket.send(JSON.stringify(["REQ", "look", ...filters]));
    });
    socket.addEventListener("message", (e) => {
      let frame;
      try { frame = JSON.parse(e.data); } catch (err) { return; }
      if (frame[0] === "EVENT" && frame[1] === "look") found.push(frame[2]);
      // EOSE is a relay that answered. CLOSED is a relay that would
      // rather not — it wants AUTH, or it rate-limited the sub — and
      // hearth has nothing to offer it: signing an auth event for a
      // relay this group has no business with would hand that relay a
      // signature for the privilege of being refused. Both mean this
      // relay is done, and waiting the full timeout out on a refusal
      // only delays the ones that did answer.
      else if (frame[0] === "EOSE" && frame[1] === "look") finish();
      else if (frame[0] === "CLOSED" && frame[1] === "look") finish();
    });
    socket.addEventListener("error", finish);
    socket.addEventListener("close", finish);
  });
}

// The id is a hash of the event's own contents, so recomputing it
// catches a relay that edited the content, and the signature catches
// one that rewrote the event wholesale.
async function eventIsGenuine(event) {
  if (!event || typeof event.id !== "string" || typeof event.sig !== "string") return false;
  if (typeof event.pubkey !== "string" || typeof event.content !== "string") return false;
  if (!Array.isArray(event.tags) || typeof event.created_at !== "number") return false;
  try {
    const idBytes = await S.utils.sha256(new TextEncoder().encode(serializeEvent(event)));
    if (S.utils.bytesToHex(idBytes) !== event.id) return false;
    return await S.schnorr.verify(event.sig, idBytes, event.pubkey);
  } catch (err) {
    return false;
  }
}

async function lookupNostrName(pubkey) {
  const newest = (events, kind) => events
    .filter((e) => e && e.kind === kind && e.pubkey === pubkey)
    .sort((a, b) => b.created_at - a.created_at)[0] || null;

  const filters = [{ kinds: [KINDS.PROFILE, KINDS.RELAY_LIST], authors: [pubkey], limit: 4 }];
  const seen = (await Promise.all(
    NAME_LOOKUP_RELAYS.map((url) => queryRelay(url, filters))
  )).flat();

  let profile = newest(seen, KINDS.PROFILE);

  // NIP-65. Somebody who publishes nowhere near the four relays above
  // has said where they do publish, and the newest copy of a
  // replaceable event is the one that counts wherever it turns up.
  const list = newest(seen, KINDS.RELAY_LIST);
  if (list) {
    const writes = list.tags
      .filter((t) => t[0] === "r" && typeof t[1] === "string" && (t.length < 3 || t[2] === "write"))
      .map((t) => t[1])
      .filter((url) => url.startsWith("wss://") && !NAME_LOOKUP_RELAYS.includes(url))
      .slice(0, 4);
    if (writes.length > 0) {
      const more = (await Promise.all(
        writes.map((url) => queryRelay(url, [{ kinds: [KINDS.PROFILE], authors: [pubkey], limit: 2 }]))
      )).flat();
      const later = newest(more, KINDS.PROFILE);
      if (later && (!profile || later.created_at > profile.created_at)) profile = later;
    }
  }

  if (!profile) return null;
  if (!(await eventIsGenuine(profile))) return null;
  let meta;
  try { meta = JSON.parse(profile.content); } catch (err) { return null; }
  // NIP-01 defines name. display_name is a convention rather than the
  // spec, and it is what several clients put the readable one in, so
  // it stands in when name is missing.
  for (const field of ["name", "display_name"]) {
    const value = meta[field];
    if (typeof value === "string" && value.trim() !== "") return value.trim().slice(0, 40);
  }
  return null;
}

/* ============================================================
   arriving

   Two arrivals, and they are not the same person, so they do not get
   the same screen.

   Somebody following an invite link is being let into a room by
   somebody who already knows them, and the only thing wanted from
   them is what to call them. That is the name screen, and it asks
   before a key is minted so that signing in with an extension never
   means naming a key that is about to be thrown away.

   Somebody arriving at the bare address with no link and no identity
   on the device is a different person entirely. Almost nobody is
   genuinely new here without a link — a link is how anyone is let in
   — so this is somebody who already has an account and is standing in
   front of a device that does not have it yet. That is the log-in
   screen, and it leads with the one thing that fits: bring it from
   the device that does have it. The address box is still there,
   because somebody with neither a link nor a second device has to
   have a way through, but it is the last resort rather than the
   greeting.
   ============================================================ */
let pendingName = null; // { name, seeded } settled before there was a relay to publish it to
// A relay typed on the log-in screen, before there was an identity to
// connect with. resolveRelayUrl prefers it over anything remembered.
let chosenRelay = null;

// Signing in with an extension is offered on both screens and behaves
// the same on each: take the identity it holds, then go and read the
// name that identity already publishes so nobody is asked for one
// they have written down elsewhere. Resolves to a signer, or to null
// when the extension would not say who it is.
async function signInWithExtension(failEl, onLooking) {
  let signer;
  try {
    signer = extensionSigner(await window.nostr.getPublicKey());
  } catch (err) {
    failEl.textContent = "your extension didn't hand over a public key. " +
      "You can try again, or come in as somebody new.";
    failEl.hidden = false;
    return null;
  }
  localStorage.setItem(SIGNER_CHOICE_KEY, "extension");
  if (onLooking) onLooking();
  const found = await lookupNostrName(signer.pubkey);
  // Their own profile's name, taken on their behalf. It stays a
  // default, tracking that profile, until they rename here.
  if (found) pendingName = { name: found, seeded: true };
  return signer;
}

// The bare address, no link, no identity. Resolves to a signer when
// one is found, or to null when the person has said they are coming
// in as somebody new and the name screen should take over.
function loginScreen() {
  return new Promise((resolve) => {
    loginExtRowEl.hidden = !hasExtension();
    loginScreenEl.hidden = false;

    const leave = (signer) => {
      loginScreenEl.hidden = true;
      resolve(signer);
    };


    // The screen is about this. Nothing is minted down this path, so
    // somebody who takes it never has a throwaway key to write over.
    loginDeviceBtn.addEventListener("click", () => {
      loginScreenEl.hidden = true;
      openTransfer("joiner", () => {
        // Came back without a key, so this screen's question stands.
        loginScreenEl.hidden = false;
      });
    });

    loginExtBtn.addEventListener("click", async () => {
      loginFailEl.hidden = true;
      loginExtBtn.disabled = true;
      const signer = await signInWithExtension(loginFailEl, () => {
        loginFailEl.hidden = true;
      });
      if (!signer) { loginExtBtn.disabled = false; return; }
      // Signed in, but their profile carries no name. Nobody is in
      // this room as eight characters of hex, so the name screen
      // takes over with the identity already settled.
      leave(signer);
    });

    const useTypedRelay = () => {
      const value = loginRelayInput.value.trim();
      if (!value) return;
      chosenRelay = relayUrlFromHost(value);
      leave(null); // on to the name screen, and a key of their own
    };
    loginRelayGoBtn.addEventListener("click", useTypedRelay);
    loginRelayInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") useTypedRelay();
    });
  });
}

// Whichever screen this arrival calls for.
async function landing() {
  // An invite link is somebody being let in by somebody who knows
  // them, and it is the only arrival where a name is the question.
  // A pairing link naming this device as the joiner is the log-in
  // screen's own primary action, already taken on the other device.
  // Asking the question again would be asking somebody to choose
  // something they have just chosen.
  const pairing = pendingPairing();
  if (pairing) {
    // Every kind of pairing link is answered here, including one
    // asking this device for a key it does not have: that person
    // scanned with the wrong device of the two, and being told so is
    // better than being walked through a log in that was never the
    // thing they were doing.
    await new Promise((resolve) => openPairing(pairing, resolve));
    // Back here means no key arrived, so the arrival goes on as it
    // would have without the link.
  }

  if (!parseFragment().get("code")) {
    const signer = await loginScreen();
    // A name found on their own profile is the last question
    // answered; without one there is still a name to ask for, and
    // the name screen asks it with the identity already settled.
    if (signer && pendingName) return signer;
    return await nameScreen(signer);
  }
  return await nameScreen(null);
}

function nameScreen(alreadySignedIn) {
  return new Promise((resolve) => {
    let signedIn = alreadySignedIn || null; // an extension identity, once it has been taken

    // An offer already taken is not an offer, and somebody arriving
    // here signed in is owed a word about why they are being asked
    // anything at all.
    landingExtRowEl.hidden = !hasExtension() || !!signedIn;
    if (signedIn) {
      landingNoteEl.textContent =
        "You're signed in. There's no name on your nostr profile, so give one here.";
      landingNoteEl.hidden = false;
    }
    namePromptEl.hidden = false;
    nameInput.focus();

    // The name is the whole point of this screen, so there is no way
    // past it without one. Nobody arrives in the group as eight hex
    // characters they never chose.
    const gate = () => { nameSubmitBtn.disabled = nameInput.value.trim() === ""; };
    nameInput.addEventListener("input", gate);
    gate();

    const enter = (signer) => {
      namePromptEl.hidden = true;
      resolve(signer);
    };

    const submitName = async () => {
      const name = nameInput.value.trim();
      if (!name) return;
      pendingName = { name, seeded: false }; // typed here, so it is a decision
      if (signedIn) {
        enter(signedIn);
        return;
      }
      const privkey = S.utils.randomPrivateKey();
      await storeSealedPrivkey(privkey);
      enter(localSigner(privkey));
    };

    const signIn = async () => {
      landingFailEl.hidden = true;
      landingExtBtn.disabled = true;
      nameSubmitBtn.disabled = true;
      const signer = await signInWithExtension(landingFailEl, () => {
        landingNoteEl.textContent = "looking for your name";
        landingNoteEl.hidden = false;
      });
      landingNoteEl.hidden = true;
      if (!signer) {
        landingExtBtn.disabled = false;
        gate();
        return;
      }
      signedIn = signer;
      if (pendingName) {
        enter(signer);
        return;
      }
      // Signed in and nameless. The screen stays for the one question
      // it has left, and the offer goes, because it has been taken —
      // which on its own looks like the button did nothing, so the
      // screen says what happened and what is still wanted.
      landingExtRowEl.hidden = true;
      landingNoteEl.textContent =
        "You're signed in. There's no name on your nostr profile, so give one here.";
      landingNoteEl.hidden = false;
      gate();
      nameInput.focus();
    };

    // The third way in, and the only one that needs no name: this
    // identity already exists on a device the person is holding, and
    // the whole of what they have to do is show it a code. Nothing
    // is minted down this path, so somebody who takes it never has a
    // throwaway key to write over.
    const fromOtherDevice = () => {
      namePromptEl.hidden = true;
      openTransfer("joiner", () => {
        // Came back without a key, so the question this screen asks
        // is still unanswered.
        namePromptEl.hidden = false;
        nameInput.focus();
      });
    };

    nameSubmitBtn.addEventListener("click", submitName);
    nameInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submitName();
    });
    landingExtBtn.addEventListener("click", signIn);
    landingDeviceBtn.addEventListener("click", fromOtherDevice);
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

// The landing screen is the fallthrough rather than a source: it is
// what happens when nobody has this person's key. Minting now sits
// inside it, behind a name, because a key with nobody's name on it is
// not an identity anybody asked for.
async function acquireIdentity() {
  for (const source of identitySources) {
    const found = await source();
    if (found) return found;
  }
  return await landing();
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
      "It is gone for good unless another device already has it or you have saved it somewhere " +
      "else.";
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

  // Typed on the log-in screen a moment ago, which is a more recent
  // statement of where this person is going than anything this device
  // happens to remember.
  if (chosenRelay) return chosenRelay;

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
  // The tab carries the group's name too, for somebody who has two
  // open, and an unread count in front of it when there is one.
  renderUnread();
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
    // `d` is a single-letter tag, so the relay indexes it and asking
    // for it costs no more than the `h` beside it.
    { kinds: [KINDS.MEMBER], "#h": [GROUP_ID], "#d": [MEMBER_D] },
    // The two kind 0s worth reading, both as fallbacks and neither
    // ever written: the group profiles hearth published itself before
    // MEMBER existed, and this identity's own global profile, which
    // is what a name is seeded from at EOSE. A filter that names no
    // group is answered with the group's events left out, so the
    // second of these cannot stand in for the first.
    { kinds: [KINDS.PROFILE], "#h": [GROUP_ID] },
    { kinds: [KINDS.PROFILE], authors: [identity.pubkey] },
    { kinds: [KINDS.CALL_PRESENCE], "#h": [GROUP_ID] },
    { kinds: [KINDS.CALL_SIGNAL], "#h": [GROUP_ID], "#p": [identity.pubkey] },
  ]));
  // A name from the landing screen has had nowhere to go until now,
  // and every way into the group ends here: redeemed an invite,
  // walked in as a member, or came back after an auth. A relay that
  // wants AUTH first refuses the name, and the outbox sends it again
  // once the auth lands.
  if (pendingName) {
    const { name, seeded } = pendingName;
    pendingName = null;
    // The landing screen asked the public relays a moment ago, so the
    // refresh at EOSE has nothing left to learn this time round.
    seedRefreshed = true;
    publishMemberName(name, { seeded });
  }
}

async function handleFrame(frame, relayUrl, epoch) {
  const type = frame[0];

  if (type === "EVENT" && frame[1] === SUB_ID) {
    const event = frame[2];
    if (event.kind === KINDS.CHAT) renderIncoming(event);
    else if (event.kind === KINDS.MEMBER) recordName(memberNames, event);
    else if (event.kind === KINDS.PROFILE) recordName(profileNames, event);
    else if (event.kind === KINDS.CALL_PRESENCE) handlePresence(event);
    else if (event.kind === KINDS.CALL_SIGNAL) handleSignal(event);
    return;
  }

  if (type === "EOSE" && frame[1] === SUB_ID) {
    if (authState === "authed" || authState === "none") {
      setStatus("connected", "lit");
    }
    // Everything stored is on screen, so anything after this is
    // something that just happened. The call takes a moment longer:
    // it lives in heartbeats rather than in stored events, so the
    // people already around the fire announce themselves over the
    // next round of them and none of that is news.
    historyDone = true;
    callNewsAt = Date.now() + HEARTBEAT_MS + 1500;
    seedNameFromProfile();
    refreshSeededName();
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
        // Fresh admission or "already a member of this group" — this
        // key coming back with a code it didn't need, which leaves the
        // code unspent. Both are in, and neither is asked anything:
        // whoever needed a name gave one on the landing screen.
        finishJoin();
      } else {
        // Shown verbatim. The relay's refusal is deliberately uniform
        // across unknown, spent, expired and revoked codes, so nothing
        // is added here: a more specific message would be a guess, and
        // a friendlier one would leak what the relay chose not to.
        refuseJoin(message || "the relay refused the invite");
      }
      return;
    }

    if (entry.kind === "name") {
      if (ok) {
        outbox.delete(eventId);
      } else if (message && message.startsWith("auth-required") && authState !== "failed") {
        entry.lastReason = message;
      } else {
        outbox.delete(eventId);
        if (!entry.quiet) showBanner("your name wasn't saved: " + (message || "no reason given"));
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
   names — what each pubkey asked to be called in this group

   A kind 30078 with the group in its `d`, tagged into the group so
   only the group can read it. Deliberately not a kind 0: that one is
   keyed by pubkey and kind alone, so a member's real nostr profile
   arriving from anywhere else would take the place of the name they
   chose here — and now that somebody can sign in with a key that
   already has a kind 0 on the public relays, that is a collision
   waiting rather than a hypothetical one.

   Addressable, so the newest wins; each map tracks created_at to keep
   an old one arriving late from clobbering a rename.

   Kind 0 is still read, and only ever read. Members named themselves
   here before this kind existed and hearth wrote those names into
   kind 0s that are still on the relay, so a name hearth has not been
   given any other way is taken from one rather than lost.
   ============================================================ */

// NIP-78 keys an addressable event by (pubkey, kind, d), and `d` is
// the only part of that key a client chooses. Kind 30078 is where all
// of nostr keeps application data, so the value has to say hearth as
// well as which group: a bare group id would collide with whatever
// some other application filed under the same one, and the group id
// on the end is what keeps two groups on one relay apart.
const MEMBER_D = "hearth.member." + GROUP_ID;

const memberNames = new Map(); // pubkey -> { name, at }, from a kind 30078
const profileNames = new Map(); // pubkey -> { name, at }, from a kind 0

// The name somebody chose in this group, or the one a kind 0 happens
// to carry, or nothing at all. In that order: the group's name is
// theirs to set and a profile written somewhere else never overrules
// it.
function knownName(pubkey) {
  const entry = memberNames.get(pubkey) || profileNames.get(pubkey);
  return entry ? entry.name : null;
}

function displayName(pubkey) {
  return knownName(pubkey) || shortName(pubkey);
}

function initials(pubkey) {
  return displayName(pubkey).slice(0, 2);
}

// Both kinds carry the name the same way, as a JSON object with a
// name in it, so one reader takes either apart. The object rather
// than a bare string is for what comes next: what somebody looks like
// in a room is the thing most likely to grow a second field, and a
// second field beats a second kind.
function seededFlag(event) {
  try {
    return JSON.parse(event.content).seeded === true;
  } catch (e) {
    return false;
  }
}

function recordName(map, event) {
  let name;
  try {
    name = JSON.parse(event.content).name;
  } catch (e) {
    return;
  }
  if (typeof name !== "string" || name.trim() === "") return;
  const existing = map.get(event.pubkey);
  if (existing && existing.at >= event.created_at) return;
  map.set(event.pubkey, { name: name.trim(), at: event.created_at, seeded: seededFlag(event) });
  applyName(event.pubkey);
}

// Once, when the room has finished saying who everybody is: a member
// with no name of their own here takes the one their kind 0 carries.
// That is an existing member, whose name hearth itself wrote into a
// kind 0 before this kind existed, and it is equally somebody signing
// in with a key that has a real profile behind it.
//
// Seeding, not syncing. After this the kind 0 is never read for this
// person again, because a name changed in the group must not be
// reverted months later by a profile updated somewhere else. The
// publish below fills memberNames in as it goes, so a second EOSE —
// a reconnect, a relay that wanted AUTH first — finds nothing to do.
function seedNameFromProfile() {
  if (!identity || memberNames.has(identity.pubkey)) return;
  const profile = profileNames.get(identity.pubkey);
  if (!profile) return;
  // Carried across, not seeded. This kind 0 is one hearth wrote itself
  // back when a group name was a kind 0, so the name in it is one this
  // person chose for this room — a decision arriving late, and not
  // something the refresh below is entitled to overwrite.
  publishMemberName(profile.name, { quiet: true });
}

/* ------------------------------------------------------------
   A name taken from somebody's own nostr profile is a default, and
   a default that never moves is just a stale copy. So on every load
   the profile is asked again, and a name changed out there lands
   here too.

   Only while the name here is still a seed. The moment somebody
   types one of their own it carries no flag, this steps over it, and
   nothing they chose is ever taken back — which is the same promise
   seeding makes, held for as long as the seed lasts rather than only
   until the second load.

   This is also what rescues somebody signed in with an extension who
   has no name here at all: the lookup lives on the landing screen,
   the landing screen does not run for a signer already chosen, and
   without this they would go on being eight characters of hex with
   nothing anywhere going to look.
   ------------------------------------------------------------ */
let seedRefreshed = false;

async function refreshSeededName() {
  if (!identity || seedRefreshed) return;
  const before = memberNames.get(identity.pubkey);
  if (before && !before.seeded) return;
  seedRefreshed = true;
  const found = await lookupNostrName(identity.pubkey);
  if (!found) return;
  // Four public relays take a moment, and a name can be typed or a
  // relay switched inside it. Whatever is true now decides, and an
  // event that would say exactly what the last one said is not worth
  // sending.
  const now = memberNames.get(identity.pubkey);
  if (now && (!now.seeded || now.name === found)) return;
  publishMemberName(found, { seeded: true, quiet: true });
}

// Message rows already on screen were rendered before this name
// arrived (or under an older one) — restyle them in place. The
// hearth rebuilds itself wholesale, so one render call covers it.
function applyName(pubkey) {
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
      "device, sealed so that this page can use it but never read it out. The one way it " +
      "leaves is a transfer you start yourself and confirm on both devices.";
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
  // Fifty messages of history are not fifty things that just
  // happened, and nothing anybody says is news to the person who
  // said it.
  if (historyDone && event.pubkey !== identity.pubkey) newsOfMessage(event.pubkey);
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

function finishJoin() {
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
}

function refuseJoin(message) {
  inviteCode = null;
  halted = true;
  joinRefusedMsgEl.textContent = message;
  joinRefusedEl.hidden = false;
  setStatus("you’re not in this group", "warn");
  ws.close();
}

/* ---------- publishing a name: the landing screen and the overlay share this ---------- */
// `quiet` is a name nobody typed — one seeded from a kind 0 — and it
// is the difference between the two things that can go wrong. A name
// somebody just chose failing to save is worth a banner; a carried-over
// one failing is not, because the kind 0 it came from goes on standing
// in and there is nothing for anyone to do about it.
async function publishMemberName(name, opts) {
  const seeded = !!(opts && opts.seeded);
  memberNames.set(identity.pubkey, { name, at: Math.floor(Date.now() / 1000), seeded });
  applyName(identity.pubkey);
  const event = await finalizeEvent({
    kind: KINDS.MEMBER,
    // Both tags, and each is read by something different. `h` is what
    // files this in the relay's members-only partition, the way every
    // other event hearth writes is filed. `d` is what makes the event
    // addressable, which is the whole point of not being a kind 0:
    // this name is keyed by the group as well as by the key that
    // signed it, and a member's real nostr profile has nowhere to land
    // on top of it.
    tags: [["h", GROUP_ID], ["d", MEMBER_D]],
    // seeded says where the name came from, and it is the difference
    // between a default and a decision. A seeded name is one hearth
    // took from this person's own nostr profile on their behalf, and
    // it goes on tracking that profile. A name somebody typed carries
    // no flag and is never touched again.
    content: JSON.stringify(seeded ? { name, seeded: true } : { name }),
  });
  outbox.set(event.id, { kind: "name", event, quiet: !!(opts && opts.quiet) });
  sendEvent(event);
}

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
  // A relay that can reach somebody with hearth closed publishes the
  // public half of its VAPID key here. Without one, notifications
  // are still raised, but only while hearth is open — and the
  // account overlay says so rather than promising otherwise.
  vapidKey = typeof info.push_key === "string" && info.push_key.trim() !== "" ? info.push_key.trim() : null;
  renderNotifyChrome();
  if (vapidKey && notifyWanted()) subscribeToPush();
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
    if (isNew) newsOfVoice(event.pubkey);
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
  memberNames.clear();
  profileNames.clear();
  call.presence.clear();
  msgsEl.innerHTML = "";
  halted = false;
  isOwner = false;
  aoInvitesEl.hidden = true;
  inviteLinkRowEl.hidden = true;
  roomName = null;
  historyDone = false;
  vapidKey = null;
  unread = 0;
  renderChrome();
  renderAccountChrome();
  renderHearth();
  start(url);
}

function openAccount() {
  renderAccountChrome();
  renderDeviceSection();
  aoNameInput.value = knownName(identity.pubkey) || "";
  renderNotifyChrome();
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
  publishMemberName(name);
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
   being told

   Three different things wear the word "notification" here and it
   is worth keeping them apart.

   The unread count in the tab and on the icon costs nothing and
   asks nobody: it is just the title and the favicon, and it works
   in every browser hearth runs in.

   A banner raised while hearth is open needs permission, and on a
   phone it needs the service worker — android's chrome refuses the
   Notification constructor outright, and safari does not have one
   at all unless the page has been added to the home screen. So
   every banner goes through the registration, on every platform,
   rather than branching on which.

   A notification that arrives when hearth is closed is a push, and
   a push needs a server to send it. That is the relay's job and
   the relay has to grow it: see reference/push.md. Everything here
   does its half — reads the key, subscribes, hands the
   subscription over — and degrades to the two above when the relay
   has no key to offer.
   ============================================================ */
const NOTIFY_KEY = "hearth:notify";
let swReg = null;
let vapidKey = null; // the relay's push key, once its NIP-11 says it has one
let unread = 0;
let historyDone = false; // stored history is on screen, so what lands now is new

// Everybody in the call heartbeats, and on connecting they all
// arrive at once looking exactly like somebody who just walked in.
// Nothing about the call is news until a round of heartbeats has
// been and gone.
let callNewsAt = 0;

function notifyWanted() {
  return localStorage.getItem(NOTIFY_KEY) === "on";
}

// Not looking means the tab is elsewhere, or hearth is showing the
// fire rather than the conversation, or the conversation is scrolled
// back through history. In none of those is a message on screen.
function notLooking() {
  if (document.visibilityState !== "visible") return true;
  if (ui.mode === MODE_VOICE) return true;
  return distFromBottom() >= 80;
}

/* ---------- the count in the tab and on the icon ---------- */

// The same fire the page loaded with, with an ember sitting on its
// shoulder. Drawn here rather than kept as a second file for the
// reason the first one is inline: a copy of hearth is one thing.
function faviconWith(dot) {
  const flame =
    "<rect width='32' height='32' rx='7' fill='%231a120c'/>" +
    "<path d='M17.2 2.8c1.1 4.2-0.6 6.4-2.3 8.4-1.1-1.0-1.6-2.3-1.6-3.7-3.4 2.7-5.2 6.3-5.2 9.9 0 5.2 4.0 8.9 8.0 8.9s8.0-3.7 8.0-8.9c0-6.0-3.9-11.2-6.9-14.6z' fill='%23ff9e5a'/>" +
    "<path d='M16.1 14.5c-2.6 2.2-3.9 4.6-3.9 6.8 0 2.6 1.8 4.5 3.9 4.5s3.9-1.9 3.9-4.5c0-2.2-1.3-4.6-3.9-6.8z' fill='%23ffc07a'/>";
  const badge = dot
    ? "<circle cx='24.5' cy='7.5' r='7' fill='%231a120c'/><circle cx='24.5' cy='7.5' r='5' fill='%23ff6d5a'/>"
    : "";
  return "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>" +
    flame + badge + "</svg>";
}

function renderUnread() {
  const room = roomName ? "Hearth - " + roomName : "Hearth";
  document.title = unread > 0 ? "(" + unread + ") " + room : room;
  const icon = document.querySelector('link[rel="icon"]');
  if (icon) icon.href = faviconWith(unread > 0);
  if (navigator.setAppBadge) {
    if (unread > 0) navigator.setAppBadge(unread).catch(() => {});
    else if (navigator.clearAppBadge) navigator.clearAppBadge().catch(() => {});
  }
}

function clearUnread() {
  if (unread === 0) return;
  unread = 0;
  renderUnread();
}

/* ---------- the banner ---------- */

// Silent on hearth's side. The phone makes whatever noise the
// person has told it to make for notifications, which is the noise
// they actually chose.
async function raiseBanner(title, body, tag) {
  if (!notifyWanted()) return;
  if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
  if (!swReg) return;
  try {
    await swReg.showNotification(title, {
      body,
      icon: "icon.svg",
      badge: "icon.svg",
      tag: "hearth:" + tag,
      renotify: false,
      silent: true,
    });
  } catch (err) {
    // A browser that granted permission and then refused to show it
    // is not something to interrupt anybody about.
  }
}

// Both of these fire only when there is nothing on screen to see.
// The count moves either way, because it is what somebody coming
// back looks at.
function newsOfMessage(pubkey) {
  if (!notLooking()) return;
  unread += 1;
  renderUnread();
  raiseBanner(roomName || "hearth", displayName(pubkey) + " said something", "message");
}

function newsOfVoice(pubkey) {
  if (Date.now() < callNewsAt) return; // still finding out who was already here
  if (!notLooking()) return;
  raiseBanner(roomName || "hearth", displayName(pubkey) + " is at the fire", "voice");
}

/* ---------- turning it on ---------- */

// Permission has to be asked behind a gesture, and it may only be
// asked once — a browser that has been refused stays refused, and
// asking again does nothing but waste the one chance. So the button
// says which of the three states this is in rather than pretending
// it can always be pressed.
function renderNotifyChrome() {
  const supported = typeof Notification !== "undefined" && "serviceWorker" in navigator;
  if (!supported) {
    aoNotifyBtn.hidden = true;
    aoNotifyNoteEl.textContent =
      "This browser can't raise a notification. On an iPhone, adding hearth to the home " +
      "screen from the share menu gives it one.";
    return;
  }
  aoNotifyBtn.hidden = false;
  if (Notification.permission === "denied") {
    aoNotifyBtn.disabled = true;
    aoNotifyBtn.textContent = "notifications are blocked";
    aoNotifyNoteEl.textContent =
      "This browser has been told not to let hearth notify you, and only you can undo that, " +
      "in the site settings your browser keeps for this page.";
    return;
  }
  aoNotifyBtn.disabled = false;
  if (notifyWanted() && Notification.permission === "granted") {
    aoNotifyBtn.textContent = "turn notifications off";
    aoNotifyNoteEl.textContent = vapidKey
      ? "You'll be told when somebody says something or comes to the fire, including when " +
        "hearth is closed."
      : "You'll be told when somebody says something or comes to the fire, as long as hearth " +
        "is open. This relay can't reach you when it isn't.";
    return;
  }
  aoNotifyBtn.textContent = "turn on notifications";
  aoNotifyNoteEl.textContent =
    "Be told when somebody says something or comes to the fire while you're looking elsewhere.";
}

async function turnNotificationsOn() {
  aoNotifyBtn.disabled = true;
  let permission = Notification.permission;
  if (permission === "default") {
    try {
      permission = await Notification.requestPermission();
    } catch (err) {
      permission = "denied";
    }
  }
  if (permission !== "granted") {
    renderNotifyChrome();
    return;
  }
  localStorage.setItem(NOTIFY_KEY, "on");
  await subscribeToPush();
  renderNotifyChrome();
}

async function turnNotificationsOff() {
  aoNotifyBtn.disabled = true;
  localStorage.removeItem(NOTIFY_KEY);
  await unsubscribeFromPush();
  renderNotifyChrome();
}

aoNotifyBtn.addEventListener("click", () => {
  if (notifyWanted() && typeof Notification !== "undefined" && Notification.permission === "granted") {
    turnNotificationsOff();
  } else {
    turnNotificationsOn();
  }
});

/* ---------- push: the half of it that lives in the page ---------- */

// A VAPID key is base64url on the wire and bytes to the push
// manager, and no browser does that conversion for you.
function vapidBytes(base64url) {
  const padded = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(padded + "=".repeat((4 - padded.length % 4) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function subscribeToPush() {
  if (!swReg || !vapidKey || !swReg.pushManager) return;
  try {
    const existing = await swReg.pushManager.getSubscription();
    const sub = existing || await swReg.pushManager.subscribe({
      // Required, and the only setting a browser will accept: a push
      // that shows nothing is a push that can be used to track
      // somebody silently, and browsers stopped allowing it.
      userVisibleOnly: true,
      applicationServerKey: vapidBytes(vapidKey),
    });
    await manageRelay("subscribepush", [JSON.parse(JSON.stringify(sub))]);
  } catch (err) {
    // No push, then. The banner while hearth is open still works,
    // and saying so is renderNotifyChrome's job rather than a
    // failure worth putting in front of somebody.
  }
}

async function unsubscribeFromPush() {
  if (!swReg || !swReg.pushManager) return;
  try {
    const sub = await swReg.pushManager.getSubscription();
    if (!sub) return;
    await manageRelay("unsubscribepush", [sub.endpoint]).catch(() => {});
    await sub.unsubscribe();
  } catch (err) {
    // Nothing here is worth interrupting anybody about either.
  }
}

// Registered on every load, whether or not anybody has said yes:
// the worker is what raises a banner, and the permission prompt
// should not also be a wait for a file to install.
function registerWorker() {
  if (!("serviceWorker" in navigator)) return;
  navigator.serviceWorker.register("sw.js").then((reg) => {
    swReg = reg;
    renderNotifyChrome();
    if (notifyWanted()) subscribeToPush();
  }).catch(() => {
    // A page served from something that is not a secure context, or
    // a browser with workers switched off.
  });
}

// Coming back to the conversation is what marks it read, and being
// at the fire is not coming back to it.
document.addEventListener("visibilitychange", () => {
  if (!notLooking()) clearUnread();
});
scrollEl.addEventListener("scroll", () => {
  if (!notLooking()) clearUnread();
}, { passive: true });

/* ============================================================
   carrying this identity to another device

   keyxfer.js is the protocol and knows nothing about hearth; this
   is the screen in front of it. Two devices, one code, and two
   deliberate taps: the person holding the key says send, and the
   person receiving it says that the identity that turned up is
   theirs. Neither tap is skippable, and the whole thing exists
   because a key sealed on one device was, until now, a key that
   could never be anywhere else.

   Which device shows the code is a matter of which one has a
   camera pointing the right way, so both ways round are here. The
   one hearth offers first is the new device showing and the old
   device scanning, because the old device is usually the phone.
   ============================================================ */
/* Whether the key is locked to this device.

   Locked means this device will not hand the key to another one: the
   consent prompt that would send it is never reached, so there is
   nothing here to talk anybody through. It is on by default for a
   device that was given its key by another, because a device somebody
   pointed a camera at once is not thereby a device they meant to send
   keys from ever after.

   What it is not is a security boundary, and nothing should be built
   on it as though it were. Every device holds the whole key, the
   unlock is one unguarded tap by design, and anybody holding the
   device can take it. It is a speed bump on devices the person never
   nominated as a place their key travels from, and it is not the
   beginning of an enforcement mechanism.

   The stored name is the older one. Renaming it would read as absent
   on every device that already has it set, which would quietly
   unlock exactly the devices this exists for. */
const RECEIVE_ONLY_KEY = "hearth:receive-only";
const TRANSFERS_KEY = "hearth:transfers";
const LOCK_KEY = "hearth:lock";

// §8: a device given its key by another device does not pass it on
// until the person says it may. One tap, nothing guarding it, and
// said on the transfer screen rather than buried.
function keyLocked() {
  return localStorage.getItem(RECEIVE_ONLY_KEY) === "1";
}

// §8: every transfer is written down where the person can see it,
// so that one they did not make is something they can find out
// about afterwards.
function transferLog() {
  try {
    const stored = JSON.parse(localStorage.getItem(TRANSFERS_KEY) || "[]");
    return Array.isArray(stored) ? stored : [];
  } catch (err) {
    return [];
  }
}

function recordTransfer(entry) {
  const log = transferLog();
  log.unshift(entry);
  localStorage.setItem(TRANSFERS_KEY, JSON.stringify(log.slice(0, 20)));
}

function renderTransfers() {
  aoTransfersEl.innerHTML = "";
  for (const t of transferLog()) {
    const row = document.createElement("div");
    row.className = "xferItem";
    const when = document.createElement("span");
    when.className = "xferWhen";
    when.textContent = new Date(t.ts * 1000).toLocaleDateString([], { month: "short", day: "numeric" });
    const what = document.createElement("span");
    what.textContent = t.role === "holder" ? "sent to a device" : "arrived from a device";
    if (t.multi) what.textContent += ", and more than one device answered";
    const code = document.createElement("span");
    code.className = "xferCode";
    code.textContent = t.sas || "";
    row.append(when, what, code);
    aoTransfersEl.appendChild(row);
  }
}

/* ---------- the code, drawn and read ---------- */

/* ---------- what the code points at ----------

   Not the nostr+keyxfer URI on its own. A phone's own camera app,
   which is what somebody actually points at a screen, hands an
   unknown scheme to a web search rather than to an app, and no
   browser has registered that scheme because hearth is a page rather
   than an installed app. So the code carries an ordinary https link
   to this copy of hearth, with the pairing URI inside it, and the
   phone opens what it always opens.

   In the fragment rather than the query, because a fragment is never
   sent to the server: the host this page is served from never sees a
   burner key or a relay list in a request log.

   Whole rather than unpacked into the link's own parameters. The
   string the specification defines is the string its rules are
   written about, so it arrives at the parser exactly as it left the
   other device, and a version this build does not know is still
   refused by the same line of code. */
const PAIR_PARAM = "pair";
const PAIR_SCHEME = "nostr+keyxfer://";

// The inverse of pairingLink, and the only thing in hearth that
// decides what a device code looks like. Both readers go through it:
// the scanner pointing a camera at a screen, and the page that was
// opened by following one. They disagreed once — the code became a
// link and only the page-load half was taught to read it, so hearth
// refused the code hearth had just drawn — and one function is what
// stops that being possible rather than unlikely.
//
// Takes a link, a whole page URL, or a bare pairing URI, and returns
// the pairing URI inside it. What that URI has to contain is not this
// function's business: it hands the string to the parser the
// specification is written about, unchanged.
function innerPairingUri(text) {
  const trimmed = (text || "").trim();
  if (trimmed.startsWith(PAIR_SCHEME)) return trimmed;
  let hash;
  try {
    hash = new URL(trimmed).hash;
  } catch (err) {
    throw new Error("that code isn't a hearth device code");
  }
  const inner = pairFromFragment(hash.slice(1));
  if (!inner) throw new Error("that code isn't a hearth device code");
  return inner;
}

// Everything after the marker, to the end. Not URLSearchParams,
// because the URI is now carried unescaped and its own ampersands
// would look like the end of it to a parser that split on them.
//
// A code written by an older build arrives percent-encoded instead,
// and is still read: unescaping something that needs no unescaping
// leaves it alone, so one line covers both and a pair of devices on
// different builds still pairs.
function pairFromFragment(fragment) {
  const at = (fragment || "").indexOf(PAIR_PARAM + "=");
  if (at === -1) return null;
  const raw = fragment.slice(at + PAIR_PARAM.length + 1);
  if (raw.startsWith(PAIR_SCHEME)) return raw;
  try {
    const decoded = decodeURIComponent(raw);
    return decoded.startsWith(PAIR_SCHEME) ? decoded : null;
  } catch (err) {
    return null;
  }
}

// The pairing a code names, or a refusal somebody can read.
function readPairingCode(text) {
  return Keyxfer.parseUri(innerPairingUri(text));
}

function isLoopback(host) {
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]" ||
    host === "::1" || host === "0.0.0.0" || host.endsWith(".localhost");
}

// The link the QR draws, built from wherever this copy of hearth was
// served from. A copy served by a relay points at that relay and the
// canonical copy points at itself, so the code never sends anybody to
// a copy the pair has no reason to be able to reach.
function pairingLink(uri) {
  const http = location.protocol === "https:" || location.protocol === "http:";
  if (!http) return { url: uri, reachable: false, reason: "file" };
  return {
    // The URI goes in as itself. Every character it contains — the
    // plus, the colons, the slashes, the query's own separators — is
    // legal in a fragment, so escaping them a second time bought
    // nothing and cost around sixty characters, which is a whole QR
    // version's worth of density on a code somebody has to point a
    // camera at. It goes last so that reading it back is everything
    // after the marker, which is what makes an unescaped ampersand
    // inside it harmless.
    url: location.origin + location.pathname + "#" + PAIR_PARAM + "=" + uri,
    // A loopback address means something on this machine and nothing
    // at all on the phone being pointed at it, so a code built here
    // cannot be followed. Said on screen rather than left to fail as
    // a page that will not load.
    reachable: !isLoopback(location.hostname),
    reason: isLoopback(location.hostname) ? "loopback" : null,
  };
}

// Error correction level M, which is what stays readable on a
// screen held at arm's length without making the code so dense
// that a phone two years old cannot resolve it.
function drawQr(canvas, text) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const modules = qr.getModuleCount();
  const quiet = 4; // the margin a scanner needs to find the edges
  // Enough backing pixels that the browser is always scaling this
  // down rather than up, whatever the panel's width works out to.
  const scale = 6;
  const size = (modules + quiet * 2) * scale;
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#f0e6d9";
  ctx.fillRect(0, 0, size, size);
  ctx.fillStyle = "#0b0907";
  for (let row = 0; row < modules; row++) {
    for (let col = 0; col < modules; col++) {
      if (qr.isDark(row, col)) {
        ctx.fillRect((col + quiet) * scale, (row + quiet) * scale, scale, scale);
      }
    }
  }
}

let camera = null; // { stream, raf }
/* What the scanner has actually seen, which is the thing that was
   missing when it went quiet. Every frame is counted, every decode is
   counted, and whatever came out of the last one is kept, so that a
   scanner which finds nothing can say which kind of nothing it is:
   no picture at all from the camera, a picture with no code in it, or
   a code it read and could not use. Those three look identical from
   the outside and have completely different fixes. */
let scanStats = null;
let scanTimer = null;

// jsQR rather than the browser's own BarcodeDetector, which Safari
// does not have and Safari is the browser somebody adding an
// iPhone is holding.
async function startCamera(onText) {
  const stream = await navigator.mediaDevices.getUserMedia({
    // Asked for more pixels than the default, because how well a code
    // reads comes down to how many pixels fall across one of its
    // squares, and a default capture is often 640 across. Ideal
    // rather than required: a camera that cannot manage it should
    // give what it has rather than refuse outright.
    video: {
      facingMode: "environment",
      width: { ideal: 1280 },
      height: { ideal: 720 },
    },
    audio: false,
  });
  xVideoEl.srcObject = stream;
  xVideoEl.setAttribute("playsinline", "");
  await xVideoEl.play();
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  camera = { stream, raf: 0 };
  scanStats = {
    startedAt: Date.now(), frames: 0, decodes: 0,
    width: 0, height: 0, lastText: null, lastReason: null,
  };
  const look = () => {
    if (!camera) return;
    camera.raf = requestAnimationFrame(look);
    const w = xVideoEl.videoWidth, h = xVideoEl.videoHeight;
    // No dimensions means the camera opened and is sending nothing.
    // Counted rather than returned from in silence, because this used
    // to be indistinguishable from a code that would not read.
    if (!w || !h) return;
    scanStats.frames++;
    scanStats.width = w;
    scanStats.height = h;
    canvas.width = w;
    canvas.height = h;
    // The whole frame, so nothing is cropped away: a code the person
    // has centred is in here whatever the aspect ratio works out to.
    ctx.drawImage(xVideoEl, 0, 0, w, h);
    const found = jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: "dontInvert" });
    if (!found || !found.data) return;
    scanStats.decodes++;
    if (found.data !== scanStats.lastText) {
      // Logged once per distinct string rather than per frame, which
      // at sixty frames a second is the difference between a record
      // and a flood.
      scanStats.lastText = found.data;
      console.info("hearth: scanner read a code,", found.data.length, "characters:",
        found.data.slice(0, 160));
    }
    onText(found.data);
  };
  look();
}

function stopCamera() {
  clearInterval(scanTimer);
  if (!camera) return;
  cancelAnimationFrame(camera.raf);
  for (const track of camera.stream.getTracks()) track.stop();
  xVideoEl.srcObject = null;
  camera = null;
}

/* ---------- the screen ---------- */
/* ---------- how the connection is getting on ----------

   The session no longer decides once whether a relay can be reached;
   it keeps trying for its whole ten minutes. So the screen's job is
   to say that it is still working, and to say that it is not getting
   anywhere only when that has been true for long enough to mean
   something. Three seconds of silence is what a cold connection to a
   public relay looks like on a phone; a minute of it is a problem.

   The thresholds below are deliberately far apart. Nothing is said at
   all for the first stretch, because the ordinary case resolves
   inside it and a warning that retracts itself teaches people to
   ignore warnings. */
const TRANSPORT_QUIET_MS = 12000;   // before this, say nothing
// Thirty seconds, because by then a relay that is going to open has
// had five attempts at it under the backoff above, and the slowest
// cold connection seen was a few seconds. Sooner than this and the
// ordinary case gets a warning it does not need; later and somebody
// is watching a spinner with nothing to act on. It is also a
// twentieth of the session, so acting on it costs nothing: the
// retrying carries on behind whatever the screen says.
const TRANSPORT_TROUBLE_MS = 30000;
// A device that scanned has said hello and is waiting to be answered.
// That is a different silence — the connection is fine and the other
// device is not there, most likely because its code has already been
// used or its screen has moved on — and it deserves longer before
// being called, because the other person may be reading a prompt.
const PEER_SILENCE_MS = 60000;

let transportTimer = null;

// Kept where it can be read after the fact. Somebody reporting that a
// transfer would not start can be asked for this, and it names which
// relay was slow and by how much rather than leaving it to memory.
function recordTransport(health) {
  if (!health) return;
  try {
    localStorage.setItem("hearth:last-transport", JSON.stringify({
      at: Math.floor(Date.now() / 1000),
      elapsedMs: health.elapsedMs,
      live: health.live,
      relays: health.relays,
    }));
  } catch (err) {
    // A full or blocked store costs a diagnostic, not a transfer.
  }
}

// Whatever this screen is waiting for, it says so, and past a point
// it offers a way out. A session runs for ten minutes and goes on
// retrying underneath, but nobody should be made to watch a spinner
// that neither explains itself nor can be acted on: the three-second
// failure this replaced was wrong because it gave up too early, not
// because giving somebody a button was wrong.
function watchTransport() {
  clearInterval(transportTimer);
  const startedAt = Date.now();
  let offered = false;
  transportTimer = setInterval(() => {
    if (!xfer) { clearInterval(transportTimer); return; }
    const health = xfer.transport();
    if (!health) return;
    const waited = Date.now() - startedAt;
    const answered = xfer.peers().length > 0;

    let message = null;
    let actionable = false;
    if (health.live === 0) {
      if (waited >= TRANSPORT_TROUBLE_MS) {
        message = "Hearth still hasn't got a connection. It keeps trying, so this may come " +
          "good on its own, and starting again is worth a go if it doesn't.";
        actionable = true;
        recordTransport(health);
      } else if (waited >= TRANSPORT_QUIET_MS) {
        message = "still connecting";
      }
    } else if (xferScanned && !answered && waited >= PEER_SILENCE_MS) {
      // Connected, said hello, and nothing came back.
      message = "Your other device hasn't answered. Its code may already have been used, in " +
        "which case showing a fresh one there and scanning again is what fixes it.";
      actionable = true;
      recordTransport(health);
    }

    if (!message) {
      xShow(xTransportEl, false);
      return;
    }
    xTransportEl.textContent = message;
    xShow(xTransportEl, true);
    // Added beside whatever the screen already offers rather than
    // replacing it, and only once, so it does not flicker under a
    // thumb every second.
    if (actionable && !offered) {
      offered = true;
      const again = document.createElement("button");
      again.textContent = "start again";
      again.addEventListener("click", retryTransfer);
      xButtonsEl.appendChild(again);
    }
  }, 1000);
}

/* ---------- a scanner that says what it is seeing ----------

   It used to go quiet. Every way out of the scan loop except a
   successful read was a bare return, so a camera sending no picture
   and a code that would not decode produced exactly the same thing on
   screen: nothing at all, indefinitely. Whichever of those is
   happening, the person holding the phone can now see which. */
const SCAN_NO_PICTURE_MS = 4000;  // a camera that has sent no frame
const SCAN_LOOKING_MS = 10000;    // frames, but nothing read yet
const SCAN_STUCK_MS = 25000;      // long enough to offer another way

function watchScan() {
  clearInterval(scanTimer);
  let offered = false;
  scanTimer = setInterval(() => {
    if (!camera || !scanStats) { clearInterval(scanTimer); return; }
    const waited = Date.now() - scanStats.startedAt;
    let message = null;
    let actionable = false;

    if (scanStats.lastReason) {
      // Already said on screen by xFail, and it is a real answer
      // rather than a silence, so this stays out of the way.
      message = null;
    } else if (scanStats.frames === 0) {
      if (waited >= SCAN_NO_PICTURE_MS) {
        message = "The camera is on but isn't sending a picture. On some phones another app " +
          "still has it open.";
        actionable = waited >= SCAN_LOOKING_MS;
      }
    } else if (scanStats.decodes === 0) {
      if (waited >= SCAN_STUCK_MS) {
        message = "Hearth can see through the camera but hasn't been able to read the code. " +
          "Try filling more of the picture with it, or showing a code from this device instead.";
        actionable = true;
      } else if (waited >= SCAN_LOOKING_MS) {
        message = "still looking for a code";
      }
    }

    if (!message) {
      xShow(xTransportEl, false);
      return;
    }
    xTransportEl.textContent = message;
    xShow(xTransportEl, true);
    if (actionable && !offered) {
      offered = true;
      console.info("hearth: scanner has found nothing", JSON.stringify(scanStats));
      const swap = document.createElement("button");
      swap.textContent = "show a code instead";
      swap.addEventListener("click", () => { stopCamera(); beginShowing(); });
      xButtonsEl.appendChild(swap);
    }
  }, 1000);
}

// The same thing this screen was doing, from the beginning, with
// fresh burners. A session that never reached a relay has nothing to
// lose by being replaced, and one whose code was already spent needs
// to be.
function retryTransfer() {
  clearInterval(transportTimer);
  xShow(xTransportEl, false);
  const scanned = xferScanned;
  if (xfer) xfer.cancel();
  xfer = null;
  if (scanned) beginScanned(scanned);
  else if (xferShowing) beginShowing();
  else beginScanning();
}

let xfer = null;        // the running session
let xferRole = null;    // "holder" | "joiner"
let xferChosen = null;  // in flow A, the code the person tapped
// What to do if this closes with nothing received, which is only
// ever set when the transfer was opened from the landing screen and
// there is no identity behind it to go back to.
let xferOnClose = null;
// What this screen was doing, so that starting again can do it again:
// the code this device scanned, if it scanned one, and whether it is
// the device showing a code.
let xferScanned = null;
let xferShowing = false;
// Where the room is, as told by each device offering a key, kept
// beside the key itself until one of them is accepted.
const xferRelays = new Map();

function xShow(el, on) { el.hidden = !on; }

// One place that puts the screen into a state, so no state can
// leave a control from the previous one lying about.
function xRender(opts) {
  xTitleEl.textContent = opts.title || "";
  xNoteEl.textContent = opts.note || "";
  xShow(xNoteEl, !!opts.note);
  xPromptEl.textContent = opts.prompt || "";
  xShow(xPromptEl, !!opts.prompt);
  xShow(xQrEl, !!opts.qr);
  xShow(xCamEl, !!opts.camera);
  xShow(xSasEl, !!opts.sas);
  if (opts.sas) {
    xEmojiEl.textContent = opts.sas.emoji.join("");
    xDigitsEl.textContent = opts.sas.digits;
  }
  xShow(xListEl, !!opts.list);
  xListEl.innerHTML = "";
  for (const entry of opts.list || []) {
    const btn = document.createElement("button");
    const em = document.createElement("div");
    em.className = "xEmoji";
    em.textContent = entry.sas.emoji.join("");
    const dg = document.createElement("div");
    dg.className = "xDigits";
    dg.textContent = entry.sas.digits;
    btn.append(em, dg);
    btn.addEventListener("click", () => opts.onPick(entry));
    xListEl.appendChild(btn);
  }
  xButtonsEl.innerHTML = "";
  for (const b of opts.buttons || []) {
    const btn = document.createElement("button");
    btn.textContent = b.label;
    if (b.quiet) btn.className = "quiet";
    btn.addEventListener("click", b.onClick);
    xButtonsEl.appendChild(btn);
  }
  xSpinEl.textContent = opts.waiting || "";
  xShow(xSpinEl, !!opts.waiting);
  xShow(xFailEl, false);
  if (opts.alt) {
    xAltBtn.textContent = opts.alt.label;
    xAltBtn.onclick = opts.alt.onClick;
  }
  xShow(xAltBtn, !!opts.alt);
}

function xFail(message) {
  xFailEl.textContent = message;
  xShow(xFailEl, true);
}

function closeTransfer() {
  stopCamera();
  clearInterval(transportTimer);
  xferScanned = null;
  xferShowing = false;
  xShow(xTransportEl, false);
  if (xfer) recordTransport(xfer.transport());
  if (xfer) xfer.cancel();
  xfer = null;
  xferChosen = null;
  xShow(xMultiEl, false);
  xferEl.hidden = true;
  const after = xferOnClose;
  xferOnClose = null;
  if (after) after();
}

xCloseBtn.addEventListener("click", closeTransfer);

/* ---------- starting one ---------- */

/* ---------- arriving on a pairing link ----------

   The other device's code sent this browser here with a pairing URI
   in the fragment. Which side of the transfer this device is on is
   already settled by that URI: a code offering a key wants a holder
   to scan it, and a code asking for one wants a joiner, so nothing
   has to be guessed from what this device happens to hold.
   ============================================================ */
function pendingPairing() {
  if (!pairFromFragment(location.hash.slice(1))) return null;
  try {
    // The whole address, through the same reader the camera uses.
    const scanned = readPairingCode(location.href);
    return { scanned, role: scanned.mode === "offer" ? "holder" : "joiner" };
  } catch (err) {
    // An unreadable or unknown-version code. Kept rather than
    // swallowed, so the screen can say so instead of the link
    // appearing to do nothing.
    return { error: err.message };
  }
}

// Once, and then out of the address bar: a reload should not start the
// transfer again, and a bookmark of this page should not carry
// somebody's pairing parameters around.
function consumePairing() {
  // Cut from the marker to the end, which is where the URI is, and
  // tidy the separator it leaves behind.
  const fragment = location.hash.slice(1);
  const at = fragment.indexOf(PAIR_PARAM + "=");
  const rest = (at === -1 ? fragment : fragment.slice(0, at)).replace(/&$/, "");
  history.replaceState(null, "", location.pathname + location.search + (rest ? "#" + rest : ""));
}

// Straight into the transfer, with no camera and no method to pick,
// because the code has already been read by the phone that opened
// this page.
function openPairing(pairing, onClose) {
  consumePairing();
  xferRole = pairing.role;
  xferChosen = null;
  xferOnClose = onClose || null;
  accountOverlayEl.hidden = true;
  xferEl.hidden = false;
  xShow(xMultiEl, false);
  if (pairing.error) {
    xRender({
      title: "add a device",
      note: "That code couldn't be read: " + pairing.error,
      buttons: [{ label: "close", onClick: closeTransfer }],
    });
    return;
  }
  // A code asking for a key, opened on a device that has none, is
  // somebody who scanned with the wrong device of the two.
  if (pairing.role === "holder" && (!identity || !identity.holdsPrivateKey)) {
    xRender({
      title: "add a device",
      note: identity
        ? "Your extension holds this identity's key and hearth only ever asks it to sign, " +
          "so there is no key here to send."
        : "That code is asking for an account, and this device doesn't have one yet. Scan it " +
          "with the device that does.",
      buttons: [{ label: "close", onClick: closeTransfer }],
    });
    return;
  }
  beginScanned(pairing.scanned);
}

function openTransfer(role, onClose) {
  xferRole = role;
  xferChosen = null;
  xferOnClose = onClose || null;
  accountOverlayEl.hidden = true;
  xferEl.hidden = false;
  xShow(xMultiEl, false);

  if (role === "holder") {
    // A key held by an extension is a key this page has never seen
    // and cannot send. Said plainly rather than by a button that
    // fails when pressed.
    if (!identity.holdsPrivateKey) {
      xRender({
        title: "add a device",
        note: "Your extension holds this identity's key and hearth only ever asks it to sign, " +
          "so there is no key here to send. Add the other device from your extension instead.",
        buttons: [{ label: "close", onClick: closeTransfer }],
      });
      return;
    }
    if (keyLocked()) {
      xRender({
        title: "add a device",
        note: "Your key is locked to this device, so it can't be sent from here. Unlocking " +
          "is one tap, and you can lock it again afterwards.",
        buttons: [
          { label: "unlock this device", onClick: () => { setKeyLocked(false); openTransfer("holder"); } },
          { label: "not now", quiet: true, onClick: closeTransfer },
        ],
      });
      return;
    }
  }

  // The offer hearth makes first: the new device shows a code and the
  // device that already has the key scans it. The other way round is
  // one tap away, for a pair whose cameras are the wrong way round.
  if (role === "holder") beginScanning();
  else beginShowing();
}

function beginShowing() {
  stopCamera();
  xferScanned = null;
  xferShowing = true;
  const showing = xferRole === "joiner";
  // The screen is put up before the session starts, because the
  // session hands back its code the moment it has one and a render
  // after that would clear the canvas it was just drawn on.
  xRender({
    title: showing ? "your new device" : "add a device",
    note: showing
      ? "Scan this with the device that already has your identity."
      : "Scan this with the device you're adding.",
    waiting: "waiting for your other device",
    alt: {
      label: "scan the code it shows instead",
      onClick: () => { if (xfer) xfer.cancel(); beginScanning(); },
    },
  });
  xfer = Keyxfer.startSession({
    role: xferRole,
    showing: true,
    relays: Keyxfer.DEFAULT_RELAYS,
    on: onTransferEvent,
  });
  watchTransport();
}

// A pairing URI in hand, however it got here: read off the camera, or
// carried in the fragment of a link the phone's own camera app opened.
// From here the two are the same transfer.
function beginScanned(scanned) {
  xferScanned = scanned;
  xferShowing = false;
  const title = xferRole === "holder" ? "add a device" : "your new device";
  xRender({ title, waiting: "connecting" });
  // Started rather than gated. The relays that matter here are the
  // ones the code named, because those are where the other device is
  // listening, and the session keeps trying them for as long as it
  // lives instead of ruling on them once.
  xfer = Keyxfer.startSession({
    role: xferRole,
    showing: false,
    scanned,
    on: onTransferEvent,
  });
  watchTransport();
}

function beginScanning() {
  xferScanned = null;
  xferShowing = false;
  xRender({
    title: xferRole === "holder" ? "add a device" : "your new device",
    note: "Point this at the code on your other device.",
    camera: true,
    waiting: "looking for a code",
    alt: {
      label: "show a code instead",
      onClick: () => { stopCamera(); beginShowing(); },
    },
  });
  let taken = false;
  watchScan();
  startCamera((text) => {
    if (taken) return;
    let scanned;
    try {
      scanned = readPairingCode(text);
    } catch (err) {
      // Read something, cannot use it. Kept on the stats as well as
      // on screen, so the watcher below stops saying it is still
      // looking when it has in fact found and refused something.
      scanStats.lastReason = err.message;
      xFail(err.message);
      return;
    }
    // A code offering what this device is offering is the other
    // device in the same role, which is nobody's transfer.
    const wantMode = xferRole === "holder" ? "offer" : "request";
    if (scanned.mode !== wantMode) {
      const why = "that code is from a device in the same position as this one, so neither " +
        "of you would be receiving anything";
      scanStats.lastReason = why;
      xFail(why);
      return;
    }
    taken = true;
    console.info("hearth: scanner accepted a code after", scanStats.frames, "frames");
    stopCamera();
    beginScanned(scanned);
  }).catch((err) => {
    xRender({
      title: xferRole === "holder" ? "add a device" : "your new device",
      note: "Hearth couldn't use the camera on this device: " + err.message,
      buttons: [{ label: "show a code instead", onClick: beginShowing }],
    });
  });
}

/* ---------- what the session says, and what the screen does ---------- */
async function onTransferEvent(type, data) {
  // The first relay to come up. The flow is already proceeding by
  // then, so this only takes down whatever the screen was saying
  // about waiting for one.
  if (type === "connected") {
    xShow(xTransportEl, false);
    return;
  }

  if (type === "qr") {
    const link = pairingLink(data);
    drawQr(xQrCanvas, link.url);
    xShow(xQrEl, true);
    if (!link.reachable) {
      xMultiEl.textContent = link.reason === "loopback"
        ? "This copy of hearth is being served from an address that only means something on " +
          "this machine, so another device cannot open what this code points at. It works " +
          "wherever hearth is served from an address both devices can reach."
        : "This copy of hearth is not being served over the web, so another device cannot " +
          "open what this code points at.";
      xShow(xMultiEl, true);
    }
    return;
  }

  // §3.8. A notice rather than a refusal: the code on the two
  // screens is what settles which device is the real one, and this
  // says only that somebody else pointed a camera at it.
  if (type === "multi") {
    xMultiEl.textContent = "Another device also responded to this code. If that wasn't you, " +
      "someone nearby may have scanned it. Nothing was shared with them.";
    xShow(xMultiEl, true);
    return;
  }

  // §4 step 9 and §5 step 11: the tap that releases the key. The
  // line naming what the other side claims to be is the only
  // defence against a page that is itself pretending to be the
  // device being added, which the code comparison cannot catch.
  if (type === "consent") {
    const claim = data.origin
      ? "a browser at " + data.origin
      : (data.plat ? "a " + data.plat + " device" : "a device");
    xRender({
      title: "add a device",
      prompt: "Send your key to " + claim + " showing this?",
      sas: data.sas,
      note: "Check that these four emoji and these six digits are what your other device is " +
        "showing. If they aren't, this isn't your device.",
      buttons: [
        { label: "send my key", onClick: () => sendKey(data) },
        { label: "not mine", quiet: true, onClick: () => xfer && xfer.deny(data.peer) },
      ],
    });
    return;
  }

  // The receiving side, waiting. In flow B there is exactly one
  // device this could be, because this device scanned its code; in
  // flow A anybody may have scanned ours, so the codes are a list
  // and the person picks the one their other device is showing.
  if (type === "sas") {
    if (data.single) {
      xRender({
        title: "your new device",
        note: "Your other device should be showing this. Approve it there.",
        sas: data.list[0].sas,
        waiting: "waiting for your other device",
      });
    } else {
      xRender({
        title: "your new device",
        prompt: "Tap the code your other device shows",
        list: data.list,
        onPick: (entry) => { xferChosen = entry.peer; offerLogin(entry.peer); },
      });
    }
    return;
  }

  if (type === "arrived") {
    if (data.single || xferChosen === data.peer) offerLogin(data.peer);
    return;
  }

  // The other device saying where the room is. Held rather than
  // written down: until the person has agreed to the identity that
  // arrived, this is a stranger's list of servers and has no business
  // on this device.
  if (type === "rumor") {
    if (data.kind !== KINDS.ROOM_RELAYS) return;
    try {
      const parsed = JSON.parse(data.content);
      if (Array.isArray(parsed.relays)) xferRelays.set(data.from, parsed.relays);
    } catch (err) {
      // A list that will not parse is a list this device does without.
    }
    return;
  }

  if (type === "sent") {
    // Kept for a transfer that worked but took its time. The
    // interesting report is not only the one that failed.
    recordTransport(xfer && xfer.transport());
    recordTransfer({
      ts: Math.floor(Date.now() / 1000),
      role: "holder",
      rung: "relay",
      sas: data.sas.emoji.join("") + " " + data.sas.digits,
      peer: data.peer,
      multi: false,
    });
    xRender({
      title: "add a device",
      note: "Your key is on its way. Your other device will ask you to confirm who you are " +
        "before it keeps it.",
      sas: data.sas,
      waiting: "waiting for your other device",
    });
    return;
  }

  if (type === "waiting") {
    xRender({ title: "add a device", waiting: "waiting for your other device" });
    return;
  }

  if (type === "done") {
    if (xferRole === "holder") {
      xRender({
        title: "add a device",
        note: "Your other device has your identity now.",
        buttons: [{ label: "close", onClick: closeTransfer }],
      });
    }
    return;
  }

  if (type === "expired") {
    stopCamera();
    xRender({
      title: xferRole === "holder" ? "add a device" : "your new device",
      note: "That took longer than ten minutes, so the code is no longer good. Nothing was sent.",
      buttons: [{ label: "start again", onClick: () => openTransfer(xferRole) }],
    });
    return;
  }

  if (type === "error") {
    xFail(data);
    return;
  }
}

async function sendKey(data) {
  xRender({ title: "add a device", sas: data.sas, waiting: "sending" });
  await xfer.approve(data.peer, S.utils.bytesToHex(identity.privkey), "device");
  // Straight after the key, in the same session, to the same burner:
  // the relays this device has reached this room on. A device holding
  // a key and no idea where the room is would land on a box asking
  // for a server address, which is precisely what somebody who just
  // held two phones together was spared. Sent immediately rather than
  // waiting for the receipt, because the far side stores the key and
  // reloads the moment its owner agrees, and a message that arrives
  // after that reload arrives nowhere.
  const relays = rememberedRelays().slice(0, 8);
  if (relays.length > 0) {
    await xfer.sendTo(data.peer, KINDS.ROOM_RELAYS, [], JSON.stringify({ relays }));
  }
}

// §4 steps 14 and 15, §5 step 16: the key is in hand and still not
// stored. The person is shown who it would make them, because a key
// that arrived from somebody else's device is a login somebody else
// chose, and the name is the part of it they can recognise.
async function offerLogin(peerHex) {
  const who = xfer.chosen(peerHex);
  if (!who) {
    xRender({ title: "your new device", waiting: "waiting for your other device" });
    return;
  }
  xRender({ title: "your new device", waiting: "checking who that is" });
  const name = await lookupNostrName(who.pubkey).catch(() => null);
  const called = name || shortName(who.pubkey);
  // A device that arrived here from the landing screen has no
  // identity of its own to lose, and telling it that something is
  // about to be written over would be a lie.
  let note = "";
  if (identity && identity.holdsPrivateKey) {
    note = "This takes the place of the identity this device is using now, " +
      shortName(identity.pubkey) + ", which is written over and gone.";
  } else if (identity) {
    note = "This takes the place of the identity this device is using now.";
  }
  xRender({
    title: "your new device",
    prompt: "Log in as " + called + "?",
    note,
    buttons: [
      { label: "log in", onClick: () => keepReceivedKey(peerHex) },
      { label: "no", quiet: true, onClick: closeTransfer },
    ],
  });
}

async function keepReceivedKey(peerHex) {
  xRender({ title: "your new device", waiting: "keeping it" });
  // Before the reload below takes this page away with it.
  recordTransport(xfer.transport());
  // The two messages were sent together but travel separately, and
  // the second one is what saves this device from asking for a server
  // address. Worth a moment before giving up on it, and no longer,
  // because the key is the part that matters and it is already here.
  for (let i = 0; i < 30 && !xferRelays.has(peerHex); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  const record = await xfer.accept(peerHex);
  if (!record) {
    xFail("that key is no longer being offered");
    return;
  }
  await storeSealedPrivkey(S.utils.hexToBytes(record.privkeyHex));
  localStorage.removeItem(SIGNER_CHOICE_KEY);
  // Remembered exactly as a relay this device had reached would be,
  // last first, so the other device's first choice ends up this
  // device's first choice. With this list in hand the reload below
  // goes straight into the room and asks nothing.
  for (const url of (xferRelays.get(peerHex) || []).slice().reverse()) {
    if (typeof url === "string" && /^wss?:\/\//.test(url)) rememberRelay(url);
  }
  // §2.2's unlock setting travels with the key. Hearth has one
  // behaviour today, the default, and stores what arrived so that
  // the setting is not lost by the device that carried it.
  localStorage.setItem(LOCK_KEY, record.lock || "device");
  // §8: the key arrives locked to this device. Whoever set this
  // device up did so by holding two devices together once, which is
  // not the same as deciding this is a place keys leave from.
  localStorage.setItem(RECEIVE_ONLY_KEY, "1");
  recordTransfer({
    ts: Math.floor(Date.now() / 1000),
    role: "joiner",
    rung: "relay",
    sas: record.sas.emoji.join("") + " " + record.sas.digits,
    peer: record.peer,
    multi: record.multi,
  });
  // A reload rather than a swap in place, for the reason importing a
  // key reloads: everything on screen belongs to the identity that
  // was signing a moment ago.
  location.reload();
}

// Both ways, and unguarded in both. The specification asks for one
// tap, and a lock whose key is in the same room as the door is not
// made stronger by making it stiff.
function setKeyLocked(locked) {
  if (locked) localStorage.setItem(RECEIVE_ONLY_KEY, "1");
  else localStorage.removeItem(RECEIVE_ONLY_KEY);
  renderDeviceSection();
}

function renderDeviceSection() {
  const locked = keyLocked();
  // The state first, then the control that changes it, so what the
  // button does is read in the light of what is true now.
  aoReceiveOnlyEl.textContent = locked
    ? "Your key stays here. This device won't hand it to another one, so the prompt that " +
      "would send it never comes up. Leave it locked unless you're adding a device from here."
    : "This device can hand your key to another one, which is what adding a device from here " +
      "needs. Lock it again afterwards.";
  aoAllowSendBtn.textContent = locked ? "unlock this device" : "lock key to this device";
  renderTransfers();
}

aoAddDeviceBtn.addEventListener("click", () => openTransfer("holder"));
aoFromDeviceBtn.addEventListener("click", () => openTransfer("joiner"));
aoAllowSendBtn.addEventListener("click", () => setKeyLocked(!keyLocked()));

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
  registerWorker();

  layout();
  setMode(MODE_VOICE, false); // the room's face is the fire
  new ResizeObserver(layout).observe(mainEl);

  // A pairing link this device is the holder for. It waits until here
  // because sending a key needs the key, and acquireIdentity above is
  // what settles whether this device has one.
  const pairing = pendingPairing();
  if (pairing && !pairing.error && pairing.role === "holder") openPairing(pairing);

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
