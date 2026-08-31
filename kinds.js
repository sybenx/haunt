/* ============================================================
   Every nostr event kind hearth speaks, in one place. There are
   ten now and there will be a couple of dozen once channels,
   direct messages and device pairing land, so they live here
   rather than as bare numbers scattered through app.js.
   ============================================================ */
const KINDS = {
  // NIP-01 metadata: a person's global nostr profile. Read only,
  // and read for one thing — a name to fall back on when there is no
  // kind 30078 to prefer. Hearth used to publish one of these per
  // group, which is what MEMBER below replaced: a kind 0 is keyed by
  // pubkey and kind alone, so the same person's real profile,
  // arriving from anywhere else, took the group's copy's place.
  PROFILE: 0,

  // NIP-78 application-specific data: how one person appears in one
  // group. Addressable, so the relay keys it by (pubkey, kind, d),
  // and the `d` names the group — one key can be called different
  // things in two groups without either replacing the other.
  MEMBER: 30078,

  // NIP-29 group chat message.
  CHAT: 9,

  // NIP-65. Not a kind Hearth publishes or stores: it is read once,
  // off the public relays, to find where somebody signing in with an
  // extension keeps the profile their name is in.
  RELAY_LIST: 10002,

  // NIP-29 moderation: the owner mints an invite code. Owner-only
  // on the relay side, and the stored event is withheld from even
  // the group's members, because its code tag is a bearer token.
  CREATE_INVITE: 9009,

  // NIP-29 join request. With a live code it admits a stranger;
  // from an existing member or the owner it needs no code at all.
  JOIN_REQUEST: 9021,

  // NIP-42 client authentication response.
  CLIENT_AUTH: 22242,

  // Hearth's own, no NIP: WebRTC signalling (offers, answers, ICE
  // candidates) and call presence. Ephemeral range, so relays
  // never store them. See app.js's voice section for why presence
  // is deliberately not the same thing as membership.
  CALL_SIGNAL: 25050,
  CALL_PRESENCE: 25051,

  // Hearth's own, no NIP: the relays this group can be reached on,
  // sent to a device that has just been given this identity. A new
  // device has the key and no idea where the room is, and the list
  // is per-device, so without this the first thing it would ask for
  // is a server address — which is the one thing the transfer
  // existed to avoid.
  //
  // Never published as an event. It is a rumor inside a gift wrap,
  // so the ephemeral range it sits in never comes up: no relay sees
  // it as anything but the wrap it travels in. It is here rather
  // than in keyxfer.js because it is hearth's, not the transfer
  // specification's, and that file implements only what other
  // clients also implement.
  ROOM_RELAYS: 25052,

  // NIP-98 HTTP auth, for the relay's NIP-86 management API.
  HTTP_AUTH: 27235,
};

// The kinds a device-to-device key transfer speaks — the seal, the
// gift wrap and the six rumors inside them — are deliberately not
// here. They live in keyxfer.js, which implements a specification
// written against no particular client and knows nothing about
// hearth or about bothy: a transfer travels over public relays and
// shares not one kind with anything above.
