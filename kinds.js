/* ============================================================
   Every nostr event kind hearth speaks, in one place. There are
   eight now and there will be a couple of dozen once channels,
   direct messages and device pairing land, so they live here
   rather than as bare numbers scattered through app.js.
   ============================================================ */
const KINDS = {
  // NIP-01 metadata. Hearth tags it into the group (an `h` tag),
  // which files it in the relay's members-only partition — a name
  // chosen for the group is readable by the group, not the world.
  PROFILE: 0,

  // NIP-29 group chat message.
  CHAT: 9,

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

  // NIP-98 HTTP auth, for the relay's NIP-86 management API.
  HTTP_AUTH: 27235,
};
