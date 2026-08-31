# Push: the half of it that is bothy's

Hearth can already raise a notification while it is open. It cannot raise one when it
is closed, because nothing in a page runs when the page is not running. That takes a
push, and a push takes a server holding a key and a list of endpoints. This is what
that server has to do.

Everything on hearth's side is written and shipped. It degrades quietly: a relay with
no key advertised gets notifications while hearth is open and nothing more, and the
account overlay says exactly that rather than promising otherwise.

## What hearth already does

**Reads a key.** `loadRelayInfo` takes `push_key` out of the relay's NIP-11 document.
It is the public half of a VAPID keypair, base64url, unpadded — the same string a
browser wants for `applicationServerKey`.

**Subscribes.** With a key in hand and notifications turned on, hearth calls
`pushManager.subscribe({ userVisibleOnly: true, applicationServerKey })` and hands the
result over as a NIP-86 call:

```
POST <relay over https>
Authorization: Nostr <base64 NIP-98 event>
Content-Type: application/nostr+json+rpc

{"method":"subscribepush","params":[{
  "endpoint":"https://fcm.googleapis.com/fcm/send/...",
  "expirationTime":null,
  "keys":{"p256dh":"<base64url>","auth":"<base64url>"}
}]}
```

`unsubscribepush` takes `[endpoint]` and undoes it. Both go through `manageRelay`, so
they are authenticated the way every other management call is: a kind 27235 event over
that exact method, URL and body. **The signer of that event is the member the
subscription belongs to.** The body never says whose it is, and the relay must not
believe a body that tries to.

**Receives.** `sw.js` handles `push` and expects a JSON payload of

```json
{ "room": "the bothy", "kind": "message" }
```

`kind` is `"message"` or `"voice"`, and `url` is optional. Anything it cannot parse
still raises a notification, because something happened and somebody asked to hear
about it.

## What bothy has to grow

**A VAPID keypair**, generated once and kept. The public half goes in the NIP-11
document as `push_key`; the private half signs the JWT on every send. Rotating it
invalidates every subscription, so it wants to live wherever the relay's other secrets
live.

**A subscription table.** Keyed by endpoint, holding the pubkey it was registered by,
the group, `p256dh`, `auth`, and when it was last seen working. One member has several:
a phone, a laptop, a home screen install and a browser tab are four different
endpoints. Store the pubkey from the NIP-98 event, never from the body.

**A send on a stored message.** When a kind 9 lands for a group, push to every member
of that group with a subscription, except the pubkey that signed it. Payload is the
room's name and `"kind":"message"` — nothing else, and specifically not the message.

**A send on somebody arriving at the fire.** Kind 25051 is ephemeral, so nothing is
stored, but the relay still sees every one. It has to keep the same presence table
hearth keeps — last seen per pubkey, gone after 13 seconds — and push only on the
transition from absent to present. Presence heartbeats every 5 seconds, so a relay that
pushes on the event rather than on the transition will send twelve notifications a
minute per person in the call. This is the one that will go wrong if it is written
quickly.

**Encryption.** Web push payloads are encrypted to the subscription's own keys with
aes128gcm (RFC 8291) and authorised by a VAPID JWT (RFC 8292). Neither is worth
writing by hand; every language has a library that takes a subscription, a payload and
a VAPID keypair and does both.

**Cleanup.** A push service answering 404 or 410 means that endpoint is gone for good.
Delete the row. Anything else — 429, a 5xx — is worth a retry and not worth a deletion.

## What it must not do

**No message content in the payload.** It travels through Apple's or Google's push
service to reach the phone, and the contents of the room are not theirs to hold. The
notification says which room and what kind of thing; anybody who wants to know what was
said opens hearth and reads it from the relay.

**No name in the payload either**, for the same reason. Hearth's own banner, raised
while it is open, does say who — it reads that from events it already has and nothing
leaves the device.

**Do not push to somebody whose socket is open.** They are already getting the banner
hearth raises itself, and two notifications for one message is worse than one.

## What it costs

A push endpoint identifies a device to the push service, and registering one tells the
relay which devices a member has. That is a real thing to hand over, and it is why this
is something a person turns on in the account overlay rather than something hearth does
on their behalf. A relay that never advertises a `push_key` never learns any of it, and
hearth works.
