# Haunt

Haunt is a voice and chat client for a small group of friends. It is meant for ten to
twenty people who already know each other, and it replaces the private Discord server
that such a group usually ends up on. There is no public directory, no discovery and no
strangers.

## What it talks to

Haunt runs against a [bothy](https://github.com/sybenx/bothy) relay. One person in the
group owns and hosts that relay, and it holds the group's membership, its moderation
state and the history of everything said in public channels. A group is a relay, and a
person may belong to more than one.

Haunt is a static page with no backend of its own. Everything it needs is either in the
relay or on the user's device.

## Joining

A person joins by opening one link, and that link is the only thing they are ever asked
to paste. A new member's link carries the relay and an invite code. A returning member's
link carries only the relay. When Haunt has been served by the relay itself, the link
carries nothing, because the app already knows which relay it came from.

Someone who arrives by link is never asked to configure anything. The field for typing a
relay address by hand exists for the person who arrived with nothing, and it is the
unusual path rather than the front door.

## Identity

Identity is a nostr keypair, and the people using Haunt are not expected to know that. A
new member's key is created for them silently when they first arrive.

A member moves their identity to a second device by showing a code on one screen and
scanning it with the other. The code carries a temporary public key rather than the
identity itself, so photographing it achieves nothing; the device that already holds the
key approves the transfer and delivers the key over an encrypted message. Haunt never
asks anyone to paste a secret into a box, in either direction.

## What is private and what is not

Public channels are readable by the relay. That is deliberate, and it is what gives the
group durable history that survives a new device, a lost phone, or a member joining
years late. The relay's owner can read them, and Haunt says so rather than implying
otherwise.

Direct messages between two members are encrypted end to end and are not stored on the
group's relay at all. They travel over the relays the recipient has published for that
purpose, which are usually public ones. This means the group's owner cannot read them
and cannot see who is talking to whom, and the option to do either does not exist rather
than being declined.

A member who wants their direct messages held somewhere they control runs their own
bothy and points their message relays at it.

## Voice and video

Voice is WebRTC. Media never passes through the bothy relay, which carries only the
signalling — who is in the call, and one negotiation per participant.

Calls are distributed through a selective forwarding unit rather than a mesh, so a
participant sends one stream regardless of how many people are listening. This is what
makes a call of ten people work on a home connection, and it is what makes one person
streaming their screen to the rest possible at all.

## The interface

Haunt is designed for a phone first. A desktop version exists as a separate product: a
game overlay with independent floating windows for voice and for each conversation,
reached by keyboard shortcut. It is not this.

The conversation fills the screen and the microphone sits at the bottom of it, in the
scroll rather than pinned above it, so scrolling back through the conversation carries
the microphone away and returning brings it back. Tapping it opens the hearth, which is
the call as a place: the people in it, who is speaking, and — when someone is sharing
their screen — their video in the middle with the faces around it.

Public channels are firelit. A direct message is cool and has no hearth, because there
is no call in a private conversation.

## How it is distributed

Haunt is one static file, so copies of it are free and there is no single place it has
to live. Every bothy serves a copy, so any relay a person can reach will give them the
app. A canonical copy is hosted separately, so a relay being down does not take the app
with it. A person who wants one on disk can keep one.

The client remembers every relay it has seen for a group and tries them in turn. A group
with a second relay stays reachable when the first is down, which only works because the
list is held on the device rather than fetched from the relay that has failed.

## What it is not

Haunt is not a general nostr client, and it does not try to be compatible with other
NIP-29 clients. That compatibility was attempted and abandoned: the specification is
silent on most of what matters, its reference relay implementation is archived and
declared broken by its author, and the clients that exist each guessed differently.
Haunt and bothy are written against each other.

Haunt does not federate, has no accounts on a server anyone else runs, and asks nobody
to trust a service. What a group depends on is a relay one of them owns.

## What's built so far

Everything above describes where Haunt is going. Today, people can exchange chat
messages and hear each other in a voice call, both through a bothy relay. Read
`index.html` and `app.js` for what's actually wired up — this file won't be kept in
sync with every feature as it lands. There is no channels, no direct messages, no QR
device pairing, no invites, no video, no screen sharing, and the key an identity is
minted around never leaves the browser it was created in yet. When a piece of the
vision above ships, this paragraph should shrink, not grow with a list of what's still
missing.

## Conventions

- Commit straight to `main`. No branches, no PRs. This is a one-contributor repo, and
  in bothy itself every branch ended up as either a stale leftover or a deploy that
  quietly never happened.
- No decision records, no rationale documents, no changelog. This file describes what
  the thing is. Anything else worth explaining lives in a comment next to the code it
  explains.
- Prose is written in complete sentences, not fragments.
- Every release gets an annotated tag (`git tag -a`, not `git tag`). A lightweight tag
  is silently skipped by `--follow-tags`, which has already caused missed releases
  once before.
