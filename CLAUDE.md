# Hearth

Hearth is a voice and chat client for a small group of friends. It is meant for ten to
twenty people who already know each other, and it replaces the private Discord server
that such a group usually ends up on. There is no public directory, no discovery and no
strangers.

## What it talks to

Hearth runs against a [bothy](https://github.com/sybenx/bothy) relay. One person in the
group owns and hosts that relay, and it holds the group's membership, its moderation
state and the history of everything said in public channels. A group is a relay, and a
person may belong to more than one.

Hearth is a static page with no backend of its own. Everything it needs is either in the
relay or on the user's device.

## Joining

A person joins by opening one link, and that link is the only thing they are ever asked
to paste. A new member's link carries the relay and an invite code. A returning member's
link carries only the relay. When Hearth has been served by the relay itself, the link
carries nothing, because the app already knows which relay it came from.

Someone who arrives by link is never asked to configure anything. The field for typing a
relay address by hand exists for the person who arrived with nothing, and it is the
unusual path rather than the front door.

Two arrivals need two screens, because they are not the same person. Somebody following
an invite link is being let in by somebody who already knows them, and the only thing
asked of them is what to call themselves. Somebody who opens the bare address with no
link and no identity on the device is almost never new — a link is how anyone is let in
— so they are a member standing in front of a device that does not have their account
yet, and that screen is a log in. It leads with bringing the account from the device that
does have it, offers a signing extension quietly beside that, and keeps the relay address
field at the bottom for the person who has neither.

A device that has just been handed an identity is also told where the room is: the
sending device passes its relay list over the same encrypted channel, right behind the
key. Without it a device would have the account and no idea which relay to ask, and the
first thing it saw would be the address field that the whole transfer existed to avoid.

## Identity

Identity is a nostr keypair, and the people using Hearth are not expected to know that. A
new member's key is created for them, and the one thing asked before it is made is what
to call them. Somebody who already has a nostr identity says so on that same first screen
and signs with the extension holding it, and Hearth then goes and reads the name they
already publish rather than asking for it again. Nobody joins as a string of hex; the
short pubkey that still appears is only ever a member whose name has not reached this
device yet.

The name a person goes by in the group is theirs to choose and is not their nostr
profile. Somebody arriving with an identity is never asked to type a name they have
already published: hearth reads that profile, uses what it finds, and goes on reading it,
so a name changed out there changes here too. That lasts exactly as long as the name here
is a default. The moment somebody names themselves in the group it is a decision, hearth
stops looking, and nothing they chose is ever taken back by a profile updated somewhere
else. It never writes to the profile in either case, and the group's copy lives in an
event scoped to the group, so one key can be called different things in two of them.

Being told is something a person turns on, never something hearth decides for them. The
count in the tab costs nothing and is always there; a notification while hearth is open
asks permission first; and one that arrives when hearth is closed needs the relay to
send it, which means telling the relay which devices are yours. That last one is worth
asking for and not worth assuming, so it lives behind the account icon with the rest of
what is yours. A notification names the room and never what was said: the payload goes
through Apple's or Google's push service on its way to the phone, and the contents of
the room are not theirs to hold. See `reference/push.md` for the relay's half.

A member moves their identity to a second device by showing a code on one screen and
scanning it with the other, using whatever the scanning phone already points at a code
with. Two devices with no camera between them copy the link the code stands for and
paste it into the other, which is the same bytes carried by hand; the specification's
typed three-word code is not implemented, because copying covers that case with none of
its machinery. Either way the two devices are meant to be in front of the person at
once, which is why neither is described as sending anything anywhere. The code is an
ordinary web link to the copy of Hearth that drew it, carrying the pairing details in
its fragment, because a camera app hands a scheme no app has claimed to a web search
rather than to anything useful. The fragment keeps those details out of every request
log on the way. What they amount to is a temporary public key rather than the identity
itself, so photographing the code achieves nothing.

Both screens then show the same four emoji, derived from both temporary keys and from a
random number each device committed to before it saw the other's, and the person
compares them; the device holding the key sends it only after its owner has read a line
naming what the other device claims to be, and the device receiving it stores nothing
until its owner agrees to the identity that arrived. The key travels as an encrypted
message over public relays rather than over the group's own, because a bothy delivers
that kind of message to its owner alone. Neither joining nor moving to a second device
ever asks anyone to paste a secret into a box, in either direction. The one place a key
is typed in is bringing an identity that already exists somewhere else, and that is
something a person goes and finds behind the account icon rather than something Hearth
asks them for.

That transfer follows an outside specification rather than something invented here, so a
key can move between Hearth and any other client that implements it. The specification
lives in the nostr-key-management repository; `keyxfer.js` implements the part of it that
carries a key between two devices, `keyxfer-vectors.json` holds the known answers a
second implementation has to reproduce, and `vectors.html` checks them.

## What is private and what is not

Public channels are readable by the relay. That is deliberate, and it is what gives the
group durable history that survives a new device, a lost phone, or a member joining
years late. The relay's owner can read them, and Hearth says so rather than implying
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

Calls are a mesh. Everybody sends to everybody, which means a person sharing their screen
sends one copy of it up their own connection for every person watching, and there is no
unit anywhere turning one copy into many. That is a real ceiling and it is the one Hearth
accepts: a handful of people, seven at the outside. Past that the picture degrades and
Hearth says why, rather than quietly finding a way round it. A group that needs more than
that every week wants a different kind of software, and building the thing that would
serve them would mean running a server for the group to depend on, which is the one thing
Hearth is for not doing.

Somebody in the call can share their screen or turn on their camera. It fills the window
the fire occupies, and follows the person up into a corner of the conversation when they
scroll away from the fire. Putting that corner away puts the picture away and nothing
else: they are still in the call, still hearing everyone, and the fire still has the
picture when they come back to it.

A screen of code and a screen of a game want opposite things: one wants every letter
legible and does not care how few frames arrive, the other wants the motion and would
rather lose detail than stutter. Hearth works out which it is looking at, by watching how
much the picture is actually changing, and moves between the two as the screen changes.
Asking the person instead meant asking them to predict what they were about to show, in
words that did not say what they meant, and offering them the choice afterwards was the
same mistake standing a little further back.

How fast the picture goes is worked out too, between eight frames a second and sixty. How
many people are watching sets the ceiling, because in a mesh each of them is another copy
going up the same connection, and the encoder saying it is struggling brings it down a
rung until it stops saying so.

How large a picture each person is sent is that person's own to decide. A mesh gives the
sharer a separate connection to every watcher, so there is no single resolution for them
all to compromise on: each watcher measures the window it will actually be shown in and
says so, and a phone turned on its side says so again. The sharer never sends more than
the capture itself contains, because scaling a laptop screen up to a larger number sends
more bits carrying no more detail.

## The interface

Hearth is designed for a phone first. A window with room in it is not a second design but
the same one with the scarcity taken out: the fire on one side, the conversation on the
other, both always there. The three modes below exist because a phone cannot show both at
once, so where there is room they are gone, and so is everything that answered for them.
Which of the two arrangements a screen gets is decided by measuring what fits, in both
directions, rather than by asking what kind of machine it is: a phone lying on its side
has the width and nowhere near the height, and is answered by the height.

A desktop version exists as a separate product, and that is a different thing again: a
game overlay with independent floating windows for voice and for each conversation,
reached by keyboard shortcut. It is not this, and a wide browser window is not it.

The screen is one vertical arrangement with the fire at the bottom of it, and where the
scroll sits is the whole of what is showing. Opening Hearth lands at the hearth itself,
the call as a place: the people in it, who is speaking, a microphone large enough to be
the point, and — when someone is sharing their screen — their video in the middle with
the faces around it. Pulling the conversation up over the fire leaves the call sitting
compactly beneath the composer, in the scroll rather than pinned, and scrolling back
through history carries it away like anything else in the conversation. Scrolled away, a
down arrow floats over the words to lead back to the fire, and a small mute control
floats beside it while a call is running. The microphone is never above the composer.
Everything that is not the conversation — who you are, your key, your relays, the
owner's invites — lives behind the account icon, which is always in the top bar.

Public channels are firelit. A private conversation is cool where the room is warm, and
it has a hearth of its own, because two friends can be in a call just as the whole room
can.

## How it speaks

The metaphor lives in the name, the colours and the light, and never on a control. A
button says what pressing it does. There is one register: lowercase, no full stops on
fragments, and no em dashes in status text. And a protocol step is never shown to
someone who does not know the protocol — a person connecting is "connecting" whether
the client is dialling, authenticating or subscribing, because the stages are not their
concern, and any stage that genuinely fails has its own message. Old commits contain
labels like "slip away" and "sit down"; they were the metaphor leaking onto controls,
and they are not the house style.

## How it is distributed

Hearth is one static file, so copies of it are free and there is no single place it has
to live. Every bothy serves a copy, so any relay a person can reach will give them the
app. A canonical copy is hosted separately, so a relay being down does not take the app
with it. A person who wants one on disk can keep one.

The client remembers every relay it has seen for a group and tries them in turn. A group
with a second relay stays reachable when the first is down, which only works because the
list is held on the device rather than fetched from the relay that has failed.

## What it is not

Hearth is not a general nostr client, and it does not try to be compatible with other
NIP-29 clients. That compatibility was attempted and abandoned: the specification is
silent on most of what matters, its reference relay implementation is archived and
declared broken by its author, and the clients that exist each guessed differently.
Hearth and bothy are written against each other.

Hearth does not federate, has no accounts on a server anyone else runs, and asks nobody
to trust a service. What a group depends on is a relay one of them owns.

## What's built so far

Everything above describes where Hearth is going. Today, people can exchange chat
messages and hear each other in a voice call through a bothy relay, and the way in
exists: the owner mints invite links inside Hearth, a link redeems itself on arrival,
and everybody who has no identity on the device lands on one screen that asks for a name
or takes the one their signing extension already holds. Read `index.html` and `app.js`
for what's actually wired up — this file won't be kept in sync with every feature as it
lands. An identity moves to a second device by QR, both flows of it, or by the link
behind it. There is no channels and no direct messages. When a piece of the vision above
ships, this paragraph should shrink, not grow with a list of what's still missing.

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
