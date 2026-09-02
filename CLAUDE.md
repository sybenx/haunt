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

What the group is called, who runs it and who belongs to it are all things the group says
about itself, and the relay says them in events it generates and signs with its own key.
Hearth reads those rather than the relay's NIP-11 document: a relay's name and a relay's
operator are facts about a server, and answering questions about a group with them is only
ever right on a relay that holds exactly one. The NIP-11 document is still read for the two
things that genuinely are the server's own, which are the public half of its push key and
whether the address the page was served from is a relay at all, and its name still stands in
as a label for a relay that generates no metadata event.

The member list that arrives with them is the group's real membership, which is a different
question from who happens to be in the call. It is what lets Hearth learn what somebody is
called before they have ever said anything, so a member who has never spoken is a name and
not a string of hex the first time they appear. None of it reaches a client the relay has
not yet admitted, because it lives inside the group along with everything else, and a client
without it falls back to what it would have shown anyway.

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
link and no identity on the device is almost never new, because a link is how anyone is
let in. They are a member standing in front of a device that does not have their account
yet, so that screen is a log in. It leads with bringing the account over from the device
that does have it, offers a signing extension beside that, and keeps the relay address
field at the bottom for the person who has neither.

A device that has just been handed an identity is also told where the group is: the
sending device passes its relay list over the same encrypted channel, right behind the
key. Without it the device would have the account and no idea which relay to ask, and the
first thing it showed would be the address field that the whole transfer existed to
avoid.

## Identity

Identity is a nostr keypair, and the people using Hearth are not expected to know that. A
new member's key is created for them, and the one thing asked before it is made is what
to call them. Somebody who already has a nostr identity says so on that same first screen
and signs with the extension holding it, and Hearth then reads the name they already
publish rather than asking for it again. Nobody joins as a string of hex. The short
pubkey that still appears is only ever a member whose name has not reached this device
yet.

The name a person goes by in the group is theirs to choose, and it is not their nostr
profile. Somebody arriving with an identity is never asked to type a name they have
already published: Hearth reads that profile, uses what it finds, and goes on reading it,
so a name changed elsewhere changes here too. That lasts exactly as long as the name here
is a default. Once somebody names themselves in the group it is a decision, Hearth stops
looking, and nothing they chose is overwritten by a profile updated somewhere else.
Hearth never writes to the profile in either case, and the group's copy lives in an event
scoped to the group, so one key can be called different things in two groups.

Notifications are something a person turns on, never something Hearth decides for them.
The count in the tab costs nothing and is always there. A notification while Hearth is
open asks permission first. One that arrives when Hearth is closed needs the relay to
send it, which means telling the relay which devices are yours; that is worth asking for
and not worth assuming, so it lives behind the account icon with the rest of what is
yours. A notification names the group and never what was said, because the payload goes
through Apple's or Google's push service on its way to the phone and the contents of the
group are not theirs to hold. See `reference/push.md` for the relay's half.

A member moves their identity to a second device by showing a code on one screen and
scanning it with the other, using whatever the scanning phone already points at a code
with. Two devices with no camera between them copy the link the code stands for and paste
it into the other, which is the same bytes carried by hand. Either way the two devices are
meant to be in front of the person at once, which is why neither is described as sending
anything anywhere. The code is an ordinary
web link to the copy of Hearth that drew it, carrying the pairing details in its fragment,
because a camera app hands an unclaimed URL scheme to a web search rather than to anything
useful. The fragment keeps those details out of every request log on the way. What they
amount to is a temporary public key rather than the identity itself, so photographing the
code achieves nothing.

The device receiving the key then shows five figures, derived from both temporary keys and
from a random number each device committed to before it saw the other's, and the person
types them into the device holding the key. Typed rather than compared, because a screen
offering one thing to check and a button underneath it is a check that will sometimes not
happen: people moving quickly press the only control there is. A number that has to be
carried between two screens cannot be entered by somebody who never read the second one.
Five of them because no secret anybody already holds is five figures long, so the shape of
the field says on its own that this is not a password being asked for. Five wrong entries
end the attempt, and the same device is refused a second one for an hour, because every
chance an attacker gets comes from starting again rather than from typing again.

The device holding the key sends it only after its owner has also read a line naming what
the other device claims to be — the one thing a matching number cannot settle, since a page
that really is the far end will show a matching number — and the device receiving it stores
nothing until its owner agrees to the identity that arrived. The key travels as an
encrypted message over public relays rather than over the group's own, because a bothy
delivers that kind of message to its owner alone. Neither joining nor moving to a second
device ever asks anyone to paste a secret into a box, in either direction. The one place a
key is typed in is bringing an identity that already exists somewhere else, and that is
something a person goes and finds behind the account icon rather than something Hearth asks
them for.

That transfer follows an outside specification rather than something invented here, so a
key can move between Hearth and any other client that implements it. The specification is
QR Secret Transfer, which lives in the nostr-key-management repository along with the
`nostr-nsec` profile naming what Hearth moves under it. `keyxfer.js` implements it and
knows nothing about Hearth, `keyxfer-vectors.json` holds the known answers a second
implementation has to reproduce, and `vectors.html` checks them. Its event kinds are
unregistered placeholders in the specification too, so a build of Hearth pairs with a build
of Hearth and with nothing else until they are settled.

## What is private and what is not

Public channels are readable by the relay. That is deliberate, and it is what gives the
group durable history that survives a new device, a lost phone, or a member joining years
late. The relay's owner can read them, and Hearth says so rather than implying otherwise.

Direct messages between two members are encrypted end to end and are not stored on the
group's relay at all. They travel over the relays the recipient has published for that
purpose, which are usually public ones. This means the group's owner cannot read them and
cannot see who is talking to whom, and the option to do either does not exist rather than
being declined.

A member who wants their direct messages held somewhere they control runs their own bothy
and points their message relays at it.

## Voice and video

Voice is WebRTC. Media never passes through the bothy relay, which carries only the
signalling: who is in the call, and one negotiation per participant.

Calls are a mesh. Everybody sends to everybody, which means a person sharing their screen
sends one copy of it up their own connection for every person watching, and there is no
server anywhere turning one copy into many. That is a real ceiling and it is the one
Hearth accepts: a handful of people, seven at the outside. Past that the picture degrades
and Hearth says why, rather than quietly finding a way round it. A group that needs more
than that every week wants a different kind of software, and building it would mean
running a server for the group to depend on, which is the one thing Hearth is for not
doing.

Somebody in the call can share their screen or turn on their camera. It fills the area the
call view occupies, and follows the person up into a corner of the conversation when they
scroll away from the call. Dismissing that corner dismisses the picture and nothing else:
they are still in the call, still hearing everyone, and the call view still has the
picture when they come back to it.

A screen of code and a screen of a game want opposite things. One wants every letter
legible and does not care how few frames arrive; the other wants the motion and would
rather lose detail than stutter. Hearth works out which it is looking at by watching how
much the picture is actually changing, and moves between the two as the screen changes.
Asking the person instead meant asking them to predict what they were about to show, and
offering the choice afterwards was the same mistake standing further back.

Frame rate is worked out too, between eight frames a second and sixty. How many people are
watching sets the ceiling, because in a mesh each of them is another copy going up the same
connection, and the encoder reporting that it is struggling brings the rate down a step
until it stops reporting it.

How large a picture each person is sent is that person's own to decide. A mesh gives the
sharer a separate connection to every watcher, so there is no single resolution for them
all to compromise on. Each watcher measures the area it will actually be shown in and says
so, and a phone turned on its side says so again. The sharer never sends more than the
capture itself contains, because scaling a laptop screen up to a larger number sends more
bits carrying no more detail.

## The interface

Hearth is designed for a phone first. A window with room in it is not a second design but
the same one with the scarcity taken out: the call on one side, the conversation on the
other, both always visible. The three modes below exist because a phone cannot show both
at once, so where there is room they are gone, and so is everything that answered for them.
Which arrangement a screen gets is decided by measuring what fits, in both directions,
rather than by asking what kind of machine it is: a phone lying on its side has the width
and nowhere near the height, and is answered by the height. A shared screen is the one
thing there is never room for twice. It takes the conversation's half rather than a slice
of the call's, because a picture in the call's column is too small to be worth turning a
phone sideways for. Putting it in the corner hands the conversation its half back, and the
call view is the same in every one of those states.

A desktop version exists as a separate product, and that is a different thing again: a
game overlay with independent floating windows for voice and for each conversation, reached
by keyboard shortcut. It is not this, and a wide browser window is not it.

The screen is one vertical arrangement with the call at the bottom of it, and where the
scroll sits is the whole of what is showing. Opening Hearth lands at the call: the people
in it, who is speaking, a microphone large enough to be the point, and, when someone is
sharing their screen, their video in the middle with the faces around it. Pulling the
conversation up over the call leaves it sitting compactly beneath the composer, in the
scroll rather than pinned, and scrolling back through history carries it away like anything
else in the conversation. Scrolled away, a down arrow floats over the words to lead back
to the call, and a small mute control floats beside it while a call is running. The
microphone is never above the composer. Everything that is not the conversation — who you
are, your key, your relays, the owner's invites — lives behind the account icon, which is
always in the top bar.

Public channels are warm-toned. A private conversation is cool where the group is warm,
and it has a call of its own, because two friends can be in a call just as the whole group
can.

## Language

The theme lives in the name, the colours and the light, and never in the words. Controls
and copy use ordinary language: a button says what pressing it does, in the word a person
would already use for it. Do not name a region or a control after the metaphor. The call
is "the call", not "the fire" or "the hearth"; the only place the product name appears in
the interface is the title over the call view, which reads "The Hearth".

There is one register: lowercase, no full stops on fragments, and no em dashes in status
text.

A protocol step is never shown to someone who does not know the protocol. A person
connecting is "connecting" whether the client is dialling, authenticating or subscribing,
because the stages are not their concern, and any stage that genuinely fails has its own
message.

Old commits contain labels like "slip away", "sit down" and "the fire is out". They are
the mistake this section exists to prevent.

## How it is distributed

Hearth is one static file, so copies of it are free and there is no single place it has to
live. Every bothy serves a copy, so any relay a person can reach will give them the app. A
canonical copy is hosted separately, so a relay being down does not take the app with it.
A person who wants one on disk can keep one.

The client remembers every relay it has seen for a group and tries them in turn. A group
with a second relay stays reachable when the first is down, which only works because the
list is held on the device rather than fetched from the relay that has failed.

## What it is not

Hearth is not a general nostr client, and it does not try to be compatible with other
NIP-29 clients. That compatibility was attempted and abandoned: the specification is silent
on most of what matters, its reference relay implementation is archived and declared broken
by its author, and the clients that exist each guessed differently. Hearth and bothy are
written against each other.

Hearth does not federate, has no accounts on a server anyone else runs, and asks nobody to
trust a service. What a group depends on is a relay one of them owns.

## What's built so far

Everything above describes where Hearth is going. Today, people can exchange chat messages
and hear each other in a voice call through a bothy relay, and the way in exists: the owner
mints invite links inside Hearth, a link redeems itself on arrival, and everybody who has
no identity on the device lands on one screen that asks for a name or takes the one their
signing extension already holds. Read `index.html` and `app.js` for what is actually wired
up; this file will not be kept in sync with every feature as it lands. An identity moves to
a second device by QR, both directions of it, or by the link behind it. There are no
channels and no direct messages. When a piece of the vision above ships, this paragraph
should shrink, not grow with a list of what is still missing.

## Conventions

- Commit straight to `main`. No branches, no PRs. This is a one-contributor repo, and in
  bothy itself every branch ended up as either a stale leftover or a deploy that quietly
  never happened.
- No decision records, no rationale documents, no changelog. This file describes what the
  thing is. Anything else worth explaining lives in a comment next to the code it explains.
- Prose is written in complete sentences, not fragments.
- Every release gets an annotated tag (`git tag -a`, not `git tag`). A lightweight tag is
  silently skipped by `--follow-tags`, which has already caused missed releases once before.
