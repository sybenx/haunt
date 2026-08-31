/* ============================================================
   hearth's service worker. It exists for one reason: a
   notification on a phone has to come from here. Both the banner
   raised while hearth is open (showNotification is a registration
   method, and on android and on an installed ios there is no other
   way to raise one) and the push that arrives when hearth is
   closed land in this file.

   It caches nothing, on purpose. Hearth is deployed on every push
   and served from whatever bothy a person arrived through; a
   worker holding old copies of app.js would serve somebody a
   version of hearth nobody is running any more, and the bug that
   causes looks like anything but a stale cache. There is no fetch
   handler here at all, so every request goes to the network as if
   this file did not exist.
   ============================================================ */

// A new worker takes over immediately rather than waiting for every
// tab to close, because the only thing it changes is how a
// notification is raised.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

/* ------------------------------------------------------------
   A push carries no message text and no name. The relay knows
   both, and could put either in here, but the payload travels
   through apple's or google's push service to get to the device
   and hearth has no business handing them the contents of a room.
   So a push says which room and which kind of thing happened, and
   anybody who wants to know what was said opens hearth and reads
   it from the relay like always.
   ------------------------------------------------------------ */
self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (err) {
    // A push that isn't hearth's own, or a payload that didn't
    // survive the trip. Still worth waking somebody for: something
    // happened in a room they asked to hear about.
  }
  const room = typeof data.room === "string" && data.room.trim() !== "" ? data.room.trim() : "hearth";
  const body = data.kind === "voice" ? "somebody is at the fire" : "there's a message";
  event.waitUntil(self.registration.showNotification(room, {
    body,
    icon: "icon.svg",
    badge: "icon.svg",
    // One notification per room per kind: a quiet room that gets
    // eleven messages should be one line in the shade, not eleven.
    tag: "hearth:" + (data.kind === "voice" ? "voice" : "message"),
    renotify: false,
    data: { url: typeof data.url === "string" ? data.url : "./" },
  }));
});

/* ------------------------------------------------------------
   Tapping one goes to hearth. If a tab is already open on this
   origin it is focused rather than a second one being made,
   because two hearths signing as the same key both heartbeating
   into the same call is a mess nobody asked for.
   ------------------------------------------------------------ */
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "./";
  event.waitUntil((async () => {
    const open = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const client of open) {
      if ("focus" in client) {
        if ("navigate" in client && url !== "./") await client.navigate(url).catch(() => {});
        return client.focus();
      }
    }
    if (self.clients.openWindow) return self.clients.openWindow(url);
  })());
});
