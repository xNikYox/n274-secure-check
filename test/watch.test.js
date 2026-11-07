// Überwachung: watch.js in einer Sandbox mit Attrappen laden und den Vergleich prüfen
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const noop = () => {};
const listener = { addListener: noop };
const ctx = vm.createContext({
  browser: { webRequest: { onHeadersReceived: listener }, alarms: { create: noop, onAlarm: listener }, notifications: { onClicked: listener, create: noop },
    runtime: { onMessage: listener, getURL: (x) => x }, storage: { local: { get: async () => ({}), set: async () => {} } }, tabs: { create: noop } },
  URL, Date, Math, console,
});
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "watch.js"), "utf8") + "\nthis.changesRaw = changes; this.normalize = normalize;", ctx);
// Ergebnisse aus der Sandbox in normale Objekte (sonst schlägt der Vergleich wegen anderer Prototypen fehl)
ctx.changes = (a, b) => JSON.parse(JSON.stringify(ctx.changesRaw(a, b)));

const snap = (o = {}) => ({ status: 200, grade: "A", certDays: 40, headers: { HSTS: true, CSP: true, Clickjacking: true, nosniff: true, "Referrer-Policy": true }, broken: [], exposed: [], ...o });

test("Vergleich mit dem letzten Stand", () => {
  assert.deepEqual(ctx.changes(null, snap()), []);
  assert.deepEqual(ctx.changes(snap(), snap()), []);
  const ch = ctx.changes(snap(), snap({ grade: "C", status: 500, headers: { ...snap().headers, CSP: false }, broken: ["404 https://x.de/a"], exposed: [{ status: "bad", title: "Git-Ordner öffentlich (/.git)" }] }));
  const t = ch.map((c) => `${c.status}: ${c.text}`);
  assert.ok(t.includes("bad: Note A → C"));
  assert.ok(t.includes("bad: Status 200 → 500"));
  assert.ok(t.includes("bad: CSP entfernt"));
  assert.ok(t.some((x) => /^warn: 1 neue kaputte Links/.test(x)));
  assert.ok(t.includes("bad: Neu offen: Git-Ordner öffentlich (/.git)"));
  const better = ctx.changes(snap({ certDays: 3, exposed: [{ title: "X" }], broken: ["404 a"] }), snap({ certDays: 89 }));
  assert.deepEqual(better.map((c) => c.status + ": " + c.text), ["ok: Zertifikat erneuert (noch 89 Tage)", "ok: 1 Links wieder in Ordnung", "ok: Wieder geschlossen: X"]);
});

test("Adressen werden vereinheitlicht", () => {
  assert.equal(ctx.normalize("meine-seite.de"), "https://meine-seite.de/");
  assert.equal(ctx.normalize("http://x.de/a#b"), "http://x.de/a");
  assert.throws(() => ctx.normalize("ftp://x.de"));
});
