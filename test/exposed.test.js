const test = require("node:test");
const assert = require("node:assert/strict");
const E = require("../lib/exposed");

const home = "<!doctype html><html><head><title>Start</title></head><body>Willkommen</body></html>";
const all = (over = {}) => E.paths().map((path) => ({ path, status: 200, finalUrl: "https://example.de" + path, text: home, ...(over[path] || {}) }));

test("Soft-404 (alles liefert die Startseite) → keine Treffer", () => {
  assert.deepEqual(E.evaluate(all()), []);
});

test("echte Funde am Inhalt erkannt", () => {
  const r = E.evaluate(all({
    "/.git/HEAD": { text: "ref: refs/heads/main\n" },
    "/.env": { text: "APP_KEY=base64:abc\nDB_PASSWORD=geheim\n" },
    "/backup.sql": { text: "-- MySQL dump 10.13\nCREATE TABLE `users` (" },
    "/uploads/": { text: "<html><head><title>Index of /uploads</title></head>" },
    "/wp-json/wp/v2/users": { text: '[{"id":1,"name":"admin","slug":"admin"}]' },
  }));
  const titles = r.map((x) => x.title);
  assert.ok(titles.some((t) => /Git-Ordner/.test(t)));
  assert.ok(titles.some((t) => /\/\.env\)/.test(t)));
  assert.ok(titles.some((t) => /Datenbank-Sicherung/.test(t)));
  assert.ok(titles.some((t) => /Verzeichnisliste/.test(t)));
  assert.ok(titles.some((t) => /Benutzernamen/.test(t)));
  assert.equal(r.find((x) => /\.env\)/.test(x.title)).status, "bad");
  assert.ok(r.every((x) => x.cat === "exposed" && x.weight > 0));
});

test("Weiterleitung auf Login/Startseite und Fehlercodes zählen nicht", () => {
  const r = E.evaluate(all({
    "/.git/HEAD": { finalUrl: "https://example.de/login", text: "ref: refs/heads/main" },
    "/.env": { status: 403, text: "APP_KEY=x" },
  }));
  assert.deepEqual(r, []);
});
