// Das Auslese-Skript in einer nachgebauten Seite (jsdom) laufen lassen
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const code = fs.readFileSync(path.join(__dirname, "..", "content.js"), "utf8");
const html = `<!doctype html><html lang="de"><head>
  <title>Testseite</title><meta name="description" content="Kurz"><meta name="viewport" content="width=device-width">
  <meta name="generator" content="WordPress 6.4.2"><link rel="canonical" href="/start"><meta property="og:title" content="x">
  <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/js/bootstrap.min.js" integrity="sha384-x"></script>
  <link rel="stylesheet" href="/wp-content/themes/a/style.css">
  <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"X"}</script>
</head><body>
  <!-- Zugangsdaten DB: user root, Passwort hunter2 -->
  <!-- normaler Kommentar -->
  <h1>Hallo</h1><h1>Zweite</h1>
  <form action="http://example.de/login"><input type="password" autocomplete="off"></form>
  <form method="POST" action="/kontakt"><input name="name"><textarea name="msg"></textarea><input type="hidden" name="_wpnonce" value="a1b2c3d4e5"><input type="file"></form>
  <footer><a href="/impressum">Impressum</a> · <a href="/privacy-policy">Datenschutz</a></footer>
  <div id="BorlabsCookieBox"></div>
  <img src="a.png" alt="A"><img src="b.png">
  <iframe src="https://www.youtube.com/embed/x"></iframe>
  <script>var inline = 1;</script>
</body></html>`;

test("liest Formulare, Bibliotheken, SEO-Angaben und heikle Kommentare", async () => {
  const dom = new JSDOM(html, { url: "https://example.de/seite", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  // Seite hat jQuery als Variable (wie nach dem Laden)
  w.jQuery = { fn: { jquery: "1.12.4" } };
  w.PerformanceObserver = class { observe() { throw new Error("nicht unterstützt"); } };
  // Variablen-Pfade aus der Lückendatenbank (macht sonst das Hintergrundskript)
  const Retire = require("../lib/retire");
  w.__n274FuncPaths = Retire.funcPaths(require("../lib/retire-db").db);
  const data = JSON.parse(JSON.stringify(await w.eval(code))); // Werte aus dem jsdom-Kontext in normale Objekte
  assert.equal(data.title, "Testseite");
  assert.equal(data.lang, "de");
  assert.equal(data.viewport, true);
  assert.equal(data.canonical, "https://example.de/start");
  assert.equal(data.generator, "WordPress 6.4.2");
  assert.equal(data.og, true);
  assert.deepEqual(data.h1, ["Hallo", "Zweite"]);
  assert.equal(data.imagesTotal, 2);
  assert.equal(data.imagesNoAlt, 1);
  assert.deepEqual(data.forms, [
    { name: null, action: "http://example.de/login", method: "get", password: true, pwAutocomplete: "off", csrf: false, upload: false, fields: 1 },
    { name: null, action: "https://example.de/kontakt", method: "post", password: false, pwAutocomplete: null, csrf: true, upload: true, fields: 3 },
  ]);
  assert.deepEqual(data.legal, { imprint: "https://example.de/impressum", privacy: "https://example.de/privacy-policy" });
  assert.match(data.cmpHint, /borlabs-cookie/);
  assert.equal(data.loosePassword, false);
  assert.deepEqual(data.iframes, ["https://www.youtube.com/embed/x"]);
  assert.deepEqual(data.structuredData, ["Organization"]);
  assert.equal(data.inlineScripts, 2); // JSON-LD + Inline-Skript
  assert.deepEqual(data.libs.map((l) => `${l.name} ${l.version} ${l.via}`), ["jquery 1.12.4 Variable"]); // Adresse/Inhalt prüft der Hintergrund
  assert.equal(data.scripts.find((s) => /bootstrap/.test(s.src)).integrity, "sha384-x");
  assert.ok(data.tech.includes("WordPress"));
  assert.equal(data.sensitiveComments.length, 1);
  assert.match(data.sensitiveComments[0], /Zugangsdaten/);
  assert.equal(data.timing.lcp, null);
});
