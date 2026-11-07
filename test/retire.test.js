const test = require("node:test");
const assert = require("node:assert/strict");
const R = require("../lib/retire");
const { db, meta } = require("../lib/retire-db");

test("Datenbank geladen", () => {
  assert.ok(meta.libraries > 50);
  assert.ok(db.jquery.vulnerabilities.length > 3);
});

test("Erkennung über Adresse, Dateiname und Inhalt", () => {
  assert.deepEqual(R.fromUrl(db, "https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js").map((x) => [x.name, x.version, x.via]), [["jquery", "1.12.4", "Adresse"]]);
  assert.deepEqual(R.fromUrl(db, "https://example.de/js/jquery-3.4.1.min.js?ver=1").map((x) => [x.name, x.version]), [["jquery", "3.4.1"]]);
  assert.deepEqual(R.fromUrl(db, "https://example.de/app.js"), []);
  const found = R.fromContent(db, "/*! jQuery v3.4.1 | (c) JS Foundation */\n!function(e){...}", "https://example.de/bundle.js");
  assert.deepEqual(found.map((x) => [x.name, x.version, x.via]), [["jquery", "3.4.1", "Dateiinhalt"]]);
});

test("Variablen-Pfade ohne eval, nur einfache Ausdrücke", () => {
  assert.deepEqual(R.parseFunc("(window.jQuery || window.$ || window.$jq || window.$j).fn.jquery"), { alts: ["jQuery", "$", "$jq", "$j"], path: ["fn", "jquery"] });
  assert.deepEqual(R.parseFunc("angular.version.full"), { alts: ["angular.version.full"], path: [] });
  assert.equal(R.parseFunc("require('jquery').fn.jquery"), null);
  assert.equal(R.parseFunc("new jQuery.jPlayer().version.script"), null);
  assert.ok(R.funcPaths(db).some((f) => f.lib === "jquery" && f.alts.includes("jQuery")));
});

test("Versionen: Lücken-Bereiche, Vorabversionen, Zusammenführen", () => {
  assert.equal(R.cmp("3.0.0-beta1", "3.0.0"), -1);
  assert.equal(R.cmp("1.10.0", "1.9.0"), 1);
  assert.ok(R.vulnerabilities(db, "jquery", "3.4.1").length >= 1);
  assert.equal(R.vulnerabilities(db, "jquery", "3.7.1").length, 0);
  assert.equal(R.vulnerabilities(db, "gibtsnicht", "1.0").length, 0);
  const m = R.merge([{ name: "jquery", version: "3.4.1", via: "Adresse", src: "a.js" }, { name: "jquery", version: "3.4.1", via: "Variable", src: null }]);
  assert.deepEqual(m, [{ name: "jquery", version: "3.4.1", via: "Variable", src: "a.js" }]);
});
