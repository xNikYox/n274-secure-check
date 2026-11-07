// Lückendatenbank von retire.js (Apache-2.0) holen und verkleinert als lib/retire-db.js ablegen.
//   node scripts/update-retire.js [pfad/zu/jsrepository-v4.json]
// Ohne Pfad wird die aktuelle Datei von GitHub geladen. Im Addon selbst gibt es keinen Online-Abruf.
const fs = require("node:fs");
const path = require("node:path");

const URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json";

(async () => {
  const src = process.argv[2];
  const raw = src ? fs.readFileSync(src, "utf8") : await (await fetch(URL)).text();
  const repo = JSON.parse(raw);
  const out = {};
  for (const [name, lib] of Object.entries(repo)) {
    if (name === "retire-example" || name === "dont check") continue;
    const ex = lib.extractors || {};
    const keep = {};
    for (const k of ["func", "uri", "filename", "filecontent"]) if (ex[k]?.length) keep[k] = ex[k];
    out[name] = {
      extractors: keep,
      vulnerabilities: (lib.vulnerabilities || []).map((v) => {
        const x = { below: v.below, severity: v.severity || "medium" };
        if (v.atOrAbove) x.atOrAbove = v.atOrAbove;
        const id = v.identifiers || {};
        if (id.CVE?.length) x.cve = id.CVE.slice(0, 3);
        if (id.summary) x.summary = String(id.summary).slice(0, 160);
        if (v.info?.length) x.info = v.info[0];
        return x;
      }),
    };
  }
  const date = new Date().toISOString().slice(0, 10);
  const js = `// Automatisch erzeugt mit scripts/update-retire.js am ${date} – Daten: retire.js (https://github.com/RetireJS/retire.js), Apache License 2.0\n` +
    `(function () {\n  const db = ${JSON.stringify(out)};\n  const meta = { date: "${date}", libraries: ${Object.keys(out).length} };\n` +
    `  if (typeof module !== "undefined" && module.exports) module.exports = { db, meta };\n  else { globalThis.RETIRE_DB = db; globalThis.RETIRE_META = meta; }\n})();\n`;
  fs.writeFileSync(path.join(__dirname, "..", "lib", "retire-db.js"), js);
  console.log(`${Object.keys(out).length} Bibliotheken, ${Object.values(out).reduce((a, l) => a + l.vulnerabilities.length, 0)} Lücken → lib/retire-db.js (${Math.round(js.length / 1024)} KB)`);
})();
