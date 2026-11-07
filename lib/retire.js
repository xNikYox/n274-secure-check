// n274 Secure Check – Bibliotheken erkennen und bekannte Lücken nachschlagen (Datenbank: retire.js, offline im Addon).
// Erkennung über Variablen der Seite (func), Adresse (uri), Dateiname (filename) und Dateiinhalt (filecontent).
(function () {
  "use strict";
  const VERSION = "[0-9][0-9.a-z_\\-]+";

  /** Schöne Namen für die Anzeige */
  const NAMES = {
    jquery: "jQuery", "jquery-ui": "jQuery UI", "jquery-ui-dialog": "jQuery UI Dialog", "jquery-ui-autocomplete": "jQuery UI Autocomplete",
    "jquery-ui-tooltip": "jQuery UI Tooltip", "jquery-mobile": "jQuery Mobile", "jquery-migrate": "jQuery Migrate", "jquery.validator": "jQuery Validation",
    "jquery.prettyPhoto": "prettyPhoto", "jquery-deparam": "jQuery deparam", bootstrap: "Bootstrap", lodash: "Lodash", underscore: "Underscore",
    "moment.js": "Moment.js", angularjs: "AngularJS", vue: "Vue", react: "React", "react-dom": "ReactDOM", handlebars: "Handlebars", mustache: "Mustache",
    dompurify: "DOMPurify", knockout: "Knockout", ember: "Ember", backbone: "Backbone", dojo: "Dojo", prototypejs: "Prototype", yui: "YUI",
    tinymce: "TinyMCE", ckeditor: "CKEditor", ckeditor5: "CKEditor 5", "pdf.js": "PDF.js", highcharts: "Highcharts", chart: "Chart.js",
    axios: "axios", select2: "Select2", "datatables": "DataTables", froala: "Froala", "plupload": "Plupload", "video.js": "Video.js",
    swfobject: "SWFObject", easyXDM: "easyXDM", sessvars: "sessvars", "jPlayer": "jPlayer", markdown: "markdown-it", "mathjax": "MathJax",
  };
  const nice = (n) => NAMES[n] || n;

  /** Nicht mehr gepflegte Bibliotheken (zusätzlich zu den Lücken) */
  const EOL = [
    { lib: "angularjs", below: "999", text: "AngularJS (1.x) bekommt seit 2022 keine Sicherheitsupdates mehr", fix: "Auf ein unterstütztes Framework umsteigen." },
    { lib: "vue", below: "3.0.0", text: "Vue 2 bekommt seit Ende 2023 keine Updates mehr", fix: "Auf Vue 3 umsteigen." },
    { lib: "moment.js", below: "999", text: "Moment.js wird nicht mehr weiterentwickelt", fix: "Für neue Projekte Day.js, Luxon oder date-fns nutzen." },
  ];

  function cmp(a, b) {
    const pa = String(a).split(/[.\-+_]/).map((x) => (/^\d+$/.test(x) ? +x : x));
    const pb = String(b).split(/[.\-+_]/).map((x) => (/^\d+$/.test(x) ? +x : x));
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const x = pa[i] ?? 0;
      const y = pb[i] ?? 0;
      if (x === y) continue;
      if (typeof x === "number" && typeof y === "number") return x < y ? -1 : 1;
      // Vorabversion (1.0.0-beta) liegt vor der Hauptversion
      if (typeof x === "string" && typeof y === "number") return -1;
      if (typeof x === "number" && typeof y === "string") return 1;
      return x < y ? -1 : 1;
    }
    return 0;
  }

  const cache = new WeakMap();
  /** Regeln einmal vorbereiten */
  function compile(db) {
    if (cache.has(db)) return cache.get(db);
    const re = (s, flags) => {
      try {
        return new RegExp(s.replace(/§§version§§/g, VERSION), flags);
      } catch {
        return null;
      }
    };
    const libs = Object.entries(db).map(([name, lib]) => ({
      name,
      uri: (lib.extractors.uri || []).map((s) => re(s, "i")).filter(Boolean),
      filename: (lib.extractors.filename || []).map((s) => re(s, "i")).filter(Boolean),
      filecontent: (lib.extractors.filecontent || []).map((s) => re(s)).filter(Boolean),
      func: (lib.extractors.func || []).map(parseFunc).filter(Boolean),
      vulns: lib.vulnerabilities || [],
    }));
    cache.set(db, libs);
    return libs;
  }

  /**
   * func-Ausdrücke ohne eval auswerten: nur "a.b.c" oder "(window.a || window.b).c.d" werden unterstützt,
   * alles andere (require(), new …) bleibt außen vor.
   */
  function parseFunc(expr) {
    const s = String(expr).trim();
    let m = /^\(([^()]+)\)((?:\.[\w$]+)+)$/.exec(s);
    if (m) {
      const alts = m[1].split("||").map((a) => a.trim().replace(/^window\./, ""));
      if (alts.every((a) => /^[\w$]+(\.[\w$]+)*$/.test(a))) return { alts, path: m[2].slice(1).split(".") };
      return null;
    }
    m = /^(?:window\.)?([\w$]+(?:\.[\w$]+)*)$/.exec(s);
    return m ? { alts: [m[1]], path: [] } : null;
  }

  /** Liste der Variablen-Pfade für das Auslese-Skript: [{ lib, alts, path }] */
  function funcPaths(db) {
    const out = [];
    for (const l of compile(db)) for (const f of l.func) out.push({ lib: l.name, alts: f.alts, path: f.path });
    return out;
  }

  /** Gefundene Version säubern: „3.4.1.min“ → „3.4.1“ (der Versions-Ausdruck schluckt sonst Dateiendungen) */
  const version = (m) => {
    if (!m || !m[1]) return null;
    let v = m[1];
    for (let i = 0; i < 3; i++) v = v.replace(/[._-]+$/, "").replace(/[.-](min|slim|pack|packed|prod|production|dev|debug|bundle|umd|esm|full|core|js)$/i, "");
    return v;
  };

  /** Aus der Adresse einer Datei */
  function fromUrl(db, url) {
    const found = [];
    const file = String(url).split(/[?#]/)[0];
    const name = file.split("/").pop();
    for (const l of compile(db)) {
      for (const r of l.uri) {
        const v = version(r.exec(file));
        if (v) {
          found.push({ name: l.name, version: v, via: "Adresse", src: url });
          break;
        }
      }
      if (found.some((f) => f.name === l.name)) continue;
      for (const r of l.filename) {
        const v = version(r.exec(name));
        if (v) {
          found.push({ name: l.name, version: v, via: "Dateiname", src: url });
          break;
        }
      }
    }
    return found;
  }

  /** Aus dem Inhalt einer Datei (Kopfkommentare, eingebaute Versionsnummern) */
  function fromContent(db, text, src = null) {
    const found = [];
    const body = String(text).slice(0, 1_500_000);
    for (const l of compile(db)) {
      for (const r of l.filecontent) {
        const v = version(r.exec(body));
        if (v && /^\d/.test(v)) {
          found.push({ name: l.name, version: v, via: "Dateiinhalt", src });
          break;
        }
      }
    }
    return found;
  }

  /** Bekannte Lücken einer Version → [{ severity, summary, cve, below, info }] */
  function vulnerabilities(db, name, ver) {
    const lib = compile(db).find((l) => l.name === name);
    if (!lib) return [];
    return lib.vulns.filter((v) => cmp(ver, v.below) < 0 && (!v.atOrAbove || cmp(ver, v.atOrAbove) >= 0));
  }

  function eol(name, ver) {
    return EOL.find((e) => e.lib === name && cmp(ver, e.below) < 0) || null;
  }

  /** Treffer zusammenführen: gleiche Bibliothek + Version nur einmal (Variable > Inhalt > Adresse) */
  function merge(list) {
    const rank = { Variable: 0, Dateiinhalt: 1, Adresse: 2, Dateiname: 3 };
    const out = new Map();
    for (const f of list) {
      const k = f.name + "@" + f.version;
      const old = out.get(k);
      if (!old || (rank[f.via] ?? 9) < (rank[old.via] ?? 9)) out.set(k, { ...f, src: f.src || old?.src || null });
    }
    return [...out.values()];
  }

  const api = { compile, parseFunc, funcPaths, fromUrl, fromContent, vulnerabilities, eol, merge, cmp, nice };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else globalThis.Retire = api;
})();
