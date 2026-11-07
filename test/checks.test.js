const test = require("node:test");
const assert = require("node:assert/strict");
const C = require("../lib/checks");

const NOW = Date.UTC(2026, 10, 7);
const H = (o) => Object.entries(o).map(([name, value]) => ({ name, value }));
const goodHeaders = H({
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; frame-ancestors 'self'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=()",
  "Content-Encoding": "br",
  Server: "nginx",
});
const goodSecurity = { state: "secure", protocolVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256", certificates: [{ subject: "example.de", issuer: "R11", validity: { start: NOW - 86400000 * 30, end: NOW + 86400000 * 60 } }] };
const goodPage = {
  title: "Beispiel – Startseite für Tests", description: "Eine Beschreibung mit genug Zeichen, damit sie für Suchmaschinen gut lesbar und vollständig ist.",
  h1: ["Willkommen"], lang: "de", viewport: true, canonical: "https://example.de/", og: true, imagesTotal: 2, imagesNoAlt: 0,
  forms: [{ action: "https://example.de/login", method: "post", password: true, csrf: true }], scripts: [{ src: "https://example.de/app.js" }], libs: [{ name: "jquery", version: "3.7.1", via: "Variable" }],
  legal: { imprint: "https://example.de/impressum", privacy: "https://example.de/datenschutz" },
  timing: { ttfb: 120, dcl: 600, load: 1200, lcp: 900 }, resources: { count: 20, bytes: 900000, largest: [], protocol: "h2" }, images: [],
};
const base = (o = {}) => ({ url: "https://example.de/", now: NOW, headers: goodHeaders, security: goodSecurity, chain: [], requests: [], page: goodPage,
  cookies: [{ name: "session", secure: true, httpOnly: true, sameSite: "lax" }], wellKnown: { securityTxt: true, robotsTxt: true, sitemap: true }, httpRedirect: { result: "https" }, ...o });
const find = (r, id) => r.items.find((i) => i.id === id);

test("gut eingerichtete Seite bekommt A/A+ und keine Probleme", () => {
  const r = C.analyze(base());
  assert.ok(["A+", "A"].includes(r.grade), r.grade + " " + r.scores.security);
  assert.equal(r.counts.bad, 0);
  assert.deepEqual(r.items.filter((i) => i.status === "warn").map((i) => i.id), []);
  assert.ok(r.scores.perf >= 90 && r.scores.seo >= 90);
  assert.ok(r.tech.includes("Nginx") && r.tech.includes("jQuery 3.7.1"));
  const t = C.analyze(base({ page: { ...goodPage, generator: "WordPress 6.4.2", tech: ["WordPress", "Google Fonts"] } })).tech;
  assert.ok(t.includes("WordPress 6.4.2") && !t.includes("WordPress") && t.includes("Google Fonts"));
});

test("HTTP-Seite: Note F, Passwort im Klartext", () => {
  const r = C.analyze(base({ url: "http://example.de/", security: null, httpRedirect: null, page: { ...goodPage, forms: [{ action: "http://example.de/login", password: true }] } }));
  assert.equal(r.grade, "F");
  assert.equal(find(r, "https").status, "bad");
  assert.equal(find(r, "form-pw").status, "bad");
  assert.equal(find(r, "form-http").status, "bad");
  assert.equal(find(r, "hsts"), undefined); // HSTS nur bei HTTPS sinnvoll
});

test("fehlende Header, Versions-Leck, schwache CSP", () => {
  const r = C.analyze(base({ headers: H({ Server: "Apache/2.4.29 (Ubuntu)", "X-Powered-By": "PHP/7.2.1", "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:" }) }));
  assert.equal(find(r, "hsts").status, "warn");
  assert.equal(find(r, "csp").status, "warn");
  assert.match(find(r, "csp").detail, /unsafe-inline/);
  assert.match(find(r, "csp").detail, /unsafe-eval/);
  assert.equal(find(r, "frame").status, "warn");
  assert.equal(find(r, "nosniff").status, "warn");
  assert.equal(find(r, "leak").status, "warn");
  assert.match(find(r, "leak").detail, /PHP\/7\.2\.1/);
  assert.equal(find(r, "compress").status, "warn");
  assert.ok(r.scores.security < 75, String(r.scores.security));
});

test("CSP mit Nonce + unsafe-inline gilt als in Ordnung (Fallback für alte Browser)", () => {
  const r = C.analyze(base({ headers: H({ "Content-Security-Policy": "script-src 'nonce-x' 'unsafe-inline' 'strict-dynamic'; object-src 'none'" }) }));
  assert.equal(find(r, "csp").status, "ok");
});

test("Zertifikat: abgelaufen / bald fällig, altes TLS, schwach", () => {
  const exp = C.analyze(base({ security: { ...goodSecurity, certificates: [{ ...goodSecurity.certificates[0], validity: { end: NOW - 86400000 } }] } }));
  assert.equal(find(exp, "cert").status, "bad");
  assert.ok(["C", "D", "F"].includes(exp.grade));
  const soon = C.analyze(base({ security: { ...goodSecurity, certificates: [{ ...goodSecurity.certificates[0], validity: { end: NOW + 86400000 * 5 } }] } }));
  assert.match(find(soon, "cert").title, /5 Tagen/);
  assert.equal(find(C.analyze(base({ security: { ...goodSecurity, protocolVersion: "TLSv1.1" } })), "tls").status, "bad");
  assert.equal(find(C.analyze(base({ security: { ...goodSecurity, state: "weak", weaknessReasons: ["cipher"] } })), "tls-state").status, "warn");
});

test("Mixed Content: Skripte kritisch, Bilder Hinweis", () => {
  const r = C.analyze(base({ requests: [{ url: "http://cdn.x.de/a.js", type: "script" }, { url: "http://cdn.x.de/b.png", type: "image" }] }));
  assert.equal(find(r, "mixed").status, "bad");
  const r2 = C.analyze(base({ requests: [{ url: "http://cdn.x.de/b.png", type: "image" }] }));
  assert.equal(find(r2, "mixed").status, "warn");
});

test("Cookies: Sitzungs-Cookie ohne Secure/HttpOnly, SameSite=None ohne Secure", () => {
  const r = C.analyze(base({ cookies: [{ name: "PHPSESSID", secure: false, httpOnly: false, sameSite: "no_restriction" }, { name: "theme", secure: true, httpOnly: false, sameSite: "lax" }] }));
  assert.equal(find(r, "cookie-secure").status, "bad");
  assert.match(find(r, "cookie-httponly").title, /PHPSESSID/);
  assert.doesNotMatch(find(r, "cookie-httponly").title, /theme/); // normale Cookies brauchen kein HttpOnly
  assert.equal(find(r, "cookie-samesite").status, "bad");
});

test("veraltete Bibliotheken: Lücken aus der retire.js-Datenbank, nicht mehr gepflegte Versionen", () => {
  const libs = [{ name: "jquery", version: "1.12.4", via: "Adresse", src: "https://code.jquery.com/jquery-1.12.4.min.js" }, { name: "bootstrap", version: "4.1.3", via: "Dateiinhalt" },
    { name: "lodash", version: "4.18.1", via: "Variable" }, { name: "angularjs", version: "1.8.2", via: "Variable" }];
  const r = C.analyze(base({ page: { ...goodPage, libs } }));
  const jq = find(r, "lib-jquery");
  assert.equal(jq.status, "warn"); // jQuery-Lücken sind „medium“
  assert.match(jq.title, /^jQuery 1\.12\.4: \d+ bekannte Lücken \(CVE-/);
  assert.match(jq.detail, /CVE-2020-11022|behoben in 3\.5\.0/);
  assert.match(jq.detail, /Erkannt über Adresse: https:\/\/code\.jquery\.com/);
  assert.match(jq.fix, /^Auf jQuery 3\.5\.0 oder neuer/);
  assert.ok(find(r, "lib-bootstrap"));
  assert.equal(find(r, "lib-lodash"), undefined);
  assert.ok(find(r, "lib-angularjs") || find(r, "eol-angularjs"));
  assert.equal(find(r, "eol-angularjs").status, "warn");
  assert.ok(r.tech.includes("jQuery 1.12.4"));
  assert.equal(C.cmpVersion("3.10.0", "3.9.9"), 1);
});

test("Drittanbieter, Tracker, SRI und heikle Kommentare", () => {
  const r = C.analyze(base({
    requests: [{ url: "https://www.googletagmanager.com/gtag/js", type: "script" }, { url: "https://static.hotjar.com/c.js", type: "script" }, { url: "https://cdn.example.de/x.js", type: "script" }],
    page: { ...goodPage, scripts: [{ src: "https://cdn.jsdelivr.net/npm/x.js" }, { src: "https://cdnjs.cloudflare.com/y.js", integrity: "sha384-abc" }, { src: "https://static.example.de/own.js" }], sensitiveComments: ["TODO Passwort für Admin: geheim123"] },
  }));
  assert.match(find(r, "consent").detail, /Google Tag Manager/);
  assert.match(find(r, "consent").detail, /Hotjar/);
  assert.match(find(r, "third").title, /^2 fremde/); // eigene Subdomain zählt nicht
  assert.equal(find(r, "sri").status, "warn");
  assert.match(find(r, "sri").title, /^1 fremde/);
  assert.equal(find(r, "comments").status, "warn");
});

test("Leistung und SEO bei schwacher Seite", () => {
  const r = C.analyze(base({
    headers: goodHeaders.filter((h) => h.name !== "Content-Encoding"),
    page: { title: "", h1: ["A", "B"], viewport: false, robots: "noindex", imagesTotal: 10, imagesNoAlt: 8, timing: { ttfb: 2100, load: 7000, lcp: 5200 }, resources: { count: 180, bytes: 12 * 1048576, largest: [{ name: "hero.png", bytes: 6e6 }], protocol: "http/1.1" }, images: [{ src: "hero.png", natural: 4000 * 3000, shown: 800 * 600, lazy: false, belowFold: false }] },
  }));
  for (const id of ["ttfb", "load", "lcp", "weight", "title", "viewport"]) assert.equal(find(r, id).status, "bad", id);
  for (const id of ["requests", "protocol", "compress", "img-size", "desc", "h1", "noindex", "alt"]) assert.equal(find(r, id).status, "warn", id);
  assert.ok(r.scores.perf < 40 && r.scores.seo < 50, JSON.stringify(r.scores));
});

test("Markdown-Bericht enthält Note, Probleme und Tipps", () => {
  const md = C.toMarkdown(C.analyze(base({ headers: H({}) })));
  assert.match(md, /^# n274 Secure Check: example\.de/);
  assert.match(md, /\*\*Sicherheit: [A-F]/);
  assert.match(md, /⚠️ \*\*Kein HSTS/);
  assert.match(md, /👉 Header setzen: Strict-Transport-Security/);
});

test("Netzwerk: Protokoll + Resource Timing zusammengeführt, Fehler, langsam, groß, Cache, Komprimierung", () => {
  const T0 = 1_000_000;
  const req = (url, type, o = {}) => ({ url, method: "GET", type, start: T0 + (o.at || 0), end: T0 + (o.at || 0) + (o.ms ?? 50), headersAt: T0 + (o.at || 0) + 20, status: o.status ?? 200, fromCache: !!o.cache, error: o.error || null, redirects: o.redirects || [], h: o.h || {} });
  const net = [
    req("https://example.de/", "main_frame", { h: { "content-type": "text/html", "content-encoding": "br" } }),
    req("https://example.de/app.js", "script", { at: 100, ms: 1800, h: { "content-type": "application/javascript", "cache-control": "no-cache" } }),
    req("https://example.de/fehlt.css", "stylesheet", { at: 120, status: 404, h: { "content-type": "text/html" } }),
    req("https://example.de/logo.png", "image", { at: 150, h: { "cache-control": "max-age=86400", "content-length": "800000" } }),
    req("https://example.de/logo.png", "image", { at: 160, cache: true }),
    req("https://example.de/x.png", "image", { at: 170 }),
    req("https://example.de/x.png", "image", { at: 180 }),
    req("https://www.google-analytics.com/g/collect", "ping", { at: 200, error: "NS_ERROR_TRACKING_URI" }),
    req("https://example.de/abgebrochen.js", "script", { at: 210, error: "NS_BINDING_ABORTED" }),
    req("https://cdn.other.net/big.js", "script", { at: 50, ms: 400, h: { "content-encoding": "gzip" } }),
  ];
  const resTiming = [
    { name: "https://example.de/app.js", transfer: 120000, encoded: 119000, decoded: 119000, protocol: "h2" },
    { name: "https://cdn.other.net/big.js", transfer: 300000, encoded: 299000, decoded: 900000, protocol: "h2" },
  ];
  const r = C.analyze(base({ net, navStart: T0, page: { ...goodPage, resTiming, blockingScripts: ["https://example.de/app.js", "https://a.de/1.js", "https://a.de/2.js"] } }));
  const n = r.network;
  assert.equal(n.totals.count, 10);
  const app = n.requests.find((x) => x.file === "app.js");
  assert.deepEqual([app.transfer, app.size, app.protocol, app.start, app.duration, app.wait], [120000, 119000, "h2", 100, 1800, 20]);
  assert.equal(n.requests.find((x) => x.file === "logo.png").transfer, 800000); // aus Content-Length
  assert.equal(find(r, "net-errors").status, "bad"); // fehlende CSS-Datei
  assert.match(find(r, "net-errors").detail, /404 · CSS · https:\/\/example\.de\/fehlt\.css/);
  assert.doesNotMatch(find(r, "net-errors").detail, /abgebrochen|collect/); // Abbruch und Blockade sind keine Fehler der Seite
  assert.match(find(r, "net-blocked").title, /^1 Anfragen/);
  assert.match(find(r, "net-slow").detail, /1,8 s · Skript/);
  assert.match(find(r, "net-big").detail, /big\.js/); // 900 KB entpackt
  assert.match(find(r, "net-big").detail, /logo\.png/);
  assert.equal(find(r, "net-compress").status, "warn");
  assert.match(find(r, "net-compress").detail, /app\.js/);
  assert.doesNotMatch(find(r, "net-compress").detail, /big\.js/);
  assert.match(find(r, "net-cache").detail, /no-cache · https:\/\/example\.de\/app\.js/);
  assert.doesNotMatch(find(r, "net-cache").detail, /logo\.png/);
  assert.match(find(r, "net-dup").detail, /2× https:\/\/example\.de\/x\.png/);
  assert.doesNotMatch(find(r, "net-dup").detail, /logo/); // zweites Mal aus dem Cache
  assert.equal(find(r, "net-blocking").status, "warn");
  assert.deepEqual(n.domains.map((x) => x.host), ["example.de", "cdn.other.net", "www.google-analytics.com"]); // nach übertragenen Bytes
  assert.ok(r.scores.net < 60, String(r.scores.net));
});

test("Netzwerk: saubere Seite ohne Auffälligkeiten", () => {
  const T0 = 5;
  const net = [{ url: "https://example.de/", method: "GET", type: "main_frame", start: T0, end: T0 + 80, headersAt: T0 + 40, status: 200, h: { "content-encoding": "br", "content-type": "text/html" } },
    { url: "https://example.de/a.js", method: "GET", type: "script", start: T0 + 90, end: T0 + 120, status: 200, h: { "content-encoding": "br", "content-type": "text/javascript", "cache-control": "public, max-age=31536000, immutable" } }];
  const r = C.analyze(base({ net, navStart: T0, page: { ...goodPage, blockingScripts: [] } }));
  assert.deepEqual(r.items.filter((i) => i.cat === "net" && i.status !== "ok" && i.status !== "info").map((i) => i.id), []);
  assert.equal(r.scores.net, 100);
});

test("Netzwerk: unbekannte Größen fremder Server zählen nicht als 0", () => {
  const net = [{ url: "https://example.de/", method: "GET", type: "main_frame", start: 0, end: 50, status: 200, h: { "content-length": "1000", "content-encoding": "br" } },
    { url: "https://fonts.gstatic.com/a.woff2", method: "GET", type: "font", start: 60, end: 90, status: 200, h: {} }];
  const r = C.analyze(base({ net, navStart: 0, page: { ...goodPage, resTiming: [{ name: "https://fonts.gstatic.com/a.woff2", transfer: 0, encoded: 0, decoded: 0 }] } }));
  const font = r.network.domains.find((d) => d.host === "fonts.gstatic.com");
  assert.equal(font.bytes, null);
  assert.equal(r.network.totals.thirdBytes, null);
  assert.equal(find(r, "net-third").title, "1 Anfragen an fremde Domains");
  assert.equal(r.network.requests[1].fromCache, false);
});

test("Formulare: Login per GET, fremdes Ziel, fehlendes CSRF-Token, autocomplete=off", () => {
  const forms = [
    { action: "https://example.de/login", method: "get", password: true, pwAutocomplete: "off", csrf: false },
    { name: "newsletter", action: "https://newsletter-dienst.com/subscribe", method: "post", csrf: false },
    { name: "kontakt", action: "https://example.de/kontakt", method: "post", csrf: false, upload: true },
  ];
  const r = C.analyze(base({ page: { ...goodPage, forms } }));
  assert.equal(find(r, "form-get").status, "bad");
  assert.match(find(r, "form-foreign").detail, /newsletter-dienst\.com/);
  assert.match(find(r, "form-csrf").detail, /kontakt/);
  assert.doesNotMatch(find(r, "form-csrf").detail, /newsletter/); // fremde Ziele nicht doppelt
  assert.equal(find(r, "form-ac").status, "info");
  assert.equal(find(r, "form-upload").status, "info");
  assert.equal(find(r, "form-get").cat, "forms");
});

test("DSGVO: Tracker vor Einwilligung, Google Fonts, Einbettungen, fehlendes Impressum", () => {
  const T0 = 1000;
  const req = (url, type, at) => ({ url, method: "GET", type, start: T0 + at, end: T0 + at + 30, status: 200, h: {} });
  const net = [req("https://example.de/", "main_frame", 0), req("https://www.googletagmanager.com/gtag/js?id=G-1", "script", 200), req("https://fonts.googleapis.com/css2?family=Inter", "stylesheet", 120),
    req("https://www.youtube.com/embed/abc", "sub_frame", 400), req("https://cdn.jsdelivr.net/npm/x.js", "script", 150)];
  const page = { ...goodPage, legal: { imprint: null, privacy: "https://example.de/datenschutz" } };
  const r = C.analyze(base({ net, navStart: T0, page, cookies: [{ name: "_ga", secure: true }] }));
  assert.equal(find(r, "consent").status, "bad");
  assert.match(find(r, "consent").detail, /Google Tag Manager \(Tracking, USA\)/);
  assert.match(find(r, "consent").detail, /YouTube-Einbettung/);
  assert.equal(find(r, "cmp").status, "warn");
  assert.equal(find(r, "track-cookies").status, "bad");
  assert.equal(find(r, "gfonts").status, "warn");
  assert.equal(find(r, "embeds").status, "warn");
  assert.match(find(r, "cdn").title, /jsDelivr/);
  assert.match(find(r, "abroad").detail, /Google Fonts \(USA\)/);
  assert.equal(find(r, "imprint").status, "bad");
  assert.equal(find(r, "privacy-link").status, "ok");
  assert.ok(r.scores.privacy < 40, String(r.scores.privacy));
  // gleiche Seite: Tracker erst nach dem ersten Klick, Banner vorhanden → in Ordnung
  const later = [req("https://example.de/", "main_frame", 0), req("https://app.usercentrics.eu/browser-ui/latest/loader.js", "script", 100), req("https://www.googletagmanager.com/gtag/js", "script", 5000)];
  const ok = C.analyze(base({ net: later, navStart: T0, firstInteraction: T0 + 3000, page: goodPage, cookies: [] }));
  assert.equal(find(ok, "consent").status, "ok");
  assert.match(find(ok, "cmp").title, /Usercentrics/);
  // Einwilligung schon erteilt (Cookie) → nur Hinweis
  const consented = C.analyze(base({ net, navStart: T0, page: goodPage, cookies: [{ name: "CookieConsent", secure: true }] }));
  assert.equal(find(consented, "consent").status, "info");
  assert.match(find(consented, "consent").detail, /privaten Fenster/);
});

test("DSGVO: Impressum-Pflicht nur für deutschsprachige Seiten", () => {
  const r = C.analyze(base({ url: "https://example.com/", page: { ...goodPage, lang: "en", legal: {} } }));
  assert.equal(find(r, "imprint"), undefined);
  const de = C.analyze(base({ url: "https://example.com/", page: { ...goodPage, lang: "de-DE", legal: {} } }));
  assert.equal(find(de, "imprint").status, "bad");
});

test("Offene Dateien fließen in die Sicherheitsnote ein (nur eigene Seiten)", () => {
  const notOwn = C.analyze(base());
  assert.equal(notOwn.own, false);
  assert.equal(notOwn.items.filter((i) => i.cat === "exposed").length, 0);
  const clean = C.analyze(base({ exposed: [], exposedChecked: 30 }));
  assert.equal(clean.own, true);
  assert.equal(find(clean, "exposed-none").title, "Keine offenen Dateien gefunden (30 Pfade geprüft)");
  const E = require("../lib/exposed");
  const leak = E.evaluate([{ path: "/.env", status: 200, finalUrl: "https://example.de/.env", text: "DB_PASSWORD=x" }]);
  const r = C.analyze(base({ exposed: leak, exposedChecked: 30 }));
  assert.ok(["C", "D", "F"].includes(r.grade), r.grade);
});
