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
  forms: [{ action: "https://example.de/login", password: true }], scripts: [{ src: "https://example.de/app.js" }], libs: [{ name: "jQuery", version: "3.7.1" }],
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

test("veraltete Bibliotheken mit bekannten Lücken", () => {
  const libs = [{ name: "jQuery", version: "1.12.4", src: "https://code.jquery.com/jquery-1.12.4.min.js" }, { name: "Bootstrap", version: "4.1.3" }, { name: "Lodash", version: "4.17.21" }, { name: "AngularJS", version: "1.8.2" }];
  const r = C.analyze(base({ page: { ...goodPage, libs } }));
  assert.equal(find(r, "lib-jQuery").status, "bad");
  assert.match(find(r, "lib-jQuery").title, /CVE-2020-11022/);
  assert.equal(find(r, "lib-Bootstrap").status, "bad");
  assert.equal(find(r, "lib-Lodash"), undefined);
  assert.equal(find(r, "lib-AngularJS").status, "warn");
  assert.equal(C.analyze(base({ page: { ...goodPage, libs: [{ name: "Bootstrap", version: "3.4.1" }] } })).items.find((i) => i.id === "lib-Bootstrap"), undefined);
  assert.equal(C.cmpVersion("3.10.0", "3.9.9"), 1);
  assert.equal(C.cmpVersion("3.5", "3.5.0"), 0);
});

test("Drittanbieter, Tracker, SRI und heikle Kommentare", () => {
  const r = C.analyze(base({
    requests: [{ url: "https://www.googletagmanager.com/gtag/js", type: "script" }, { url: "https://static.hotjar.com/c.js", type: "script" }, { url: "https://cdn.example.de/x.js", type: "script" }],
    page: { ...goodPage, scripts: [{ src: "https://cdn.jsdelivr.net/npm/x.js" }, { src: "https://cdnjs.cloudflare.com/y.js", integrity: "sha384-abc" }, { src: "https://static.example.de/own.js" }], sensitiveComments: ["TODO Passwort für Admin: geheim123"] },
  }));
  assert.match(find(r, "trackers").title, /Google Tag Manager/);
  assert.match(find(r, "trackers").title, /Hotjar/);
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
