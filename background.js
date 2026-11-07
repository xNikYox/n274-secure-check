// n274 Secure Check – Hintergrund: merkt sich je Tab Header, Zertifikat, Weiterleitungen und Anfragen der geladenen Seite
// und erstellt auf Abruf den Bericht. Alles bleibt lokal; abgerufen wird nur die geprüfte Seite selbst.
"use strict";

const tabs = new Map(); // tabId → { main, chain, net, redirecting, report, navStart }
const pending = new Map(); // requestId → Eintrag im Netzwerk-Protokoll
const MAX_REQUESTS = 3000;
const SUB_TYPES = ["sub_frame", "stylesheet", "script", "image", "imageset", "font", "object", "xmlhttprequest", "ping", "beacon", "media", "websocket", "csp_report", "speculative", "web_manifest", "other"];
const KEEP_HEADERS = ["content-type", "content-length", "content-encoding", "cache-control", "expires", "etag", "last-modified", "age", "x-cache", "cf-cache-status", "access-control-allow-origin", "timing-allow-origin"];

function fresh(navStart = Date.now()) {
  return { main: null, chain: [], net: [], redirecting: false, report: null, navStart };
}

/* ---------------- Aufzeichnen ---------------- */
browser.webRequest.onBeforeRequest.addListener((d) => {
  if (d.tabId < 0) return;
  const rec = tabs.get(d.tabId);
  if (rec && rec.redirecting) rec.redirecting = false; // gehört noch zur selben Navigation
  else {
    if (rec) for (const e of rec.net) if (e.id !== d.requestId) pending.delete(e.id); // alte Seite vergessen
    tabs.set(d.tabId, fresh(d.timeStamp));
  }
}, { urls: ["<all_urls>"], types: ["main_frame"] });

/* ---- Netzwerk-Protokoll: jede Anfrage des Tabs mit Zeiten, Status, Headern, Fehlern ---- */
browser.webRequest.onBeforeRequest.addListener((d) => {
  if (d.tabId < 0 || pending.has(d.requestId)) return; // Weiterleitung: gleiche requestId, Eintrag besteht schon
  const rec = tabs.get(d.tabId);
  if (!rec || rec.net.length >= MAX_REQUESTS) return;
  const e = { id: d.requestId, url: d.url, method: d.method, type: d.type, start: d.timeStamp, status: null, end: null, headersAt: null, fromCache: false, ip: null, error: null, redirects: [], h: {} };
  rec.net.push(e);
  pending.set(d.requestId, e);
}, { urls: ["<all_urls>"], types: ["main_frame", ...SUB_TYPES] });

browser.webRequest.onBeforeRedirect.addListener((d) => {
  const e = pending.get(d.requestId);
  if (e) {
    e.redirects.push({ status: d.statusCode, from: d.url, to: d.redirectUrl });
    e.url = d.redirectUrl;
  }
}, { urls: ["<all_urls>"] });

browser.webRequest.onHeadersReceived.addListener((d) => {
  const e = pending.get(d.requestId);
  if (!e) return;
  e.status = d.statusCode;
  e.headersAt = d.timeStamp;
  e.ip = d.ip || e.ip;
  e.h = {};
  for (const { name, value } of d.responseHeaders || []) {
    const k = name.toLowerCase();
    if (KEEP_HEADERS.includes(k)) e.h[k] = value;
  }
}, { urls: ["<all_urls>"] }, ["responseHeaders"]);

browser.webRequest.onCompleted.addListener((d) => {
  const e = pending.get(d.requestId);
  if (!e) return;
  e.end = d.timeStamp;
  e.status = d.statusCode;
  e.fromCache = !!d.fromCache;
  e.ip = d.ip || e.ip;
  pending.delete(d.requestId);
}, { urls: ["<all_urls>"] });

browser.webRequest.onErrorOccurred.addListener((d) => {
  const e = pending.get(d.requestId);
  if (!e) return;
  e.end = d.timeStamp;
  e.error = d.error;
  pending.delete(d.requestId);
}, { urls: ["<all_urls>"] });

browser.webRequest.onBeforeRedirect.addListener((d) => {
  const rec = tabs.get(d.tabId);
  if (!rec) return;
  rec.chain.push({ url: d.url, status: d.statusCode, to: d.redirectUrl });
  rec.redirecting = true;
}, { urls: ["<all_urls>"], types: ["main_frame"] });

// Zertifikat lässt sich nur hier (blockierend) lesen – nur für die Hauptseite, damit nichts ausgebremst wird
browser.webRequest.onHeadersReceived.addListener(async (d) => {
  if (d.tabId < 0 || (d.statusCode >= 300 && d.statusCode < 400)) return {};
  const rec = tabs.get(d.tabId) || fresh();
  let security = null;
  try {
    security = await browser.webRequest.getSecurityInfo(d.requestId, { certificateChain: false });
  } catch {
    // kein HTTPS oder nicht verfügbar
  }
  rec.main = { url: d.url, status: d.statusCode, headers: d.responseHeaders || [], security: slimSecurity(security), ip: d.ip || null, at: Date.now() };
  tabs.set(d.tabId, rec);
  return {};
}, { urls: ["<all_urls>"], types: ["main_frame"] }, ["blocking", "responseHeaders"]);

browser.tabs.onRemoved.addListener((id) => {
  const rec = tabs.get(id);
  if (rec) for (const e of rec.net) pending.delete(e.id);
  tabs.delete(id);
});

/** Nur das Nötige vom Zertifikat behalten */
function slimSecurity(s) {
  if (!s) return null;
  const c = s.certificates?.[0];
  return {
    state: s.state,
    protocolVersion: s.protocolVersion,
    cipherSuite: s.cipherSuite,
    hsts: s.hsts,
    isExtendedValidation: s.isExtendedValidation,
    certificateTransparencyStatus: s.certificateTransparencyStatus,
    weaknessReasons: s.weaknessReasons || [],
    errorMessage: s.errorMessage || null,
    certificates: c ? [{ subject: cn(c.subject), issuer: cn(c.issuer), validity: c.validity }] : [],
  };
}
const cn = (dn) => (/CN=([^,]+)/.exec(dn || "") || [])[1] || dn || null;

/* ---------------- Zusätzliche Abrufe bei der geprüften Seite ---------------- */
async function probe(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    return await fetch(url, { cache: "no-store", credentials: "omit", signal: ctrl.signal, ...opts });
  } finally {
    clearTimeout(t);
  }
}

async function wellKnown(origin) {
  const exists = async (path, type) => {
    try {
      const r = await probe(origin + path);
      if (!r.ok) return false;
      const ct = r.headers.get("content-type") || "";
      // Viele Seiten liefern für alles die Startseite aus – dann zählt es nicht
      return type.test(ct) || (!/html/i.test(ct) && ct !== "");
    } catch {
      return null;
    }
  };
  const [securityTxt, robotsTxt, sitemap] = await Promise.all([
    exists("/.well-known/security.txt", /text\/plain/i),
    exists("/robots.txt", /text\/plain/i),
    exists("/sitemap.xml", /xml/i),
  ]);
  return { securityTxt, robotsTxt, sitemap };
}

/** Leitet http:// auf https:// um? → "https" | "http" | "error" */
async function httpRedirect(host) {
  try {
    const r = await probe("http://" + host + "/", { method: "GET" });
    return { result: /^https:/i.test(r.url) ? "https" : "http" };
  } catch {
    return { result: "error" };
  }
}

/* ---------------- Bericht ---------------- */
async function analyze(tabId) {
  const tab = await browser.tabs.get(tabId);
  if (!/^https?:/i.test(tab.url || "")) return { error: "Nur Webseiten (http/https) lassen sich prüfen." };
  const rec = tabs.get(tabId);
  const sameDoc = rec?.main && sameOrigin(rec.main.url, tab.url);
  if (!sameDoc) return { needsReload: true };
  const [result] = await browser.tabs.executeScript(tabId, { file: "/content.js", runAt: "document_idle" });
  const origin = new URL(tab.url).origin;
  const [cookies, wk, redir] = await Promise.all([
    browser.cookies.getAll({ url: tab.url }).catch(() => []),
    wellKnown(origin),
    /^https:/i.test(tab.url) ? httpRedirect(new URL(tab.url).host) : Promise.resolve(null),
  ]);
  const report = Checks.analyze({
    url: tab.url,
    now: Date.now(),
    headers: rec.main.headers,
    security: rec.main.security,
    chain: rec.chain,
    requests: rec.net.filter((e) => e.type !== "main_frame").map((e) => ({ url: e.url, type: e.type, status: e.status, ip: e.ip })),
    net: rec.net.map(({ id, ...e }) => e),
    navStart: rec.navStart,
    page: result || {},
    cookies: cookies.map((c) => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, session: c.session })),
    wellKnown: wk,
    httpRedirect: redir,
  });
  report.ip = rec.main.ip;
  report.status = rec.main.status;
  report.title = result?.title || tab.title;
  rec.report = report;
  return { report };
}

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

browser.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "analyze") return analyze(msg.tabId).catch((e) => ({ error: String(e.message || e) }));
  if (msg?.type === "report") return Promise.resolve({ report: tabs.get(msg.tabId)?.report || null });
  if (msg?.type === "reload") return browser.tabs.reload(msg.tabId, { bypassCache: true }).then(() => ({ ok: true }));
  return undefined;
});
