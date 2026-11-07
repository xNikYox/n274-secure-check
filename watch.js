// n274 Secure Check – Überwachung eigener Seiten: täglich im Hintergrund prüfen, mit dem letzten Stand vergleichen und
// bei Problemen Bescheid geben (Zertifikat läuft ab, Fehlerseiten, kaputte Links, Sicherheits-Header weg, offene Dateien).
"use strict";

const WATCH_ALARM = "n274-watch";
const DAY = 24 * 3600 * 1000;
const captured = new Map(); // URL → { headers, security, status } aus Hintergrund-Abrufen (tabId -1)

// Zertifikat und Header der eigenen Abrufe mitschneiden (nur Abrufe des Addons selbst)
browser.webRequest.onHeadersReceived.addListener(async (d) => {
  if (!watchPending.has(d.url)) return {};
  let security = null;
  try {
    security = await browser.webRequest.getSecurityInfo(d.requestId, { certificateChain: false });
  } catch {
    // kein HTTPS
  }
  captured.set(d.url, { headers: d.responseHeaders || [], security: slimSecurity(security), status: d.statusCode, ip: d.ip || null });
  return {};
}, { urls: ["<all_urls>"], tabId: -1, types: ["xmlhttprequest"] }, ["blocking", "responseHeaders"]);
const watchPending = new Set();

async function getWatch() {
  return (await browser.storage.local.get("watch")).watch || [];
}
async function setWatch(list) {
  await browser.storage.local.set({ watch: list });
}

function normalize(url) {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url) && !/^https?:\/\//i.test(url)) throw new Error("Nur http/https");
  const u = new URL(/^https?:\/\//i.test(url) ? url : "https://" + url);
  if (!/^https?:$/.test(u.protocol)) throw new Error("Nur http/https");
  u.hash = "";
  return u.href;
}

/** Eine Seite prüfen → Stand (snapshot) */
async function checkSite(url) {
  const snap = { at: Date.now(), url, status: null, error: null, certDays: null, certIssuer: null, tls: null, headers: {}, grade: null, score: null,
    httpsRedirect: null, broken: [], exposed: [], problems: [] };
  let finalUrl = url;
  let html = "";
  // 1) Seite abrufen (Header + Zertifikat über webRequest)
  for (let hop = 0; hop < 6; hop++) {
    watchPending.add(finalUrl);
    try {
      const r = await probe(finalUrl, { redirect: "manual" });
      const cap = captured.get(finalUrl);
      const loc = cap?.headers.find((h) => h.name.toLowerCase() === "location")?.value;
      if (cap && cap.status >= 300 && cap.status < 400 && loc) {
        finalUrl = new URL(loc, finalUrl).href;
        continue;
      }
      snap.status = cap?.status ?? r.status;
      if (r.ok || r.type === "basic") html = await readText(r, 2_000_000);
      break;
    } catch (e) {
      snap.error = String(e.message || e);
      break;
    } finally {
      watchPending.delete(finalUrl);
    }
  }
  const cap = captured.get(finalUrl);
  captured.clear();
  if (cap) {
    const h = Checks.headerMap(cap.headers);
    const csp = h["content-security-policy"] || "";
    snap.headers = {
      HSTS: !!h["strict-transport-security"],
      CSP: !!csp,
      Clickjacking: /frame-ancestors/i.test(csp) || /deny|sameorigin/i.test(h["x-frame-options"] || ""),
      nosniff: /nosniff/i.test(h["x-content-type-options"] || ""),
      "Referrer-Policy": !!h["referrer-policy"],
    };
    const c = cap.security?.certificates?.[0];
    if (c?.validity?.end) snap.certDays = Math.floor((c.validity.end - Date.now()) / 86400000);
    snap.certIssuer = c?.issuer || null;
    snap.tls = cap.security?.protocolVersion || null;
    // Sicherheitsnote aus Verbindung + Headern (ohne Seiteninhalt)
    const report = Checks.analyze({ url: finalUrl, now: Date.now(), headers: cap.headers, security: cap.security, chain: [], requests: [], page: {}, cookies: [], wellKnown: {}, httpRedirect: null, net: [] });
    snap.grade = report.grade;
    snap.score = report.scores.security;
  }
  const origin = new URL(finalUrl).origin;
  if (/^https:/.test(finalUrl)) snap.httpsRedirect = (await httpRedirect(new URL(finalUrl).host)).result;
  // 2) Eigene Links und Dateien der Seite auf Fehler prüfen
  if (html) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const urls = new Set();
    for (const el of doc.querySelectorAll("a[href], link[href][rel~=stylesheet], script[src], img[src]")) {
      const raw = el.getAttribute("href") || el.getAttribute("src");
      try {
        const u = new URL(raw, finalUrl);
        u.hash = "";
        if (u.origin === origin && !/^(mailto|tel|javascript):/i.test(raw)) urls.add(u.href);
      } catch {
        // ungültige Adresse
      }
      if (urls.size >= 40) break;
    }
    await pool([...urls], 4, async (u) => {
      try {
        let r = await probe(u, { method: "HEAD" });
        if (r.status === 405 || r.status === 501) r = await probe(u);
        if (r.status >= 400) snap.broken.push(`${r.status} ${u}`);
      } catch {
        snap.broken.push(`nicht erreichbar ${u}`);
      }
    });
  }
  // 3) Offene Dateien
  const ex = await probeExposed(origin, true);
  snap.exposed = ex.items.map((i) => ({ status: i.status, title: i.title }));
  // Probleme zusammenfassen
  const p = snap.problems;
  if (snap.error) p.push({ status: "bad", text: "Nicht erreichbar: " + snap.error });
  else if (snap.status >= 400) p.push({ status: "bad", text: `Seite antwortet mit Fehler ${snap.status}` });
  if (snap.certDays != null && snap.certDays < 0) p.push({ status: "bad", text: "Zertifikat abgelaufen" });
  else if (snap.certDays != null && snap.certDays < 14) p.push({ status: "warn", text: `Zertifikat läuft in ${snap.certDays} Tagen ab` });
  if (snap.httpsRedirect === "http") p.push({ status: "bad", text: "HTTP leitet nicht auf HTTPS um" });
  for (const [k, v] of Object.entries(snap.headers)) if (!v) p.push({ status: "warn", text: `${k} fehlt` });
  if (snap.broken.length) p.push({ status: "warn", text: `${snap.broken.length} kaputte Links/Dateien` });
  for (const e of snap.exposed) p.push({ status: e.status, text: e.title });
  return snap;
}

/** Was hat sich seit dem letzten Stand geändert? */
function changes(prev, now) {
  if (!prev) return [];
  const out = [];
  const add = (status, text) => out.push({ status, text });
  if (prev.grade && now.grade && prev.grade !== now.grade) add(gradeRank(now.grade) > gradeRank(prev.grade) ? "bad" : "ok", `Note ${prev.grade} → ${now.grade}`);
  if (prev.status !== now.status) add(now.status >= 400 || now.error ? "bad" : "ok", `Status ${prev.status ?? prev.error ?? "?"} → ${now.status ?? "nicht erreichbar"}`);
  for (const k of Object.keys(now.headers)) {
    if (prev.headers?.[k] && !now.headers[k]) add("bad", `${k} entfernt`);
    if (prev.headers && !prev.headers[k] && now.headers[k]) add("ok", `${k} neu`);
  }
  if (prev.certDays != null && now.certDays != null && now.certDays > prev.certDays + 5) add("ok", `Zertifikat erneuert (noch ${now.certDays} Tage)`);
  const newBroken = now.broken.filter((b) => !(prev.broken || []).includes(b));
  if (newBroken.length) add("warn", `${newBroken.length} neue kaputte Links: ${newBroken.slice(0, 3).join(", ")}`);
  const fixed = (prev.broken || []).filter((b) => !now.broken.includes(b));
  if (fixed.length) add("ok", `${fixed.length} Links wieder in Ordnung`);
  const newExposed = now.exposed.filter((e) => !(prev.exposed || []).some((x) => x.title === e.title));
  for (const e of newExposed) add("bad", "Neu offen: " + e.title);
  const closed = (prev.exposed || []).filter((e) => !now.exposed.some((x) => x.title === e.title));
  for (const e of closed) add("ok", "Wieder geschlossen: " + e.title);
  return out;
}
const gradeRank = (g) => ["A+", "A", "B", "C", "D", "F"].indexOf(g);

/** Eine Seite prüfen, speichern und bei Neuem Bescheid geben */
async function runCheck(id, notify = true) {
  const list = await getWatch();
  const site = list.find((s) => s.id === id);
  if (!site) return null;
  const snap = await checkSite(site.url);
  const ch = changes(site.last, snap);
  const fresh = await getWatch(); // inzwischen geändert?
  const s = fresh.find((x) => x.id === id);
  if (!s) return null;
  s.last = snap;
  s.changes = ch.length ? ch : s.changes || [];
  s.changedAt = ch.length ? snap.at : s.changedAt || null;
  s.history = [...(s.history || []), { at: snap.at, grade: snap.grade, problems: snap.problems.length }].slice(-60);
  await setWatch(fresh);
  const bad = snap.problems.filter((p) => p.status === "bad");
  const news = ch.filter((c) => c.status !== "ok");
  if (notify && (news.length || (bad.length && !site.last))) {
    browser.notifications.create("n274-" + id, {
      type: "basic",
      iconUrl: browser.runtime.getURL("icons/icon-96.png"),
      title: `n274 Secure Check: ${new URL(s.url).host}`,
      message: (news.length ? news : bad).slice(0, 3).map((x) => x.text).join("\n"),
    });
  }
  return s;
}

/** Fällige Seiten prüfen (einmal täglich) */
async function runDue() {
  for (const s of await getWatch()) {
    if (!s.last || Date.now() - s.last.at > DAY - 10 * 60 * 1000) await runCheck(s.id).catch(() => {});
  }
}

browser.alarms.create(WATCH_ALARM, { periodInMinutes: 60, delayInMinutes: 1 });
browser.alarms.onAlarm.addListener((a) => a.name === WATCH_ALARM && runDue());
browser.notifications.onClicked.addListener((id) => {
  if (id.startsWith("n274-")) browser.tabs.create({ url: browser.runtime.getURL("watch/watch.html") });
});

browser.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "watch:list") return getWatch();
  if (msg?.type === "watch:add") {
    return (async () => {
      let url;
      try {
        url = normalize(msg.url);
      } catch {
        return { error: "Ungültige Adresse." };
      }
      const list = await getWatch();
      if (list.some((s) => new URL(s.url).host === new URL(url).host)) return { error: "Diese Seite wird schon überwacht." };
      const site = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), url, added: Date.now(), last: null, changes: [], history: [] };
      await setWatch([...list, site]);
      runCheck(site.id, false);
      return { site };
    })();
  }
  if (msg?.type === "watch:remove") return getWatch().then((l) => setWatch(l.filter((s) => s.id !== msg.id))).then(() => ({ ok: true }));
  if (msg?.type === "watch:check") return runCheck(msg.id, false).then((site) => ({ site }));
  return undefined;
});
