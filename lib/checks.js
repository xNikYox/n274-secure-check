// n274 Secure Check – Prüflogik. Reine Funktionen ohne Browser-APIs: bekommt gesammelte Daten, liefert den Bericht.
// Läuft im Hintergrundskript (globalThis.Checks) und in Node (Tests).
(function () {
  "use strict";

  /** Ein Prüfpunkt: status ok | warn | bad | info; weight = wie stark er die Note beeinflusst */
  const item = (id, cat, status, title, detail = "", fix = "", weight = 0) => ({ id, cat, status, title, detail, fix, weight });

  const NODE = typeof module !== "undefined" && module.exports;
  const Retire = NODE ? require("./retire") : globalThis.Retire;
  const RETIRE_DB = NODE ? require("./retire-db").db : globalThis.RETIRE_DB;

  const CATS = {
    conn: "Verbindung & Zertifikat",
    headers: "Sicherheits-Header",
    cookies: "Cookies",
    content: "Inhalte & Skripte",
    forms: "Formulare",
    exposed: "Offene Dateien (eigene Seite)",
    privacy: "Datenschutz (DSGVO)",
    perf: "Leistung",
    net: "Netzwerk",
    seo: "SEO",
  };
  const SECURITY_CATS = ["conn", "headers", "cookies", "content", "forms", "exposed"];

  /** Header-Liste ({name, value}) → Objekt mit kleinen Namen; mehrere gleiche Header mit \n verbunden */
  function headerMap(list) {
    const h = {};
    for (const { name, value } of list || []) {
      const k = String(name).toLowerCase();
      h[k] = h[k] ? h[k] + "\n" + value : String(value ?? "");
    }
    return h;
  }

  /** Versionen vergleichen: -1, 0, 1 */
  function cmpVersion(a, b) {
    const pa = String(a).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
    const pb = String(b).split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] || 0) - (pb[i] || 0);
      if (d) return d < 0 ? -1 : 1;
    }
    return 0;
  }

  const hostOf = (u) => {
    try {
      return new URL(u).hostname.toLowerCase();
    } catch {
      return "";
    }
  };
  /** Grobe „Hauptdomain“ (letzte zwei Teile; bei co.uk & Co. drei) – reicht für eigene vs. fremde Anfragen */
  function siteOf(host) {
    const p = String(host).split(".").filter(Boolean);
    if (p.length <= 2) return p.join(".");
    const two = p.slice(-2).join(".");
    return /^(co|com|org|net|gov|ac|edu)\.[a-z]{2}$/.test(two) ? p.slice(-3).join(".") : two;
  }
  const fmtBytes = (b) => (b >= 1048576 ? (b / 1048576).toFixed(1).replace(".", ",") + " MB" : Math.round(b / 1024) + " KB");
  const fmtMs = (ms) => (ms >= 1000 ? (ms / 1000).toFixed(1).replace(".", ",") + " s" : Math.round(ms) + " ms");

  /* ======================= Verbindung & Zertifikat ======================= */
  function checkConnection(d) {
    const out = [];
    const https = /^https:/i.test(d.url);
    out.push(https
      ? item("https", "conn", "ok", "Verschlüsselt über HTTPS", "", "", 15)
      : item("https", "conn", "bad", "Keine Verschlüsselung (HTTP)", "Alles – auch Passwörter und Formulare – geht im Klartext über das Netz.", "HTTPS mit einem kostenlosen Zertifikat (z. B. Let's Encrypt) einrichten und HTTP auf HTTPS weiterleiten.", 15));
    const s = d.security;
    if (https && s) {
      if (s.state === "broken" || s.state === "insecure") {
        out.push(item("tls-state", "conn", "bad", "Verbindung als unsicher eingestuft", (s.errorMessage || "") + (s.weaknessReasons?.length ? " Gründe: " + s.weaknessReasons.join(", ") : ""), "Zertifikat und TLS-Einstellungen des Servers prüfen.", 20));
      } else if (s.state === "weak") {
        out.push(item("tls-state", "conn", "warn", "Schwache Verschlüsselung", "Gründe: " + (s.weaknessReasons || []).join(", "), "Veraltete Cipher (z. B. RC4, 3DES) auf dem Server abschalten.", 10));
      }
      const v = s.protocolVersion || "";
      if (/TLSv1\.3/.test(v)) out.push(item("tls", "conn", "ok", "TLS 1.3", s.cipherSuite || "", "", 6));
      else if (/TLSv1\.2/.test(v)) out.push(item("tls", "conn", "ok", "TLS 1.2", (s.cipherSuite || "") + " – TLS 1.3 wäre noch etwas besser.", "TLS 1.3 auf dem Server aktivieren.", 6));
      else if (v) out.push(item("tls", "conn", "bad", "Veraltetes Protokoll: " + v, "TLS 1.0 und 1.1 gelten als unsicher.", "Nur TLS 1.2 und 1.3 erlauben.", 12));
      const cert = s.certificates?.[0];
      if (cert) {
        const end = cert.validity?.end;
        const days = end ? Math.floor((end - (d.now || Date.now())) / 86400000) : null;
        const who = `Für ${cert.subject || "?"}, ausgestellt von ${cert.issuer || "?"}`;
        if (days == null) out.push(item("cert", "conn", "info", "Zertifikat", who));
        else if (days < 0) out.push(item("cert", "conn", "bad", "Zertifikat abgelaufen", who, "Zertifikat erneuern (bei Let's Encrypt automatisch per certbot/acme).", 20));
        else if (days < 14) out.push(item("cert", "conn", "warn", `Zertifikat läuft in ${days} Tagen ab`, who, "Automatische Erneuerung prüfen.", 6));
        else out.push(item("cert", "conn", "ok", `Zertifikat gültig (noch ${days} Tage)`, who, "", 6));
        if (s.isExtendedValidation) out.push(item("ev", "conn", "info", "Erweitertes Zertifikat (EV)"));
      }
      if (s.certificateTransparencyStatus === "policy_not_enough_scts" || s.certificateTransparencyStatus === "policy_not_diverse_scts") {
        out.push(item("ct", "conn", "warn", "Zertifikat erfüllt Certificate Transparency nicht", s.certificateTransparencyStatus, "Zertifikat bei einer gängigen Zertifizierungsstelle neu ausstellen lassen.", 4));
      }
    } else if (https && !s) {
      out.push(item("tls", "conn", "info", "Zertifikat nicht gelesen", "Die Seite wurde aus dem Cache geladen. Neu laden für alle Details."));
    }
    // HTTP → HTTPS
    if (https && d.httpRedirect) {
      const r = d.httpRedirect;
      if (r.result === "https") out.push(item("redirect", "conn", "ok", "HTTP leitet auf HTTPS um", "", "", 5));
      else if (r.result === "http") out.push(item("redirect", "conn", "bad", "HTTP-Version leitet nicht auf HTTPS um", "Wer http:// eintippt, surft unverschlüsselt.", "Auf dem Server alle HTTP-Anfragen mit 301 auf https:// umleiten.", 8));
      else out.push(item("redirect", "conn", "info", "HTTP-Weiterleitung nicht prüfbar", r.result === "error" ? "Port 80 nicht erreichbar oder blockiert (oft in Ordnung)." : ""));
    }
    // Weiterleitungskette
    if (d.chain?.length) {
      const insecure = d.chain.some((c) => /^http:/i.test(c.to) && https);
      out.push(item("chain", "conn", insecure ? "warn" : "info", `${d.chain.length} Weiterleitung${d.chain.length > 1 ? "en" : ""} bis zur Seite`,
        d.chain.map((c) => `${c.status} ${c.url} → ${c.to}`).join("\n"), insecure ? "Weiterleitungen direkt auf die HTTPS-Adresse zeigen lassen." : "", insecure ? 4 : 0));
    }
    // Gemischte Inhalte
    if (https) {
      const mixed = (d.requests || []).filter((r) => /^http:/i.test(r.url));
      const active = mixed.filter((r) => ["script", "stylesheet", "sub_frame", "xmlhttprequest", "object", "websocket"].includes(r.type));
      if (active.length) out.push(item("mixed", "conn", "bad", `${active.length} unverschlüsselte Skripte/Anfragen (Mixed Content)`, active.slice(0, 8).map((r) => r.url).join("\n"), "Alle Ressourcen über https:// laden.", 12));
      else if (mixed.length) out.push(item("mixed", "conn", "warn", `${mixed.length} Bilder/Medien über HTTP`, mixed.slice(0, 8).map((r) => r.url).join("\n"), "Bilder und Medien über https:// laden.", 5));
      else out.push(item("mixed", "conn", "ok", "Keine unverschlüsselten Inhalte", "", "", 5));
    }
    return out;
  }

  /* ======================= Sicherheits-Header ======================= */
  function parseCsp(csp) {
    const dirs = {};
    for (const part of String(csp).split(";")) {
      const [name, ...vals] = part.trim().split(/\s+/);
      if (name) dirs[name.toLowerCase()] = vals;
    }
    return dirs;
  }

  function checkHeaders(d) {
    const h = d.headers;
    const https = /^https:/i.test(d.url);
    const out = [];
    // HSTS
    if (https) {
      const hsts = h["strict-transport-security"];
      const age = hsts ? parseInt((/max-age\s*=\s*"?(\d+)/i.exec(hsts) || [])[1] || "0", 10) : 0;
      if (!hsts) out.push(item("hsts", "headers", "warn", "Kein HSTS (Strict-Transport-Security)", "Browser könnten beim ersten Besuch noch über HTTP verbinden.", "Header setzen: Strict-Transport-Security: max-age=31536000; includeSubDomains", 8));
      else if (age < 15552000) out.push(item("hsts", "headers", "warn", "HSTS mit kurzer Laufzeit", `max-age=${age} (unter 180 Tagen)`, "max-age auf mindestens 31536000 (1 Jahr) setzen.", 4));
      else out.push(item("hsts", "headers", "ok", "HSTS aktiv", hsts + (d.security?.hsts ? " · im Browser gespeichert" : ""), "", 8));
    }
    // CSP
    const cspText = h["content-security-policy"];
    if (!cspText) {
      out.push(item("csp", "headers", "warn", "Keine Content-Security-Policy", "Ohne CSP richtet eingeschleuster Code (XSS) mehr Schaden an.", "Eine CSP setzen, z. B. erst als Content-Security-Policy-Report-Only testen. Start: default-src 'self'", 10));
    } else {
      const csp = parseCsp(cspText.split("\n")[0]);
      const script = csp["script-src"] || csp["default-src"] || [];
      const issues = [];
      const hasNonce = script.some((v) => /^'(nonce|sha256|sha384|sha512)-/.test(v)) || script.includes("'strict-dynamic'");
      if (script.includes("'unsafe-inline'") && !hasNonce) issues.push("'unsafe-inline' erlaubt eingeschleuste Skripte");
      if (script.includes("'unsafe-eval'")) issues.push("'unsafe-eval' erlaubt eval()");
      if (script.some((v) => v === "*" || v === "https:" || v === "http:" || v === "data:")) issues.push("Skripte von überall erlaubt (*, https: oder data:)");
      if (!csp["script-src"] && !csp["default-src"]) issues.push("weder script-src noch default-src gesetzt");
      if (!csp["object-src"] && !(csp["default-src"] || []).includes("'none'")) issues.push("object-src fehlt (besser 'none')");
      out.push(issues.length
        ? item("csp", "headers", "warn", "Content-Security-Policy mit Lücken", issues.join("\n"), "Inline-Skripte über Nonces/Hashes erlauben statt 'unsafe-inline'; Quellen genau angeben.", 10)
        : item("csp", "headers", "ok", "Content-Security-Policy gesetzt", cspText.slice(0, 300), "", 10));
    }
    // Clickjacking
    const cspAll = parseCsp(cspText || "");
    const xfo = h["x-frame-options"];
    if (cspAll["frame-ancestors"] || /deny|sameorigin/i.test(xfo || "")) out.push(item("frame", "headers", "ok", "Schutz vor Clickjacking", cspAll["frame-ancestors"] ? "frame-ancestors " + cspAll["frame-ancestors"].join(" ") : "X-Frame-Options: " + xfo, "", 6));
    else out.push(item("frame", "headers", "warn", "Kein Schutz vor Clickjacking", "Die Seite kann unsichtbar in fremde Seiten eingebettet werden.", "X-Frame-Options: SAMEORIGIN oder CSP frame-ancestors 'self' setzen.", 6));
    // nosniff
    if (/nosniff/i.test(h["x-content-type-options"] || "")) out.push(item("nosniff", "headers", "ok", "X-Content-Type-Options: nosniff", "", "", 4));
    else out.push(item("nosniff", "headers", "warn", "X-Content-Type-Options fehlt", "Browser könnten Dateien als anderen Typ (z. B. Skript) deuten.", "Header setzen: X-Content-Type-Options: nosniff", 4));
    // Referrer
    const ref = h["referrer-policy"];
    if (ref && !/unsafe-url|no-referrer-when-downgrade/i.test(ref)) out.push(item("referrer", "headers", "ok", "Referrer-Policy: " + ref, "", "", 2));
    else out.push(item("referrer", "headers", "warn", ref ? "Referrer-Policy gibt zu viel preis: " + ref : "Referrer-Policy fehlt", "Beim Klick auf fremde Links kann die volle Adresse übermittelt werden.", "Referrer-Policy: strict-origin-when-cross-origin setzen.", 2));
    // Permissions-Policy, COOP
    out.push(h["permissions-policy"]
      ? item("permissions", "headers", "ok", "Permissions-Policy gesetzt", h["permissions-policy"].slice(0, 200), "", 1)
      : item("permissions", "headers", "info", "Keine Permissions-Policy", "Optional: legt fest, welche Funktionen (Kamera, Mikrofon, Standort) die Seite nutzen darf.", "Z. B. Permissions-Policy: camera=(), microphone=(), geolocation=()"));
    if (h["cross-origin-opener-policy"]) out.push(item("coop", "headers", "ok", "Cross-Origin-Opener-Policy: " + h["cross-origin-opener-policy"], "", "", 1));
    // Informationen über den Server
    const leaks = [];
    if (/\d/.test(h.server || "")) leaks.push("Server: " + h.server);
    if (h["x-powered-by"]) leaks.push("X-Powered-By: " + h["x-powered-by"]);
    if (h["x-aspnet-version"]) leaks.push("X-AspNet-Version: " + h["x-aspnet-version"]);
    if (h["x-aspnetmvc-version"]) leaks.push("X-AspNetMvc-Version: " + h["x-aspnetmvc-version"]);
    if (leaks.length) out.push(item("leak", "headers", "warn", "Server verrät Software und Version", leaks.join("\n"), "Versionsangaben in den Headern abschalten (z. B. nginx: server_tokens off; PHP: expose_php = Off).", 3));
    else out.push(item("leak", "headers", "ok", "Keine Versionsangaben in den Headern", "", "", 3));
    // CORS
    const acao = h["access-control-allow-origin"];
    if (acao === "*" && /true/i.test(h["access-control-allow-credentials"] || "")) out.push(item("cors", "headers", "bad", "CORS erlaubt jede Seite mit Anmeldedaten", "Access-Control-Allow-Origin: * zusammen mit Allow-Credentials: true", "Nur bestimmte Ursprünge erlauben.", 10));
    else if (acao === "*") out.push(item("cors", "headers", "info", "CORS: Access-Control-Allow-Origin: *", "Jede Seite darf diese Antwort lesen – für öffentliche Inhalte in Ordnung."));
    return out;
  }

  /* ======================= Cookies ======================= */
  const SESSION_NAME = /sess|sid$|^sid|token|auth|login|jwt|remember|csrf|xsrf/i;
  function checkCookies(d) {
    const cookies = d.cookies || [];
    const https = /^https:/i.test(d.url);
    if (!cookies.length) return [item("cookies", "cookies", "ok", "Keine Cookies gesetzt", "", "", 0)];
    const out = [];
    const noSecure = https ? cookies.filter((c) => !c.secure) : [];
    const noHttp = cookies.filter((c) => !c.httpOnly && SESSION_NAME.test(c.name));
    const noneInsecure = cookies.filter((c) => c.sameSite === "no_restriction" && !c.secure);
    const list = (a) => a.slice(0, 10).map((c) => c.name).join(", ");
    out.push(item("cookie-count", "cookies", "info", `${cookies.length} Cookie${cookies.length > 1 ? "s" : ""}`,
      cookies.slice(0, 30).map((c) => `${c.name} · ${[c.secure && "Secure", c.httpOnly && "HttpOnly", "SameSite=" + (c.sameSite || "?"), c.session ? "Sitzung" : "dauerhaft"].filter(Boolean).join(", ")}`).join("\n")));
    if (noSecure.length) out.push(item("cookie-secure", "cookies", noSecure.some((c) => SESSION_NAME.test(c.name)) ? "bad" : "warn", `${noSecure.length} Cookie${noSecure.length > 1 ? "s" : ""} ohne Secure`, list(noSecure), "Cookies mit dem Attribut Secure setzen, damit sie nie über HTTP gehen.", noSecure.some((c) => SESSION_NAME.test(c.name)) ? 8 : 4));
    else if (https) out.push(item("cookie-secure", "cookies", "ok", "Alle Cookies mit Secure", "", "", 4));
    if (noHttp.length) out.push(item("cookie-httponly", "cookies", "warn", `Anmelde-Cookies ohne HttpOnly: ${list(noHttp)}`, "JavaScript (und damit eingeschleuster Code) kann sie auslesen.", "Sitzungs-Cookies mit HttpOnly setzen.", 6));
    else out.push(item("cookie-httponly", "cookies", "ok", "Anmelde-Cookies mit HttpOnly", "", "", 4));
    if (noneInsecure.length) out.push(item("cookie-samesite", "cookies", "bad", "SameSite=None ohne Secure", list(noneInsecure), "SameSite=None nur zusammen mit Secure verwenden.", 4));
    return out;
  }

  /* ======================= Inhalte & Skripte ======================= */
  /**
   * Dienste, die personenbezogene Daten (mind. die IP) bekommen. kind: tracking | ads | social | embed | fonts | cdn | consent | captcha
   * country: Sitz des Anbieters (für Hinweise zu Übermittlungen in Drittländer)
   */
  const SERVICES = [
    ["google-analytics.com", "Google Analytics", "tracking", "USA"], ["analytics.google.com", "Google Analytics", "tracking", "USA"],
    ["googletagmanager.com", "Google Tag Manager", "tracking", "USA"], ["doubleclick.net", "Google Ads/DoubleClick", "ads", "USA"],
    ["googlesyndication.com", "Google AdSense", "ads", "USA"], ["googleadservices.com", "Google Ads", "ads", "USA"],
    ["facebook.net", "Meta Pixel", "tracking", "USA"], ["facebook.com/tr", "Meta Pixel", "tracking", "USA"], ["facebook.com/plugins", "Facebook-Einbettung", "social", "USA"],
    ["instagram.com/embed", "Instagram-Einbettung", "social", "USA"], ["platform.twitter.com", "X/Twitter-Einbettung", "social", "USA"], ["x.com/i/", "X/Twitter", "social", "USA"],
    ["hotjar.com", "Hotjar", "tracking", "EU (Malta)"], ["clarity.ms", "Microsoft Clarity", "tracking", "USA"], ["bat.bing.com", "Microsoft Ads", "ads", "USA"],
    ["analytics.tiktok.com", "TikTok Pixel", "tracking", "China/USA"], ["snap.licdn.com", "LinkedIn Insight", "tracking", "USA"], ["px.ads.linkedin.com", "LinkedIn Insight", "tracking", "USA"],
    ["segment.com", "Segment", "tracking", "USA"], ["mixpanel.com", "Mixpanel", "tracking", "USA"], ["amplitude.com", "Amplitude", "tracking", "USA"],
    ["criteo", "Criteo", "ads", "Frankreich"], ["taboola", "Taboola", "ads", "USA"], ["outbrain", "Outbrain", "ads", "USA"], ["pinterest.com/ct", "Pinterest Tag", "tracking", "USA"],
    ["matomo.cloud", "Matomo Cloud", "tracking", "EU"], ["plausible.io", "Plausible", "tracking", "EU"],
    ["youtube.com/embed", "YouTube-Einbettung", "embed", "USA"], ["youtube.com/iframe_api", "YouTube", "embed", "USA"], ["ytimg.com", "YouTube", "embed", "USA"],
    ["google.com/maps", "Google Maps", "embed", "USA"], ["maps.googleapis.com", "Google Maps", "embed", "USA"], ["maps.gstatic.com", "Google Maps", "embed", "USA"],
    ["player.vimeo.com", "Vimeo", "embed", "USA"], ["open.spotify.com/embed", "Spotify-Einbettung", "embed", "Schweden"], ["soundcloud.com/player", "SoundCloud", "embed", "Deutschland"],
    ["fonts.googleapis.com", "Google Fonts", "fonts", "USA"], ["fonts.gstatic.com", "Google Fonts", "fonts", "USA"], ["use.typekit.net", "Adobe Fonts", "fonts", "USA"],
    ["use.fontawesome.com", "Font Awesome CDN", "fonts", "USA"], ["kit.fontawesome.com", "Font Awesome CDN", "fonts", "USA"],
    ["ajax.googleapis.com", "Google CDN", "cdn", "USA"], ["cdn.jsdelivr.net", "jsDelivr", "cdn", "USA"], ["cdnjs.cloudflare.com", "cdnjs (Cloudflare)", "cdn", "USA"],
    ["unpkg.com", "unpkg", "cdn", "USA"], ["code.jquery.com", "jQuery CDN", "cdn", "USA"], ["stackpath.bootstrapcdn.com", "Bootstrap CDN", "cdn", "USA"],
    ["google.com/recaptcha", "Google reCAPTCHA", "captcha", "USA"], ["gstatic.com/recaptcha", "Google reCAPTCHA", "captcha", "USA"], ["hcaptcha.com", "hCaptcha", "captcha", "USA"],
    ["challenges.cloudflare.com", "Cloudflare Turnstile", "captcha", "USA"],
    ["cookiebot.com", "Cookiebot", "consent", "Dänemark"], ["usercentrics.eu", "Usercentrics", "consent", "Deutschland"], ["app.usercentrics.eu", "Usercentrics", "consent", "Deutschland"],
    ["cookielaw.org", "OneTrust", "consent", "USA"], ["onetrust.com", "OneTrust", "consent", "USA"], ["consentmanager.net", "consentmanager", "consent", "Deutschland"],
    ["cookie-script.com", "Cookie-Script", "consent", "Litauen"], ["cdn-cookieyes.com", "CookieYes", "consent", "UK"], ["iubenda.com", "iubenda", "consent", "Italien"],
    ["didomi.io", "Didomi", "consent", "Frankreich"], ["klaro", "Klaro", "consent", "Deutschland"], ["termly.io", "Termly", "consent", "USA"], ["sdk.privacy-center.org", "Didomi", "consent", "Frankreich"],
  ];
  /** Einwilligungs-Werkzeuge, die ohne Fremdserver laufen (im Code der Seite erkennbar) */
  const LOCAL_CMP = [[/borlabs-cookie/i, "Borlabs Cookie"], [/complianz|cmplz/i, "Complianz"], [/real-cookie-banner/i, "Real Cookie Banner"], [/cookie-law-info|cookieyes/i, "CookieYes"], [/klaro/i, "Klaro"]];
  const CONSENT_COOKIE = /^(CookieConsent|OptanonConsent|OptanonAlertBoxClosed|euconsent-v2|cookieyes-consent|borlabs-cookie|cmplz_|real_cookie_banner|uc_|usercentrics|didomi_token|cookie_consent|cookieconsent_status|_iub_cs|klaro|CONSENT)/i;
  const TRACKING_COOKIE = /^(_ga|_gid|_gat|_gcl_|_fbp|_fbc|_hj|_clck|_clsk|_uetsid|_uetvid|_ttp|_pin_unauth|IDE$|test_cookie|_tt_enable_cookie|li_sugr|bcookie)/;

  function serviceOf(url) {
    const u = String(url).toLowerCase();
    for (const [needle, name, kind, country] of SERVICES) if (u.includes(needle)) return { name, kind, country };
    return null;
  }

  /** Erkannte Bibliotheken mit Lücken aus der Datenbank (retire.js) */
  function libFindings(p) {
    const libs = Retire && RETIRE_DB ? Retire.merge(p.libs || []) : [];
    return libs.map((l) => {
      const vulns = Retire.vulnerabilities(RETIRE_DB, l.name, l.version);
      const eol = Retire.eol(l.name, l.version);
      const rank = { critical: 3, high: 2, medium: 1, low: 0 };
      const worst = vulns.reduce((a, v) => Math.max(a, rank[v.severity] ?? 1), -1);
      return { ...l, display: Retire.nice(l.name), vulns, eol, worst };
    });
  }

  function checkContent(d) {
    const p = d.page || {};
    const https = /^https:/i.test(d.url);
    const out = [];
    // Bibliotheken (Lückendatenbank retire.js)
    const libs = libFindings(p);
    let libProblems = 0;
    for (const l of libs) {
      if (l.vulns.length) {
        libProblems++;
        const sev = l.worst >= 2 ? "bad" : l.worst === 1 ? "warn" : "info";
        const cves = [...new Set(l.vulns.flatMap((v) => v.cve || []))];
        const fixAt = l.vulns.reduce((a, v) => (!a || Retire.cmp(v.below, a) > 0 ? v.below : a), null);
        out.push(item("lib-" + l.name, "content", sev, `${l.display} ${l.version}: ${l.vulns.length} bekannte Lücke${l.vulns.length > 1 ? "n" : ""}${cves.length ? " (" + cves.slice(0, 3).join(", ") + (cves.length > 3 ? " …" : "") + ")" : ""}`,
          [...l.vulns.slice(0, 6).map((v) => `${{ critical: "kritisch", high: "hoch", medium: "mittel", low: "niedrig" }[v.severity] || v.severity}: ${v.summary || (v.cve || []).join(", ") || "Lücke"} (behoben in ${v.below})`),
            l.src ? `Erkannt über ${l.via}: ${l.src}` : `Erkannt über ${l.via}`].join("\n"),
          `Auf ${l.display} ${fixAt} oder neuer aktualisieren.`, sev === "bad" ? 10 : sev === "warn" ? 5 : 1));
      }
      if (l.eol) {
        libProblems++;
        out.push(item("eol-" + l.name, "content", "warn", `${l.display} ${l.version}: ${l.eol.text}`, l.src ? "Geladen von " + l.src : "", l.eol.fix, 3));
      }
    }
    if (libs.length && !libProblems) out.push(item("libs", "content", "ok", "Keine bekannten Lücken in erkannten Bibliotheken", libs.map((l) => `${l.display} ${l.version}`).join(", "), "", 6));
    // Fremde Skripte ohne Integritätsprüfung
    const pageSite = siteOf(hostOf(d.url));
    const ext = (p.scripts || []).filter((s) => s.src && siteOf(hostOf(s.src)) !== pageSite);
    const noSri = ext.filter((s) => !s.integrity);
    if (ext.length) {
      out.push(item("sri", "content", noSri.length ? "warn" : "ok", noSri.length ? `${noSri.length} fremde Skripte ohne Integritätsprüfung (SRI)` : "Fremde Skripte mit Integritätsprüfung",
        noSri.slice(0, 10).map((s) => s.src).join("\n"), noSri.length ? "Für feste Dateien von CDNs integrity=\"sha384-…\" crossorigin=\"anonymous\" angeben – dann läuft manipulierter Code nicht." : "", noSri.length ? 3 : 2));
    }
    // Drittanbieter (Tracker → Bereich Datenschutz)
    const reqs = d.requests || [];
    const third = new Set(reqs.map((r) => siteOf(hostOf(r.url))).filter((s) => s && s !== pageSite));
    out.push(item("third", "content", "info", `${third.size} fremde Domains geladen`, [...third].slice(0, 25).join(", ")));
    // Kommentare mit heiklen Wörtern
    if (p.sensitiveComments?.length) out.push(item("comments", "content", "warn", "HTML-Kommentare mit heiklen Wörtern", p.sensitiveComments.slice(0, 5).join("\n"), "Kommentare mit Passwörtern, Schlüsseln oder internen Hinweisen vor dem Veröffentlichen entfernen.", 5));
    // security.txt
    const wk = d.wellKnown || {};
    if (wk.securityTxt === true) out.push(item("securitytxt", "content", "ok", "security.txt vorhanden", "Sicherheitsforscher wissen, wohin sie Lücken melden können.", "", 1));
    else if (wk.securityTxt === false) out.push(item("securitytxt", "content", "info", "Keine security.txt", "Optional: /.well-known/security.txt mit Kontakt für Sicherheitsmeldungen.", "Datei anlegen, z. B. mit securitytxt.org."));
    if (p.iframes?.length) out.push(item("iframes", "content", "info", `${p.iframes.length} eingebettete Frames`, p.iframes.slice(0, 10).join("\n")));
    return out;
  }

  /* ======================= Formulare ======================= */
  const CSRF_NAME = /csrf|xsrf|token|nonce|authenticity|_wpnonce|requestverification|form_key|__RequestVerificationToken|_token/i;
  function checkForms(d) {
    const p = d.page || {};
    const https = /^https:/i.test(d.url);
    const forms = p.forms || [];
    const out = [];
    if (!forms.length) return out;
    const pageSite = siteOf(hostOf(d.url));
    const httpForms = forms.filter((f) => /^http:/i.test(f.action));
    const pwOnHttp = !https && forms.some((f) => f.password);
    if (pwOnHttp) out.push(item("form-pw", "forms", "bad", "Passwortfeld auf unverschlüsselter Seite", "Passwörter werden im Klartext übertragen.", "Die Seite nur über HTTPS ausliefern.", 15));
    if (httpForms.length) out.push(item("form-http", "forms", "bad", `${httpForms.length} Formular${httpForms.length > 1 ? "e senden" : " sendet"} unverschlüsselt`, httpForms.map((f) => f.action).join("\n"), "Formular-Ziele (action) auf https:// ändern – auch wenn der Server danach umleitet, gehen die Daten vorher im Klartext raus.", 12));
    const pwGet = forms.filter((f) => f.password && f.method === "get");
    if (pwGet.length) out.push(item("form-get", "forms", "bad", "Login-Formular sendet per GET", "Das Passwort landet in der Adresse – und damit im Verlauf, in Server-Logs und im Referrer.", "method=\"post\" verwenden.", 12));
    const foreign = forms.filter((f) => { const s = siteOf(hostOf(f.action)); return s && s !== pageSite; });
    if (foreign.length) out.push(item("form-foreign", "forms", "warn", `${foreign.length} Formular${foreign.length > 1 ? "e senden" : " sendet"} an fremde Domains`, foreign.map((f) => f.action).join("\n"), "Prüfen, ob das gewollt ist (z. B. Newsletter-Dienst) und in der Datenschutzerklärung steht.", 3));
    const noToken = forms.filter((f) => f.method === "post" && !f.csrf && siteOf(hostOf(f.action)) === pageSite);
    if (noToken.length) out.push(item("form-csrf", "forms", "warn", `${noToken.length} POST-Formular${noToken.length > 1 ? "e" : ""} ohne erkennbares CSRF-Token`, noToken.slice(0, 6).map((f) => `${f.name || "Formular"} → ${f.action}`).join("\n"),
      "Ein verstecktes Token pro Sitzung mitsenden (die meisten Frameworks können das) oder Sitzungs-Cookies mit SameSite=Lax/Strict setzen.", 4));
    else if (forms.some((f) => f.method === "post")) out.push(item("form-csrf", "forms", "ok", "POST-Formulare mit CSRF-Token", "", "", 4));
    const acOff = forms.filter((f) => f.password && /off/i.test(f.pwAutocomplete || ""));
    if (acOff.length) out.push(item("form-ac", "forms", "info", "Passwortfeld mit autocomplete=\"off\"", "Hindert Passwort-Manager – Nutzer greifen dann eher zu schwachen Passwörtern.", "autocomplete=\"current-password\" bzw. \"new-password\" setzen."));
    if (p.loosePassword) out.push(item("form-loose", "forms", "info", "Passwortfeld außerhalb eines Formulars", "Wird meist per JavaScript gesendet – dann gelten die Formular-Prüfungen hier nicht."));
    if (forms.some((f) => f.upload)) out.push(item("form-upload", "forms", "info", "Datei-Upload vorhanden", "Server-seitig Dateityp, Größe und Inhalt prüfen und Uploads nicht ausführbar speichern."));
    if (!httpForms.length && !pwOnHttp && !pwGet.length) out.push(item("forms", "forms", "ok", `${forms.length} Formular${forms.length > 1 ? "e senden" : " sendet"} verschlüsselt`, "", "", 4));
    return out;
  }

  /* ======================= Datenschutz (DSGVO) ======================= */
  function checkPrivacy(d, net) {
    const p = d.page || {};
    const out = [];
    const rs = net.requests.length ? net.requests : (d.requests || []).map((r) => ({ ...r, start: 0 }));
    const found = new Map(); // Name → { kind, country, first (ms), count }
    for (const r of rs) {
      if (r.blocked) continue;
      const s = serviceOf(r.url);
      if (!s) continue;
      const x = found.get(s.name) || { ...s, first: r.start ?? 0, count: 0 };
      x.count++;
      x.first = Math.min(x.first, r.start ?? 0);
      found.set(s.name, x);
    }
    const svc = [...found.entries()].map(([name, x]) => ({ name, ...x }));
    const needsConsent = svc.filter((x) => ["tracking", "ads", "social", "embed"].includes(x.kind));
    // Einwilligung: erste Klick-/Tastatur-Aktion seit dem Laden (vom kleinen Inhalts-Skript gemeldet)
    const interaction = d.firstInteraction != null && d.navStart ? d.firstInteraction - d.navStart : null;
    const cookies = d.cookies || [];
    const consentCookie = cookies.find((c) => CONSENT_COOKIE.test(c.name));
    const trackingCookies = cookies.filter((c) => TRACKING_COOKIE.test(c.name)).map((c) => c.name);
    const cmp = [...new Set([...svc.filter((x) => x.kind === "consent").map((x) => x.name), ...LOCAL_CMP.filter(([re]) => (p.scripts || []).some((sc) => re.test(sc.src || "")) || re.test(p.cmpHint || "")).map(([, n]) => n)])];
    out.push(cmp.length ? item("cmp", "privacy", "ok", "Cookie-Banner erkannt: " + cmp.join(", "), "", "", 2)
      : needsConsent.length ? item("cmp", "privacy", "warn", "Kein Cookie-Banner erkannt", "Es werden aber Dienste geladen, die eine Einwilligung brauchen.", "Ein Einwilligungs-Werkzeug (z. B. Borlabs, Usercentrics, Klaro) einsetzen und Dienste erst nach Zustimmung laden.", 6)
      : item("cmp", "privacy", "info", "Kein Cookie-Banner erkannt", "Nicht nötig, solange nur technisch notwendige Cookies und keine Tracker verwendet werden."));
    const before = needsConsent.filter((x) => interaction == null || x.first < interaction);
    if (before.length) {
      const already = !!consentCookie;
      out.push(item("consent", "privacy", already ? "info" : "bad",
        already ? `${before.length} einwilligungspflichtige Dienste geladen – Einwilligung offenbar schon erteilt` : `${before.length} einwilligungspflichtige Dienste vor jeder Einwilligung geladen`,
        before.map((x) => `${x.name} (${{ tracking: "Tracking", ads: "Werbung", social: "Social Media", embed: "Einbettung" }[x.kind]}, ${x.country})`).join("\n") +
          (already ? `\nEinwilligungs-Cookie gefunden: ${consentCookie.name}. Für eine echte Prüfung die Seite in einem privaten Fenster öffnen und nichts anklicken.` : "\nGeladen, bevor du auf der Seite etwas angeklickt hast."),
        already ? "" : "Tracker, Werbung, Social-Media- und Video-Einbettungen erst nach Zustimmung laden (§ 25 TDDDG, Art. 6 DSGVO). Bei Videos/Karten: Zwei-Klick-Lösung.", already ? 0 : 12));
    } else if (needsConsent.length) out.push(item("consent", "privacy", "ok", "Einwilligungspflichtige Dienste erst nach Zustimmung geladen", needsConsent.map((x) => x.name).join(", "), "", 12));
    else out.push(item("consent", "privacy", "ok", "Keine Tracker, Werbung oder Einbettungen gefunden", "", "", 12));
    if (trackingCookies.length && !consentCookie) out.push(item("track-cookies", "privacy", "bad", "Tracking-Cookies ohne Einwilligung gesetzt", trackingCookies.join(", "), "Analyse- und Werbe-Cookies erst nach Zustimmung setzen.", 8));
    const fonts = svc.filter((x) => x.kind === "fonts");
    if (fonts.length) out.push(item("gfonts", "privacy", "warn", `Schriften von ${fonts.map((x) => x.name).join(", ")} geladen`, "Dabei geht die IP-Adresse jedes Besuchers an den Anbieter. Das LG München hat 2022 für Google Fonts Schadensersatz zugesprochen – danach gab es eine Abmahnwelle.",
      "Schriften herunterladen und vom eigenen Server ausliefern (z. B. mit google-webfonts-helper).", 8));
    else out.push(item("gfonts", "privacy", "ok", "Keine Schriften von fremden Servern", "", "", 8));
    const embeds = svc.filter((x) => x.kind === "embed" && (interaction == null || x.first < interaction));
    if (embeds.length) out.push(item("embeds", "privacy", "warn", `Einbettungen ohne Klick geladen: ${embeds.map((x) => x.name).join(", ")}`, "Videos und Karten laden Inhalte (und Cookies) der Anbieter schon beim Öffnen der Seite.",
      "Zwei-Klick-Lösung: erst ein Vorschaubild zeigen, nach Klick laden. Für YouTube youtube-nocookie.com verwenden.", 5));
    const cdn = svc.filter((x) => x.kind === "cdn" || x.kind === "captcha");
    if (cdn.length) out.push(item("cdn", "privacy", "info", `Externe Dienste: ${cdn.map((x) => x.name).join(", ")}`, "Auch CDNs und Captchas bekommen die IP-Adresse der Besucher – in der Datenschutzerklärung nennen oder selbst hosten."));
    const abroad = [...new Set(svc.filter((x) => !/EU|Deutschland|Dänemark|Frankreich|Italien|Litauen|Schweden|Malta|Österreich/.test(x.country)).map((x) => `${x.name} (${x.country})`))];
    if (abroad.length) out.push(item("abroad", "privacy", "info", `Datenübermittlung außerhalb der EU: ${abroad.length} Dienst${abroad.length > 1 ? "e" : ""}`, abroad.join("\n"), "In der Datenschutzerklärung nennen; für die USA auf das EU-US Data Privacy Framework des Anbieters verweisen."));
    // Impressum & Datenschutzerklärung – Pflicht für geschäftsmäßige Seiten in Deutschland/Österreich
    const host = hostOf(d.url);
    const german = /^de/i.test(p.lang || "") || /\.(de|at|ch)$/.test(host);
    if (german) {
      out.push(p.legal?.imprint ? item("imprint", "privacy", "ok", "Impressum verlinkt", p.legal.imprint, "", 6)
        : item("imprint", "privacy", "bad", "Kein Impressum-Link gefunden", "Geschäftsmäßige Seiten brauchen ein leicht erreichbares Impressum (§ 5 DDG).", "Link „Impressum“ auf jeder Seite einbauen, z. B. im Footer.", 6));
      out.push(p.legal?.privacy ? item("privacy-link", "privacy", "ok", "Datenschutzerklärung verlinkt", p.legal.privacy, "", 6)
        : item("privacy-link", "privacy", "bad", "Kein Link zur Datenschutzerklärung gefunden", "Pflicht, sobald personenbezogene Daten verarbeitet werden – schon Server-Logs zählen.", "Link „Datenschutz“ auf jeder Seite einbauen.", 6));
    }
    return out;
  }

  /* ======================= Leistung ======================= */
  function checkPerf(d) {
    const p = d.page || {};
    const t = p.timing || {};
    const out = [];
    if (t.ttfb != null) {
      const s = t.ttfb < 600 ? "ok" : t.ttfb < 1500 ? "warn" : "bad";
      out.push(item("ttfb", "perf", s, `Server-Antwortzeit ${fmtMs(t.ttfb)}`, "Zeit bis zum ersten Byte (TTFB).", s === "ok" ? "" : "Server-Caching, schnelleres Hosting oder ein CDN nutzen.", 10));
    }
    if (t.load != null) {
      const s = t.load < 2500 ? "ok" : t.load < 5000 ? "warn" : "bad";
      out.push(item("load", "perf", s, `Vollständig geladen nach ${fmtMs(t.load)}`, t.dcl != null ? `HTML fertig nach ${fmtMs(t.dcl)}` : "", s === "ok" ? "" : "Große Dateien verkleinern, Skripte mit defer laden, Bilder lazy laden.", 10));
    }
    if (t.lcp != null) {
      const s = t.lcp < 2500 ? "ok" : t.lcp < 4000 ? "warn" : "bad";
      out.push(item("lcp", "perf", s, `Größtes Element sichtbar nach ${fmtMs(t.lcp)} (LCP)`, "Google wertet unter 2,5 s als gut.", s === "ok" ? "" : "Hauptbild vorladen (preload), kleiner machen, Server schneller antworten lassen.", 10));
    }
    if (p.resources) {
      const r = p.resources;
      const s = r.bytes < 3 * 1048576 ? "ok" : r.bytes < 8 * 1048576 ? "warn" : "bad";
      out.push(item("weight", "perf", s, `Seitengewicht ${fmtBytes(r.bytes)} in ${r.count} Dateien`,
        (r.largest || []).map((x) => `${fmtBytes(x.bytes)} · ${x.name}`).join("\n"), s === "ok" ? "" : "Bilder als WebP/AVIF und in passender Größe ausliefern, unnötige Skripte entfernen.", 8));
      if (r.count > 120) out.push(item("requests", "perf", "warn", `Viele Anfragen (${r.count})`, "", "Dateien zusammenfassen, unnötige Einbindungen entfernen.", 4));
      if (r.protocol) out.push(item("protocol", "perf", /h2|h3/.test(r.protocol) ? "ok" : "warn", "Protokoll: " + ({ h2: "HTTP/2", h3: "HTTP/3", "http/1.1": "HTTP/1.1" }[r.protocol] || r.protocol), "", /h2|h3/.test(r.protocol) ? "" : "HTTP/2 auf dem Server aktivieren – lädt viele Dateien parallel.", 4));
    }
    const enc = d.headers["content-encoding"];
    out.push(enc ? item("compress", "perf", "ok", "Komprimiert (" + enc + ")", "", "", 5) : item("compress", "perf", "warn", "HTML nicht komprimiert", "", "gzip oder Brotli auf dem Server einschalten.", 5));
    const big = (p.images || []).filter((i) => i.natural > 0 && i.shown > 0 && i.natural > i.shown * 2.5 && i.natural > 400 * 400);
    if (big.length) out.push(item("img-size", "perf", "warn", `${big.length} Bilder viel größer als angezeigt`, big.slice(0, 6).map((i) => i.src).join("\n"), "Bilder in der angezeigten Größe ausliefern (srcset).", 4));
    const lazy = (p.images || []).filter((i) => !i.lazy && i.belowFold).length;
    if (lazy > 3) out.push(item("img-lazy", "perf", "info", `${lazy} Bilder außerhalb des Sichtbereichs ohne loading="lazy"`, "", "loading=\"lazy\" für Bilder weiter unten setzen."));
    return out;
  }

  /* ======================= Netzwerk ======================= */
  const TYPE_GROUP = {
    main_frame: "Dokument", sub_frame: "Dokument", script: "Skript", stylesheet: "CSS", image: "Bild", imageset: "Bild",
    font: "Schrift", xmlhttprequest: "XHR/Fetch", websocket: "WebSocket", media: "Medien", ping: "Ping", beacon: "Ping",
  };
  /** Vom Browser oder einem Addon blockiert (kein Fehler der Seite) bzw. vom Browser abgebrochen */
  const BLOCKED = /TRACKING|BLOCKED|CSP|MALWARE|PHISHING|UNWANTED|HARMFUL/i;
  const ABORTED = /NS_BINDING_ABORTED|NS_ERROR_ABORT|NS_BINDING_REDIRECTED|NS_BINDING_RETARGETED/i;
  const TEXT_TYPE = /text\/|javascript|json|xml|svg|ecmascript|wasm|font\/ttf|font\/otf|application\/x-font-ttf/i;

  /**
   * Netzwerk-Protokoll (webRequest) mit Resource Timing (Größen, Protokoll) zusammenführen →
   * { requests: [...], domains: [...], totals }. Zeiten relativ zum Start der Navigation.
   */
  function buildNetwork(d) {
    const pageSite = siteOf(hostOf(d.url));
    const timings = new Map();
    for (const t of d.page?.resTiming || []) {
      if (!timings.has(t.name)) timings.set(t.name, []);
      timings.get(t.name).push(t);
    }
    const t0 = d.navStart || Math.min(...(d.net || []).map((e) => e.start).filter(Boolean), Date.now());
    const requests = (d.net || []).map((e) => {
      const t = timings.get(e.url)?.shift() || null;
      const h = e.h || {};
      const len = parseInt(h["content-length"] || "", 10);
      const transfer = t?.transfer || (e.fromCache ? 0 : Number.isFinite(len) ? len : null);
      const host = hostOf(e.url);
      return {
        url: e.url,
        host,
        file: fileOf(e.url),
        type: e.type,
        group: TYPE_GROUP[e.type] || "Sonstiges",
        method: e.method || "GET",
        status: e.status,
        error: e.error || null,
        blocked: !!(e.error && BLOCKED.test(e.error)),
        aborted: !!(e.error && ABORTED.test(e.error) && !BLOCKED.test(e.error)),
        start: Math.max(0, Math.round(e.start - t0)),
        duration: e.end ? Math.round(e.end - e.start) : null,
        wait: e.headersAt ? Math.round(e.headersAt - e.start) : null,
        transfer,
        size: t?.decoded || (Number.isFinite(len) ? len : null),
        fromCache: !!e.fromCache || (!!t && t.transfer === 0 && t.decoded > 0), // fremde Dateien ohne Timing-Allow-Origin melden 0/0
        protocol: t?.protocol || null,
        encoding: h["content-encoding"] || null,
        contentType: (h["content-type"] || "").split(";")[0] || null,
        cache: h["cache-control"] || null,
        expires: h.expires || null,
        cdnCache: h["x-cache"] || h["cf-cache-status"] || null,
        redirects: e.redirects?.length || 0,
        third: siteOf(host) !== pageSite,
        ip: e.ip || null,
      };
    });
    const doms = new Map();
    for (const r of requests) {
      const x = doms.get(r.host) || { host: r.host, third: r.third, count: 0, bytes: 0, known: 0, errors: 0, protocol: new Set() };
      x.count++;
      x.bytes += r.transfer || 0;
      if (r.transfer != null) x.known++;
      if ((r.status >= 400 || r.error) && !r.aborted) x.errors++;
      if (r.protocol) x.protocol.add(r.protocol);
      doms.set(r.host, x);
    }
    // Größe unbekannt (fremde Server ohne Timing-Allow-Origin/Content-Length) → null statt 0
    const domains = [...doms.values()].map(({ known, ...x }) => ({ ...x, bytes: known ? x.bytes : null, protocol: [...x.protocol].join(", ") || null })).sort((a, b) => (b.bytes || 0) - (a.bytes || 0) || b.count - a.count);
    const done = requests.filter((r) => r.duration != null);
    const totals = {
      count: requests.length,
      transfer: requests.reduce((a, r) => a + (r.transfer || 0), 0),
      size: requests.reduce((a, r) => a + (r.size || 0), 0),
      cached: requests.filter((r) => r.fromCache).length,
      thirdBytes: requests.some((r) => r.third && r.transfer != null) ? requests.filter((r) => r.third).reduce((a, r) => a + (r.transfer || 0), 0) : null,
      thirdCount: requests.filter((r) => r.third).length,
      finished: done.length ? Math.max(...done.map((r) => r.start + r.duration)) : null,
      open: requests.filter((r) => r.duration == null).length,
    };
    return { requests, domains, totals };
  }

  function fileOf(u) {
    try {
      const x = new URL(u);
      const f = x.pathname.split("/").filter(Boolean).pop() || x.pathname || "/";
      return decodeURIComponent(f).slice(0, 80) + (x.search ? x.search.slice(0, 30) + (x.search.length > 30 ? "…" : "") : "");
    } catch {
      return String(u).slice(0, 80);
    }
  }

  const list = (rs, fmt, n = 8) => rs.slice(0, n).map(fmt).join("\n") + (rs.length > n ? `\n… und ${rs.length - n} weitere` : "");

  function checkNetwork(d, net) {
    const out = [];
    const rs = net.requests;
    if (!rs.length) return [item("net-none", "net", "info", "Keine Anfragen aufgezeichnet", "Seite neu laden, damit das Netzwerk mitgeschnitten wird.")];
    const t = net.totals;
    out.push(item("net-overview", "net", "info",
      `${t.count} Anfragen · ${fmtBytes(t.transfer)} übertragen · ${t.cached} aus dem Cache · ${net.domains.length} Domains`,
      `Entpackt: ${fmtBytes(t.size)}${t.finished != null ? `\nLetzte Anfrage fertig nach ${fmtMs(t.finished)}` : ""}${t.open ? `\nNoch offen: ${t.open} (z. B. WebSockets oder laufende Abrufe)` : ""}`));

    // Fehler
    const failed = rs.filter((r) => !r.aborted && !r.blocked && (r.status >= 400 || r.error));
    const critical = failed.filter((r) => ["Dokument", "Skript", "CSS"].includes(r.group) || r.type === "main_frame");
    if (failed.length) {
      out.push(item("net-errors", "net", critical.length ? "bad" : "warn", `${failed.length} fehlgeschlagene Anfrage${failed.length > 1 ? "n" : ""}`,
        list(failed, (r) => `${r.status || r.error} · ${r.group} · ${r.url}`), "Fehlende Dateien (404) nachliefern oder die Einbindung entfernen; Serverfehler (5xx) im Server-Log prüfen.", critical.length ? 10 : 6));
    } else out.push(item("net-errors", "net", "ok", "Keine fehlgeschlagenen Anfragen", "", "", 8));
    const blocked = rs.filter((r) => r.blocked);
    if (blocked.length) out.push(item("net-blocked", "net", "info", `${blocked.length} Anfragen vom Browser/Addons blockiert`, list(blocked, (r) => `${r.error} · ${r.url}`), "Meist Tracker, die der Schutz von Firefox oder ein Werbeblocker aufhält – kein Fehler der Seite."));

    // Langsam
    const slow = rs.filter((r) => r.duration > 1000 && !["WebSocket"].includes(r.group) && !r.blocked).sort((a, b) => b.duration - a.duration);
    if (slow.length) out.push(item("net-slow", "net", slow.some((r) => r.duration > 3000 && ["Dokument", "Skript", "CSS"].includes(r.group)) ? "bad" : "warn",
      `${slow.length} langsame Anfrage${slow.length > 1 ? "n" : ""} (über 1 s)`, list(slow, (r) => `${fmtMs(r.duration)} · ${r.group} · ${r.url}`), "Langsame Server-Antworten cachen, große Dateien verkleinern oder später nachladen.", 6));
    else out.push(item("net-slow", "net", "ok", "Keine Anfrage langsamer als 1 s", "", "", 6));

    // Große Dateien
    const LIMIT = { Skript: 500 * 1024, Bild: 500 * 1024, Schrift: 300 * 1024, CSS: 300 * 1024, Dokument: 500 * 1024 };
    const big = rs.filter((r) => LIMIT[r.group] && (r.size || r.transfer || 0) > LIMIT[r.group]).sort((a, b) => (b.size || b.transfer) - (a.size || a.transfer));
    if (big.length) out.push(item("net-big", "net", "warn", `${big.length} große Datei${big.length > 1 ? "en" : ""}`, list(big, (r) => `${fmtBytes(r.size || r.transfer)} · ${r.group} · ${r.url}`), "Skripte aufteilen und nur Nötiges laden, Bilder als WebP/AVIF, Schriften als WOFF2 mit Untermenge.", 5));
    else out.push(item("net-big", "net", "ok", "Keine übergroßen Dateien", "", "", 5));

    // Komprimierung
    const plain = rs.filter((r) => !r.fromCache && r.status === 200 && !r.encoding && (r.size || r.transfer || 0) > 2048 &&
      (TEXT_TYPE.test(r.contentType || "") || ["Skript", "CSS"].includes(r.group)) && !/woff2?|font\/woff/i.test(r.contentType || ""));
    if (plain.length) out.push(item("net-compress", "net", "warn", `${plain.length} Textdatei${plain.length > 1 ? "en" : ""} ohne Komprimierung`, list(plain, (r) => `${fmtBytes(r.size || r.transfer)} · ${r.url}`), "gzip oder Brotli für HTML, CSS, JS, JSON und SVG einschalten (spart meist 60–80 %).", 5));
    else out.push(item("net-compress", "net", "ok", "Textdateien werden komprimiert übertragen", "", "", 5));

    // Caching eigener statischer Dateien
    const statics = rs.filter((r) => !r.third && ["Skript", "CSS", "Bild", "Schrift"].includes(r.group) && r.status === 200 && !r.fromCache);
    const noCache = statics.filter((r) => {
      const cc = (r.cache || "").toLowerCase();
      if (/no-store|no-cache|max-age=0\b/.test(cc)) return true;
      return !/max-age=\d+|immutable/.test(cc) && !r.expires;
    });
    if (noCache.length) out.push(item("net-cache", "net", "warn", `${noCache.length} eigene Dateien ohne Browser-Cache`, list(noCache, (r) => `${r.cache || "kein Cache-Control"} · ${r.url}`), "Für Dateien mit Versionsnummer im Namen Cache-Control: public, max-age=31536000, immutable setzen, sonst z. B. max-age=86400.", 5));
    else if (statics.length) out.push(item("net-cache", "net", "ok", "Eigene Dateien sind cachebar", "", "", 5));

    // Doppelte Anfragen
    const seen = new Map();
    for (const r of rs) if (!r.fromCache && !r.aborted && r.method === "GET" && r.group !== "XHR/Fetch" && r.group !== "Ping") seen.set(r.url, (seen.get(r.url) || 0) + 1);
    const dup = [...seen].filter(([, n]) => n > 1);
    if (dup.length) out.push(item("net-dup", "net", "warn", `${dup.length} Datei${dup.length > 1 ? "en" : ""} mehrfach geladen`, list(dup, ([u, n]) => `${n}× ${u}`), "Doppelte Einbindungen entfernen (z. B. dieselbe Bibliothek zweimal).", 3));

    // Weiterleitungen bei Unterressourcen
    const redir = rs.filter((r) => r.redirects && r.type !== "main_frame");
    if (redir.length) out.push(item("net-redirects", "net", redir.length > 5 ? "warn" : "info", `${redir.length} Dateien über Weiterleitungen geladen`, list(redir, (r) => r.url), "Direkt auf die endgültige Adresse verlinken – jede Weiterleitung kostet einen Umweg.", redir.length > 5 ? 3 : 0));

    // Blockierende Skripte im <head>
    const blocking = d.page?.blockingScripts || [];
    if (blocking.length) out.push(item("net-blocking", "net", blocking.length > 2 ? "warn" : "info", `${blocking.length} Skript${blocking.length > 1 ? "e blockieren" : " blockiert"} den Seitenaufbau`, blocking.slice(0, 10).join("\n"), "Skripte im <head> mit defer oder async laden – dann baut sich die Seite auf, während sie laden.", blocking.length > 2 ? 4 : 0));
    else out.push(item("net-blocking", "net", "ok", "Keine blockierenden Skripte im <head>", "", "", 4));

    // HTTP/1.1 bei vielen Anfragen
    const h1 = net.domains.filter((x) => x.count >= 6 && /http\/1/.test(x.protocol || ""));
    if (h1.length) out.push(item("net-h1", "net", "warn", `${h1.length} Domain${h1.length > 1 ? "s" : ""} mit vielen Anfragen über HTTP/1.1`, h1.map((x) => `${x.host}: ${x.count} Anfragen`).join("\n"), "HTTP/2 oder HTTP/3 aktivieren – Dateien laden dann parallel über eine Verbindung.", 3));

    // Fremde Domains
    if (t.thirdCount) {
      const share = t.thirdBytes != null && t.transfer ? Math.round((t.thirdBytes / t.transfer) * 100) : null;
      out.push(item("net-third", "net", share > 60 ? "warn" : "info",
        share != null ? `${share} % der Daten von fremden Domains (${t.thirdCount} Anfragen)` : `${t.thirdCount} Anfragen an fremde Domains`,
        net.domains.filter((x) => x.third).slice(0, 10).map((x) => `${x.host}: ${x.count} Anfragen${x.bytes != null ? ", " + fmtBytes(x.bytes) : ""}`).join("\n") + (share == null ? "\nGröße unbekannt: die fremden Server teilen sie nicht mit." : ""),
        share > 60 ? "Fremde Einbindungen (Werbung, Widgets, Fonts) prüfen – sie bremsen und geben Besucherdaten weiter." : "", share > 60 ? 3 : 0));
    }
    return out;
  }

  /* ======================= SEO ======================= */
  function checkSeo(d) {
    const p = d.page || {};
    const out = [];
    const title = (p.title || "").trim();
    if (!title) out.push(item("title", "seo", "bad", "Kein Seitentitel", "", "<title> mit einem aussagekräftigen Titel (30–60 Zeichen) setzen.", 10));
    else if (title.length < 10 || title.length > 65) out.push(item("title", "seo", "warn", `Titel ${title.length < 10 ? "sehr kurz" : "zu lang"} (${title.length} Zeichen)`, title, "30–60 Zeichen sind ideal.", 6));
    else out.push(item("title", "seo", "ok", "Titel: " + title, "", "", 10));
    const desc = (p.description || "").trim();
    if (!desc) out.push(item("desc", "seo", "warn", "Keine Meta-Beschreibung", "Suchmaschinen zeigen dann einen beliebigen Textausschnitt.", "<meta name=\"description\" content=\"…\"> mit 70–160 Zeichen setzen.", 8));
    else if (desc.length < 50 || desc.length > 170) out.push(item("desc", "seo", "warn", `Meta-Beschreibung ${desc.length < 50 ? "kurz" : "lang"} (${desc.length} Zeichen)`, desc, "70–160 Zeichen sind ideal.", 4));
    else out.push(item("desc", "seo", "ok", "Meta-Beschreibung vorhanden", desc, "", 8));
    const h1 = p.h1 || [];
    if (!h1.length) out.push(item("h1", "seo", "warn", "Keine Hauptüberschrift (h1)", "", "Genau eine <h1> mit dem Thema der Seite.", 6));
    else if (h1.length > 1) out.push(item("h1", "seo", "warn", `${h1.length} Hauptüberschriften (h1)`, h1.slice(0, 5).join("\n"), "Nur eine <h1> pro Seite verwenden.", 3));
    else out.push(item("h1", "seo", "ok", "Hauptüberschrift: " + h1[0], "", "", 6));
    out.push(p.lang ? item("lang", "seo", "ok", "Sprache angegeben: " + p.lang, "", "", 3) : item("lang", "seo", "warn", "Keine Sprache angegeben", "", "<html lang=\"de\"> setzen.", 3));
    out.push(p.viewport ? item("viewport", "seo", "ok", "Für Handys optimiert (viewport)", "", "", 6) : item("viewport", "seo", "bad", "Kein viewport-Meta-Tag", "Auf Handys wird die Seite winzig angezeigt.", "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> setzen.", 6));
    if (p.canonical) out.push(item("canonical", "seo", "ok", "Canonical-Adresse gesetzt", p.canonical, "", 2));
    else out.push(item("canonical", "seo", "info", "Keine Canonical-Adresse", "", "<link rel=\"canonical\" href=\"…\"> verhindert doppelte Inhalte."));
    if (/noindex/i.test(p.robots || "") || /noindex/i.test(d.headers["x-robots-tag"] || "")) out.push(item("noindex", "seo", "warn", "Seite ist für Suchmaschinen gesperrt (noindex)", p.robots || d.headers["x-robots-tag"], "Entfernen, falls die Seite gefunden werden soll.", 8));
    const img = p.imagesTotal || 0;
    const noAlt = p.imagesNoAlt || 0;
    if (img) out.push(noAlt ? item("alt", "seo", noAlt / img > 0.3 ? "warn" : "info", `${noAlt} von ${img} Bildern ohne Alternativtext`, "", "alt=\"…\" beschreibt Bilder für Suchmaschinen und Screenreader.", 4) : item("alt", "seo", "ok", "Alle Bilder mit Alternativtext", "", "", 4));
    out.push(p.og ? item("og", "seo", "ok", "Vorschau für soziale Netzwerke (Open Graph)", "", "", 2) : item("og", "seo", "info", "Keine Open-Graph-Angaben", "Geteilte Links bekommen dann kein schönes Vorschaubild.", "og:title, og:description und og:image setzen."));
    if (p.structuredData) out.push(item("schema", "seo", "ok", "Strukturierte Daten (JSON-LD) vorhanden", p.structuredData.join(", "), "", 2));
    const wk = d.wellKnown || {};
    if (wk.robotsTxt === false) out.push(item("robots", "seo", "info", "Keine robots.txt", "", "Eine robots.txt mit Verweis auf die Sitemap anlegen."));
    else if (wk.robotsTxt === true) out.push(item("robots", "seo", "ok", "robots.txt vorhanden", "", "", 1));
    if (wk.sitemap === true) out.push(item("sitemap", "seo", "ok", "sitemap.xml vorhanden", "", "", 2));
    else if (wk.sitemap === false) out.push(item("sitemap", "seo", "info", "Keine sitemap.xml unter /sitemap.xml", "", "Sitemap anlegen und in der Search Console einreichen."));
    return out;
  }

  /* ======================= Technik ======================= */
  function detectTech(d) {
    const h = d.headers;
    const p = d.page || {};
    const tech = new Set();
    const add = (x) => x && tech.add(x);
    if (h.server) add(h.server.replace(/\/[\d.]+.*/, "").replace(/^(\w)/, (c) => c.toUpperCase()));
    if (h["x-powered-by"]) add(h["x-powered-by"]);
    if (h["cf-ray"]) add("Cloudflare");
    if (h["x-vercel-id"]) add("Vercel");
    if (h["x-nf-request-id"]) add("Netlify");
    if (h["x-amz-cf-id"]) add("Amazon CloudFront");
    if (h["x-served-by"] && /cache/i.test(h["x-served-by"])) add("Fastly");
    if (/github/i.test(h.server || "")) add("GitHub Pages");
    if (p.generator) add(p.generator);
    for (const l of libFindings(p)) add(`${l.display} ${l.version}`);
    for (const t of p.tech || []) add(t);
    // „WordPress“ weglassen, wenn es schon „WordPress 6.4.2“ gibt
    const list = [...tech];
    return list.filter((t) => !list.some((o) => o !== t && o.toLowerCase().startsWith(t.toLowerCase() + " ")));
  }

  /* ======================= Bewertung ======================= */
  function score(items, cats, warnCredit = 0.25) {
    let max = 0;
    let got = 0;
    for (const it of items) {
      if (!cats.includes(it.cat) || !it.weight) continue;
      max += it.weight;
      got += it.status === "ok" ? it.weight : it.status === "warn" ? it.weight * warnCredit : 0;
    }
    return max ? Math.round((got / max) * 100) : null;
  }

  function grade(points, items) {
    if (points == null) return "?";
    let g = points >= 97 ? "A+" : points >= 88 ? "A" : points >= 78 ? "B" : points >= 65 ? "C" : points >= 50 ? "D" : "F";
    // harte Grenzen: ohne HTTPS oder mit schweren Mängeln keine gute Note
    const bad = items.filter((i) => i.status === "bad" && SECURITY_CATS.includes(i.cat));
    if (items.some((i) => i.id === "https" && i.status === "bad")) g = "F";
    else if (bad.length && ["A+", "A", "B"].includes(g)) g = "C";
    return g;
  }

  /**
   * Bericht erstellen. d = { url, now, headers (Liste), security, chain, requests, page, cookies, wellKnown, httpRedirect }
   */
  function analyze(input) {
    const d = { ...input, headers: headerMap(input.headers) };
    const network = buildNetwork(d);
    const exposed = input.exposed == null ? [] : input.exposed.length ? input.exposed
      : [item("exposed-none", "exposed", "ok", `Keine offenen Dateien gefunden (${input.exposedChecked || 0} Pfade geprüft)`, "", "", 10)];
    const items = [...checkConnection(d), ...checkHeaders(d), ...checkCookies(d), ...checkContent(d), ...checkForms(d), ...exposed,
      ...checkPerf(d), ...checkNetwork(d, network), ...checkSeo(d), ...checkPrivacy(d, network)];
    const security = score(items, SECURITY_CATS);
    return {
      url: d.url,
      host: hostOf(d.url),
      at: d.now || Date.now(),
      grade: grade(security, items),
      scores: { security, perf: score(items, ["perf"], 0.5), net: score(items, ["net"], 0.5), seo: score(items, ["seo"], 0.5), privacy: score(items, ["privacy"], 0.25) }, // Sicherheit/Datenschutz strenger
      counts: {
        bad: items.filter((i) => i.status === "bad").length,
        warn: items.filter((i) => i.status === "warn").length,
        ok: items.filter((i) => i.status === "ok").length,
      },
      items,
      tech: detectTech(d),
      cats: CATS,
      network: { ...network, requests: network.requests.slice(0, 1500) },
      own: input.exposed != null,
      libs: libFindings(d.page || {}).map((l) => ({ name: l.display, version: l.version, via: l.via, vulns: l.vulns.length })),
      retireDate: NODE ? require("./retire-db").meta.date : globalThis.RETIRE_META?.date || null,
    };
  }

  /** Bericht als Markdown (zum Kopieren, z. B. als To-do-Liste für die eigene Seite) */
  function toMarkdown(r) {
    const icon = { ok: "✅", warn: "⚠️", bad: "❌", info: "ℹ️" };
    const lines = [`# n274 Secure Check: ${r.host}`, "", `${r.url}  `, `Geprüft: ${new Date(r.at).toLocaleString("de-DE")}`, "",
      `**Sicherheit: ${r.grade}** (${r.scores.security} Punkte) · Leistung: ${r.scores.perf ?? "–"} · Netzwerk: ${r.scores.net ?? "–"} · SEO: ${r.scores.seo ?? "–"} · Datenschutz: ${r.scores.privacy ?? "–"}`, ""];
    if (r.tech.length) lines.push("Technik: " + r.tech.join(", "), "");
    for (const [cat, name] of Object.entries(r.cats)) {
      const its = r.items.filter((i) => i.cat === cat);
      if (!its.length) continue;
      lines.push(`## ${name}`, "");
      for (const i of its) {
        lines.push(`- ${icon[i.status]} **${i.title}**`);
        if (i.detail) lines.push(...i.detail.split("\n").slice(0, 6).map((x) => `  - ${x}`));
        if (i.fix && i.status !== "ok") lines.push(`  - 👉 ${i.fix}`);
      }
      lines.push("");
    }
    return lines.join("\n");
  }

  const api = { analyze, toMarkdown, buildNetwork, headerMap, cmpVersion, siteOf, hostOf, parseCsp, serviceOf, CATS };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else globalThis.Checks = api;
})();
