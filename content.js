// n274 Secure Check – liest die geöffnete Seite aus (nur lesen, nichts ändern). Wird bei Bedarf eingefügt;
// das Ergebnis (Promise) geht an das Hintergrundskript.
(async () => {
  const w = window.wrappedJSObject || window; // Firefox: Zugriff auf die Variablen der Seite (für Bibliotheks-Versionen)
  const safe = (fn, fallback = null) => {
    try {
      const v = fn();
      return v == null ? fallback : v;
    } catch {
      return fallback;
    }
  };
  const str = (v) => (typeof v === "string" ? v : v == null ? null : String(v));
  const meta = (sel) => safe(() => document.querySelector(sel)?.getAttribute("content")?.trim() || null);
  const abs = (u) => safe(() => new URL(u, location.href).href, u);

  /* ---- Bibliotheken (Variablen der Seite, sonst Dateiname) ---- */
  const libs = [];
  const addLib = (name, version, src = null) => {
    version = str(version);
    if (version && /^\d+(\.\d+)*/.test(version) && !libs.some((l) => l.name === name)) libs.push({ name, version: version.match(/^\d+(\.\d+)*/)[0], src });
  };
  addLib("jQuery", safe(() => w.jQuery.fn.jquery));
  addLib("jQuery UI", safe(() => w.jQuery.ui.version));
  addLib("Bootstrap", safe(() => w.bootstrap.Tooltip.VERSION) || safe(() => w.jQuery.fn.tooltip.Constructor.VERSION));
  if (safe(() => typeof w._.flatMapDeep === "function")) addLib("Lodash", safe(() => w._.VERSION));
  addLib("Moment.js", safe(() => w.moment.version));
  addLib("AngularJS", safe(() => w.angular.version.full));
  addLib("Vue", safe(() => w.Vue.version));
  addLib("React", safe(() => w.React.version));
  const scripts = [...document.scripts].map((s) => ({ src: s.src ? abs(s.src) : null, integrity: s.getAttribute("integrity") || null, inline: !s.src }));
  const FILES = [
    [/jquery[.-]ui[.-]?v?(\d+\.\d+\.\d+)|jqueryui\/(\d+\.\d+\.\d+)/i, "jQuery UI"],
    [/jquery[@/.-]v?(\d+\.\d+\.\d+)/i, "jQuery"],
    [/bootstrap[@/.-]v?(\d+\.\d+\.\d+)/i, "Bootstrap"],
    [/lodash[@/.-]v?(\d+\.\d+\.\d+)/i, "Lodash"],
    [/moment[@/.-]v?(\d+\.\d+\.\d+)/i, "Moment.js"],
    [/angular[.-]?js[@/.-]v?(1\.\d+\.\d+)|angular[@/.-]v?(1\.\d+\.\d+)/i, "AngularJS"],
    [/vue[@/.-]v?(\d+\.\d+\.\d+)/i, "Vue"],
  ];
  for (const s of scripts) {
    if (!s.src) continue;
    for (const [re, name] of FILES) {
      const m = re.exec(s.src);
      if (m) addLib(name, m[1] || m[2], s.src);
    }
  }

  /* ---- Technik ---- */
  const tech = [];
  const html = document.documentElement;
  const has = (sel) => safe(() => !!document.querySelector(sel), false);
  const anySrc = (re) => scripts.some((s) => s.src && re.test(s.src)) || [...document.querySelectorAll("link[href]")].some((l) => re.test(l.href));
  if (anySrc(/\/wp-content\/|\/wp-includes\//)) tech.push("WordPress");
  if (safe(() => w.Shopify)) tech.push("Shopify");
  if (has("#__NEXT_DATA__") || safe(() => w.next)) tech.push("Next.js");
  if (safe(() => w.__NUXT__) || has("#__nuxt")) tech.push("Nuxt");
  if (has("[data-reactroot]") || safe(() => w.React)) tech.push("React");
  if (has("[data-v-app]") || safe(() => w.Vue) || safe(() => w.__VUE__)) tech.push("Vue");
  const ngv = safe(() => document.querySelector("[ng-version]")?.getAttribute("ng-version"));
  if (ngv) tech.push("Angular " + ngv);
  if (has("astro-island") || has("[data-astro-cid]")) tech.push("Astro");
  if (has("[class*='svelte-']")) tech.push("Svelte");
  if (anySrc(/static\.wixstatic\.com|parastorage\.com/)) tech.push("Wix");
  if (anySrc(/squarespace/)) tech.push("Squarespace");
  if (anySrc(/fonts\.googleapis\.com/)) tech.push("Google Fonts");
  if (anySrc(/fontawesome|font-awesome/)) tech.push("Font Awesome");
  if (anySrc(/cdn\.tailwindcss\.com/)) tech.push("Tailwind CSS");

  /* ---- Formulare, Frames ---- */
  const forms = [...document.forms].slice(0, 50).map((f) => ({ action: abs(f.getAttribute("action") || location.href), method: (f.method || "get").toLowerCase(), password: !!f.querySelector("input[type=password]") }));
  // Passwortfelder außerhalb von <form> zählen auch
  if (document.querySelector("input[type=password]") && !forms.some((f) => f.password)) forms.push({ action: location.href, method: "post", password: true });
  const iframes = [...document.querySelectorAll("iframe[src]")].slice(0, 30).map((f) => abs(f.getAttribute("src")));

  /* ---- Kommentare mit heiklen Wörtern ---- */
  const sensitiveComments = [];
  safe(() => {
    const it = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    let n;
    let seen = 0;
    while ((n = it.nextNode()) && seen++ < 2000) {
      const t = n.nodeValue.trim();
      if (/passw|kennwort|api[_ -]?key|secret|private[_ -]?key|access[_ -]?token|credential|zugangsdaten/i.test(t)) sensitiveComments.push(t.replace(/\s+/g, " ").slice(0, 140));
      if (sensitiveComments.length >= 10) break;
    }
  });

  /* ---- Bilder ---- */
  const vh = innerHeight;
  const images = [...document.images].slice(0, 300).map((img) => {
    const r = img.getBoundingClientRect();
    return {
      src: img.currentSrc || img.src,
      natural: img.naturalWidth * img.naturalHeight,
      shown: Math.round(r.width * r.height * (devicePixelRatio || 1) ** 2),
      lazy: img.loading === "lazy",
      belowFold: r.top + scrollY > vh * 1.5,
      alt: img.hasAttribute("alt"),
    };
  });

  /* ---- Ladezeiten und Dateien ---- */
  const nav = safe(() => performance.getEntriesByType("navigation")[0]);
  const timing = nav
    ? {
        ttfb: nav.responseStart > 0 ? nav.responseStart : null,
        dcl: nav.domContentLoadedEventEnd > 0 ? nav.domContentLoadedEventEnd : null,
        load: nav.loadEventEnd > 0 ? nav.loadEventEnd : null,
        lcp: null,
      }
    : {};
  // LCP nur über einen Beobachter mit gepufferten Einträgen erreichbar
  timing.lcp = await new Promise((resolve) => {
    let last = null;
    try {
      const po = new PerformanceObserver((list) => {
        const e = list.getEntries();
        if (e.length) last = e[e.length - 1].startTime;
      });
      po.observe({ type: "largest-contentful-paint", buffered: true });
      setTimeout(() => {
        po.disconnect();
        resolve(last);
      }, 150);
    } catch {
      resolve(null);
    }
  });
  const res = safe(() => performance.getEntriesByType("resource"), []);
  const sized = res.map((e) => ({ name: e.name, bytes: e.transferSize || e.encodedBodySize || 0 }));
  const navBytes = nav ? nav.transferSize || nav.encodedBodySize || 0 : 0;
  const resources = {
    count: res.length + 1,
    bytes: sized.reduce((a, b) => a + b.bytes, navBytes),
    largest: sized.sort((a, b) => b.bytes - a.bytes).slice(0, 5).map((x) => ({ name: x.name.length > 110 ? x.name.slice(0, 107) + "…" : x.name, bytes: x.bytes })),
    protocol: nav?.nextHopProtocol || null,
  };

  /* ---- Netzwerk: Resource Timing (Größen, Protokoll) und blockierende Einbindungen im <head> ---- */
  const resTiming = res.slice(0, 2000).map((e) => ({
    name: e.name,
    initiator: e.initiatorType,
    start: Math.round(e.startTime),
    duration: Math.round(e.duration),
    transfer: e.transferSize || 0,
    encoded: e.encodedBodySize || 0,
    decoded: e.decodedBodySize || 0,
    protocol: e.nextHopProtocol || null,
    blocking: e.renderBlockingStatus || null,
  }));
  const blockingScripts = [...document.head.querySelectorAll("script[src]")]
    .filter((s) => !s.async && !s.defer && s.type !== "module")
    .map((s) => abs(s.getAttribute("src")))
    .slice(0, 30);
  const headStyles = document.head.querySelectorAll('link[rel~="stylesheet"]').length;

  /* ---- SEO ---- */
  const structuredData = [];
  for (const s of document.querySelectorAll('script[type="application/ld+json"]')) {
    safe(() => {
      const j = JSON.parse(s.textContent);
      for (const x of [].concat(j["@graph"] || j)) if (x?.["@type"]) structuredData.push([].concat(x["@type"]).join("/"));
    });
  }

  return {
    url: location.href,
    title: document.title,
    description: meta('meta[name="description" i]'),
    robots: meta('meta[name="robots" i]'),
    viewport: !!document.querySelector('meta[name="viewport" i]'),
    canonical: safe(() => document.querySelector('link[rel="canonical"]')?.href || null),
    lang: html.getAttribute("lang") || null,
    generator: meta('meta[name="generator" i]'),
    og: !!document.querySelector('meta[property="og:title"], meta[property="og:image"]'),
    h1: [...document.querySelectorAll("h1")].slice(0, 10).map((h) => h.textContent.replace(/\s+/g, " ").trim().slice(0, 120)),
    imagesTotal: images.length,
    imagesNoAlt: images.filter((i) => !i.alt).length,
    structuredData: structuredData.length ? [...new Set(structuredData)].slice(0, 10) : null,
    forms,
    iframes,
    scripts: scripts.filter((s) => s.src).slice(0, 200),
    inlineScripts: scripts.filter((s) => s.inline).length,
    libs,
    tech,
    sensitiveComments,
    images: images.map(({ alt, ...i }) => i),
    timing,
    resources,
    resTiming,
    blockingScripts,
    headStyles,
    timeOrigin: safe(() => performance.timeOrigin, null),
  };
})();
