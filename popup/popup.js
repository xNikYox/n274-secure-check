// Popup: aktuelle Seite prüfen, Note + wichtigste Probleme zeigen
const app = document.getElementById("app");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const color = (v) => (v == null ? "var(--muted)" : v >= 85 ? "var(--ok)" : v >= 60 ? "var(--warn)" : "var(--bad)");
let tabId = null;

function state(html) {
  app.innerHTML = `<div class="state">${html}</div>`;
}

function scoreBox(label, v) {
  return `<div class="score"><small>${label}</small><b style="color:${color(v)}">${v ?? "–"}</b><div class="bar"><i style="width:${v ?? 0}%;background:${color(v)}"></i></div></div>`;
}

function render(r) {
  const order = { bad: 0, warn: 1 };
  const issues = r.items.filter((i) => i.status === "bad" || i.status === "warn").sort((a, b) => order[a.status] - order[b.status] || b.weight - a.weight);
  app.innerHTML = `
    <div class="head">
      <div class="grade g-${esc(r.grade)}">${esc(r.grade)}</div>
      <div class="who"><b>${esc(r.host)}</b><small>${esc(r.title || r.url)}</small><small>Sicherheitsnote</small></div>
    </div>
    <div class="scores">${scoreBox("Sicherheit", r.scores.security)}${scoreBox("Leistung", r.scores.perf)}${scoreBox("Netzwerk", r.scores.net)}${scoreBox("SEO", r.scores.seo)}${scoreBox("DSGVO", r.scores.privacy)}</div>
    <div class="counts"><span><i class="dot s-bad"></i>${r.counts.bad} kritisch</span><span><i class="dot s-warn"></i>${r.counts.warn} Hinweise</span><span><i class="dot s-ok"></i>${r.counts.ok} in Ordnung</span></div>
    <div class="issues">${issues.slice(0, 6).map((i) => `<div class="issue"><i class="dot s-${i.status}"></i><div><b>${esc(i.title)}</b>${i.fix ? `<small>${esc(i.fix)}</small>` : ""}</div></div>`).join("") || `<div class="good">Keine Probleme gefunden 🎉</div>`}</div>
    ${issues.length > 6 ? `<div class="foot">+ ${issues.length - 6} weitere im Bericht</div>` : ""}
    <div class="actions">
      <button class="btn primary" id="full">Vollständiger Bericht</button>
      <button class="btn" id="copy" title="Als Markdown-Liste kopieren">Kopieren</button>
      <button class="btn" id="again" title="Seite neu laden und erneut prüfen">↻</button>
    </div>
    <div class="watchrow">${r.own ? `<span class="ownchip">✓ Eigene Seite · überwacht</span>` : ""}<button class="link" id="watch">${r.own ? "Überwachung öffnen" : "Diese Seite überwachen …"}</button></div>
    <div class="foot">Alles lokal geprüft – keine Daten verlassen deinen Browser.</div>`;
  document.getElementById("watch").onclick = () => {
    const page = "watch/watch.html" + (r.own ? "" : "?add=" + encodeURIComponent(new URL(r.url).origin + "/"));
    browser.tabs.create({ url: browser.runtime.getURL(page) });
    window.close();
  };
  document.getElementById("full").onclick = () => {
    browser.tabs.create({ url: browser.runtime.getURL(`report/report.html?tab=${tabId}`) });
    window.close();
  };
  document.getElementById("copy").onclick = async (e) => {
    await navigator.clipboard.writeText(Checks.toMarkdown(r));
    e.target.textContent = "Kopiert ✓";
  };
  document.getElementById("again").onclick = reloadAndCheck;
}

async function check() {
  state(`<div class="spin"></div><span>Prüfe Seite …</span>`);
  const res = await browser.runtime.sendMessage({ type: "analyze", tabId });
  if (res?.report) return render(res.report);
  if (res?.needsReload) {
    state(`<span>Die Seite wurde geladen, bevor n274 Secure Check lief. Für Header und Zertifikat einmal neu laden.</span><button class="btn primary" id="reload">Neu laden &amp; prüfen</button>`);
    document.getElementById("reload").onclick = reloadAndCheck;
    return;
  }
  state(`<span>${esc(res?.error || "Prüfen nicht möglich.")}</span>`);
}

async function reloadAndCheck() {
  state(`<div class="spin"></div><span>Lade neu …</span>`);
  await browser.runtime.sendMessage({ type: "reload", tabId });
  // warten, bis die Seite fertig geladen ist
  await new Promise((resolve) => {
    const done = (id, info) => {
      if (id === tabId && info.status === "complete") {
        browser.tabs.onUpdated.removeListener(done);
        resolve();
      }
    };
    browser.tabs.onUpdated.addListener(done);
    setTimeout(resolve, 20000);
  });
  await new Promise((r) => setTimeout(r, 800)); // späte Inhalte (LCP) abwarten
  check();
}

(async () => {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  tabId = tab.id;
  check();
})();
