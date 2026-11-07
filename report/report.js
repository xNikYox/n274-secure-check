// Bericht: alle Prüfpunkte nach Bereichen, mit Details und Tipps; kopieren als Markdown, speichern als JSON
const app = document.getElementById("app");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const color = (v) => (v == null ? "var(--muted)" : v >= 85 ? "var(--ok)" : v >= 60 ? "var(--warn)" : "var(--bad)");
const LABEL = { bad: "kritisch", warn: "Hinweis", ok: "in Ordnung", info: "Info" };
let report = null;
let filter = "all";

function score(label, v) {
  return `<div class="score"><small>${label}</small><b style="color:${color(v)}">${v ?? "–"}</b><div class="bar"><i style="width:${v ?? 0}%;background:${color(v)}"></i></div></div>`;
}

function render() {
  const r = report;
  const show = (i) => filter === "all" || (filter === "issues" ? i.status === "bad" || i.status === "warn" : i.status === filter);
  const order = { bad: 0, warn: 1, info: 2, ok: 3 };
  const sections = Object.entries(r.cats).map(([cat, name]) => {
    const items = r.items.filter((i) => i.cat === cat && show(i)).sort((a, b) => order[a.status] - order[b.status]);
    if (!items.length) return "";
    const bad = r.items.filter((i) => i.cat === cat && (i.status === "bad" || i.status === "warn")).length;
    return `<section><h2><span>${esc(name)}</span><span>${bad ? bad + " offen" : "✓"}</span></h2>${items.map((i) => {
      const has = i.detail || (i.fix && i.status !== "ok");
      return `<details class="item${has ? "" : " nodetail"}"${has && i.status === "bad" ? " open" : ""}>
        <summary><i class="dot s-${i.status}" title="${LABEL[i.status]}"></i><b>${esc(i.title)}</b><span class="arrow">›</span></summary>
        ${has ? `<div class="body">${i.detail ? `<pre>${esc(i.detail)}</pre>` : ""}${i.fix && i.status !== "ok" ? `<div class="fix">👉 ${esc(i.fix)}</div>` : ""}</div>` : ""}
      </details>`;
    }).join("")}</section>`;
  }).join("");
  app.innerHTML = `
    <div class="top">
      <div class="grade g-${esc(r.grade)}">${esc(r.grade)}</div>
      <div class="who"><h1>${esc(r.host)}</h1><div class="meta">${esc(r.url)}</div><div class="meta">Geprüft ${esc(new Date(r.at).toLocaleString("de-DE"))}${r.ip ? " · Server-IP " + esc(r.ip) : ""}${r.status ? " · HTTP " + esc(r.status) : ""}</div></div>
      <div class="tools"><button class="btn" id="copy">Als Markdown kopieren</button><button class="btn" id="json">JSON speichern</button></div>
    </div>
    <div class="scores">${score("Sicherheit (Note " + esc(r.grade) + ")", r.scores.security)}${score("Leistung", r.scores.perf)}${score("SEO", r.scores.seo)}</div>
    ${r.tech.length ? `<div class="tech">${r.tech.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</div>` : ""}
    <div class="filter">
      ${[["all", "Alle"], ["issues", `Probleme (${r.counts.bad + r.counts.warn})`], ["bad", `Kritisch (${r.counts.bad})`], ["ok", `In Ordnung (${r.counts.ok})`]].map(([k, l]) => `<button data-f="${k}" class="${filter === k ? "on" : ""}">${l}</button>`).join("")}
    </div>
    ${sections || `<p class="muted">Nichts in dieser Auswahl.</p>`}
    <p class="note">n274 Secure Check schaut sich nur an, was die Seite ausliefert (passiv) und ersetzt keinen Penetrationstest: Lücken in der Server-Logik, Datenbank oder Anmeldung findet es nicht. Bibliotheks-Lücken stammen aus einer Liste im Addon.</p>`;
  for (const b of app.querySelectorAll("[data-f]")) b.onclick = () => ((filter = b.dataset.f), render());
  document.getElementById("copy").onclick = async (e) => {
    await navigator.clipboard.writeText(Checks.toMarkdown(r));
    e.target.textContent = "Kopiert ✓";
  };
  document.getElementById("json").onclick = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" }));
    a.download = `n274-secure-check-${r.host}-${new Date(r.at).toISOString().slice(0, 10)}.json`;
    a.click();
  };
}

(async () => {
  const tabId = Number(new URLSearchParams(location.search).get("tab"));
  const res = window.__report ? { report: window.__report } : await browser.runtime.sendMessage({ type: "report", tabId });
  if (!res?.report) {
    app.innerHTML = `<p class="muted">Kein Bericht vorhanden – im Popup erneut prüfen.</p>`;
    return;
  }
  report = res.report;
  document.title = `n274 Secure Check – ${report.host} (${report.grade})`;
  render();
})();
