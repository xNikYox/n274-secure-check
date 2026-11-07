// Bericht: alle Prüfpunkte nach Bereichen, mit Details und Tipps; kopieren als Markdown, speichern als JSON
const app = document.getElementById("app");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const color = (v) => (v == null ? "var(--muted)" : v >= 85 ? "var(--ok)" : v >= 60 ? "var(--warn)" : "var(--bad)");
const LABEL = { bad: "kritisch", warn: "Hinweis", ok: "in Ordnung", info: "Info" };
let report = null;
let filter = "all";
const net = { group: "Alle", problems: false, q: "", sort: "start", dir: 1 };
const fmtBytes = (b) => (b == null ? "–" : b >= 1048576 ? (b / 1048576).toFixed(1).replace(".", ",") + " MB" : b >= 1024 ? Math.round(b / 1024) + " KB" : b + " B");
const fmtMs = (ms) => (ms == null ? "offen" : ms >= 1000 ? (ms / 1000).toFixed(2).replace(".", ",") + " s" : ms + " ms");
const GROUPS = ["Alle", "Dokument", "Skript", "CSS", "Bild", "Schrift", "XHR/Fetch", "Medien", "WebSocket", "Sonstiges"];
const problem = (x) => (!x.aborted && (x.status >= 400 || x.error)) || x.duration > 1000 || (x.size || x.transfer || 0) > 500 * 1024;

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
    <div class="scores">${score("Sicherheit (Note " + esc(r.grade) + ")", r.scores.security)}${score("Leistung", r.scores.perf)}${score("Netzwerk", r.scores.net)}${score("SEO", r.scores.seo)}${score("Datenschutz", r.scores.privacy)}</div>
    ${r.tech.length ? `<div class="tech">${r.tech.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</div>` : ""}
    <div class="filter">
      ${[["all", "Alle"], ["issues", `Probleme (${r.counts.bad + r.counts.warn})`], ["bad", `Kritisch (${r.counts.bad})`], ["ok", `In Ordnung (${r.counts.ok})`]].map(([k, l]) => `<button data-f="${k}" class="${filter === k ? "on" : ""}">${l}</button>`).join("")}
    </div>
    ${sections || `<p class="muted">Nichts in dieser Auswahl.</p>`}
    ${r.network?.requests?.length ? `<section class="netview"><h2><span>Netzwerk-Analyse</span><span>${r.network.totals.count} Anfragen</span></h2><div id="netview"></div></section>` : ""}
    <p class="note">${r.own ? "Eigene Seite: zusätzlich auf offene Dateien geprüft. " : ""}Bibliotheks-Lücken: Datenbank von retire.js${r.retireDate ? " (Stand " + esc(new Date(r.retireDate).toLocaleDateString("de-DE")) + ")" : ""}. DSGVO-Hinweise sind keine Rechtsberatung.</p>
    <p class="note">n274 Secure Check schaut sich nur an, was die Seite ausliefert (passiv) und ersetzt keinen Penetrationstest: Lücken in der Server-Logik, Datenbank oder Anmeldung findet es nicht. </p>`;
  for (const b of app.querySelectorAll("[data-f]")) b.onclick = () => ((filter = b.dataset.f), render());
  if (r.network?.requests?.length) renderNet();
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

/* ---------------- Netzwerk-Analyse: Domains + Anfragen mit Wasserfall ---------------- */
function renderNet() {
  const box = document.getElementById("netview");
  const n = report.network;
  const t = n.totals;
  const total = Math.max(1, ...n.requests.map((x) => x.start + (x.duration || 0)));
  const known = n.requests.some((x) => x.transfer != null || x.size != null); // sonst sind Größen unbekannt, nicht 0
  const counts = Object.fromEntries(GROUPS.map((g) => [g, g === "Alle" ? n.requests.length : n.requests.filter((x) => x.group === g).length]));
  let rows = n.requests.filter((x) => (net.group === "Alle" || x.group === net.group) && (!net.problems || problem(x)) && (!net.q || x.url.toLowerCase().includes(net.q)));
  const key = { start: (x) => x.start, duration: (x) => x.duration ?? 1e12, size: (x) => x.size || x.transfer || 0, status: (x) => x.status || 999 }[net.sort];
  rows = rows.slice().sort((a, b) => (key(a) - key(b)) * net.dir);
  const status = (x) => {
    if (x.aborted) return `<span class="st st-ab" title="${esc(x.error)}">abgebr.</span>`;
    if (x.blocked) return `<span class="st st-bl" title="${esc(x.error)}">blockiert</span>`;
    if (x.error) return `<span class="st st-bad" title="${esc(x.error)}">Fehler</span>`;
    if (x.status == null) return `<span class="st">…</span>`;
    return `<span class="st ${x.status >= 400 ? "st-bad" : x.status >= 300 ? "st-warn" : ""}">${x.status}</span>`;
  };
  const sortHead = (k, label) => `<th data-sort="${k}" class="${net.sort === k ? "on" : ""}">${label}${net.sort === k ? (net.dir > 0 ? " ▲" : " ▼") : ""}</th>`;
  box.innerHTML = `
    <div class="netsum">
      <span class="chip">${t.count} Anfragen</span>${known ? `<span class="chip">${fmtBytes(t.transfer)} übertragen</span><span class="chip">${fmtBytes(t.size)} entpackt</span>` : `<span class="chip">Größen unbekannt</span>`}
      <span class="chip">${t.cached} aus dem Cache</span><span class="chip">${t.thirdCount} fremd${t.thirdBytes != null ? ` (${fmtBytes(t.thirdBytes)})` : ""}</span>${t.finished != null ? `<span class="chip">fertig nach ${fmtMs(t.finished)}</span>` : ""}
    </div>
    <table class="dom"><thead><tr><th>Domain</th><th>Anfragen</th><th>Übertragen</th><th>Protokoll</th><th>Fehler</th></tr></thead><tbody>
      ${n.domains.slice(0, 15).map((d) => `<tr><td>${esc(d.host)}${d.third ? ' <span class="tag">fremd</span>' : ""}</td><td>${d.count}</td><td>${d.bytes == null ? '<span class="muted" title="Der Server teilt die Größe nicht mit">?</span>' : fmtBytes(d.bytes)}</td><td>${esc(d.protocol || "–")}</td><td>${d.errors ? `<span class="st st-bad">${d.errors}</span>` : "–"}</td></tr>`).join("")}
    </tbody></table>
    ${n.domains.length > 15 ? `<p class="muted small">+ ${n.domains.length - 15} weitere Domains</p>` : ""}
    <div class="netctl">
      <div class="groups">${GROUPS.filter((g) => counts[g]).map((g) => `<button data-g="${esc(g)}" class="${net.group === g ? "on" : ""}">${esc(g)} <span>${counts[g]}</span></button>`).join("")}</div>
      <label class="prob"><input type="checkbox" id="netProb" ${net.problems ? "checked" : ""}> nur Auffällige</label>
      <input type="search" id="netQ" placeholder="Adresse filtern …" value="${esc(net.q)}">
    </div>
    <div class="tablewrap"><table class="req"><thead><tr>${sortHead("status", "Status")}<th>Typ</th><th>Datei</th>${sortHead("size", "Größe")}${sortHead("duration", "Zeit")}${sortHead("start", "Zeitleiste")}</tr></thead><tbody>
      ${rows.map((x) => {
        const left = (x.start / total) * 100;
        const width = Math.max(0.4, ((x.duration ?? total - x.start) / total) * 100);
        const wait = x.wait != null && x.duration ? Math.min(100, (x.wait / x.duration) * 100) : 0;
        return `<tr class="${problem(x) ? "prob-row" : ""}">
          <td>${status(x)}</td>
          <td><span class="g g-${esc(x.group.replace(/\W/g, ""))}">${esc(x.group)}</span></td>
          <td class="f" title="${esc(x.method + " " + x.url)}"><b>${esc(x.file)}</b><small>${esc(x.host)}${x.redirects ? " · ↪ " + x.redirects : ""}${x.fromCache ? " · Cache" : ""}${x.encoding ? " · " + esc(x.encoding) : ""}${x.protocol ? " · " + esc(x.protocol) : ""}</small></td>
          <td class="num" title="${x.size ? "entpackt " + fmtBytes(x.size) : ""}">${x.fromCache ? "Cache" : x.transfer == null ? '<span class="muted" title="Der Server teilt die Größe nicht mit">?</span>' : fmtBytes(x.transfer)}</td>
          <td class="num">${fmtMs(x.duration)}</td>
          <td class="wf"><div class="wfbar g-${esc(x.group.replace(/\W/g, ""))}" style="left:${left.toFixed(2)}%;width:${Math.min(100 - left, width).toFixed(2)}%" title="Start ${fmtMs(x.start)} · Warten ${fmtMs(x.wait)} · gesamt ${fmtMs(x.duration)}"><i style="width:${wait.toFixed(1)}%"></i></div></td>
        </tr>`;
      }).join("") || `<tr><td colspan="6" class="muted">Keine Anfragen in dieser Auswahl.</td></tr>`}
    </tbody></table></div>
    <p class="muted small">Zeitleiste ab Beginn der Navigation (0 bis ${fmtMs(total)}); heller Teil = Warten auf den Server. Größen fremder Dateien sind nur bekannt, wenn der Server sie mitteilt.</p>`;
  for (const b of box.querySelectorAll("[data-g]")) b.onclick = () => ((net.group = b.dataset.g), renderNet());
  for (const th of box.querySelectorAll("[data-sort]")) th.onclick = () => {
    net.dir = net.sort === th.dataset.sort ? -net.dir : th.dataset.sort === "start" ? 1 : -1;
    net.sort = th.dataset.sort;
    renderNet();
  };
  box.querySelector("#netProb").onchange = (e) => ((net.problems = e.target.checked), renderNet());
  const q = box.querySelector("#netQ");
  q.oninput = () => {
    net.q = q.value.trim().toLowerCase();
    clearTimeout(renderNet.t);
    renderNet.t = setTimeout(() => {
      renderNet();
      const nq = document.getElementById("netQ");
      nq.focus();
      nq.setSelectionRange(nq.value.length, nq.value.length);
    }, 200);
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
