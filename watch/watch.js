// Überwachung: Liste der eigenen Seiten mit letztem Stand, Änderungen und Problemen
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const when = (t) => (t ? new Date(t).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }) : "noch nie");
const busy = new Set();

const line = (x) => `<div class="line"><i class="dot s-${esc(x.status)}"></i><span>${esc(x.text)}</span></div>`;

async function render() {
  const list = await browser.runtime.sendMessage({ type: "watch:list" });
  const box = $("#list");
  if (!list.length) {
    box.innerHTML = `<div class="empty">Noch keine Seiten. Trag oben deine erste Seite ein – oder klick im Popup auf „Überwachen“.</div>`;
    return;
  }
  box.innerHTML = list.map((s) => {
    const l = s.last;
    const host = new URL(s.url).host;
    const facts = l ? [
      l.error ? "nicht erreichbar" : `HTTP ${l.status}`,
      l.certDays != null ? `Zertifikat noch ${l.certDays} Tage` : null,
      l.tls, l.httpsRedirect === "https" ? "HTTP → HTTPS" : null,
      `${l.broken.length} kaputte Links`, `${l.exposed.length} offene Dateien`,
    ].filter(Boolean) : [];
    const hist = (s.history || []).slice(-30);
    return `<section class="site">
      <div class="site-head">
        <div class="grade g-${esc(l?.grade || "?")}">${esc(l?.grade || "?")}</div>
        <div class="who"><b>${esc(host)}</b><span class="muted">${esc(s.url)} · zuletzt geprüft ${esc(when(l?.at))}</span></div>
        <div class="tools">
          <button class="btn" data-check="${esc(s.id)}" ${busy.has(s.id) ? "disabled" : ""}>${busy.has(s.id) ? "Prüfe …" : "Jetzt prüfen"}</button>
          <button class="btn" data-open="${esc(s.url)}">Öffnen</button>
          <button class="btn" data-remove="${esc(s.id)}" title="Aus der Überwachung entfernen">✕</button>
        </div>
      </div>
      ${l ? `<div class="facts">${facts.map((f) => `<span class="chip">${esc(f)}</span>`).join("")}</div>
      <div class="cols">
        <div><h3>Probleme</h3>${l.problems.length ? l.problems.map((p) => line(p)).join("") : `<div class="line"><i class="dot s-ok"></i><span>Alles in Ordnung</span></div>`}</div>
        <div><h3>Änderungen ${s.changedAt ? "seit " + esc(when(s.changedAt)) : ""}</h3>${(s.changes || []).length ? s.changes.map((c) => line(c)).join("") : `<div class="line muted">Keine Änderungen seit der letzten Prüfung</div>`}</div>
      </div>
      ${l.broken.length ? `<details class="more"><summary>Kaputte Links (${l.broken.length})</summary>${l.broken.map((b) => `<div class="line"><i class="dot s-warn"></i><span>${esc(b)}</span></div>`).join("")}</details>` : ""}
      ${hist.length > 1 ? `<div class="history" title="Probleme je Prüfung (letzte ${hist.length})">${hist.map((h) => `<i style="height:${4 + Math.min(22, h.problems * 3)}px;background:${h.problems ? (h.problems > 4 ? "var(--bad)" : "var(--warn)") : "var(--ok)"}" title="${esc(when(h.at))}: ${h.problems} Probleme, Note ${esc(h.grade || "?")}"></i>`).join("")}</div>` : ""}`
      : `<p class="muted">Erste Prüfung läuft …</p>`}
    </section>`;
  }).join("");
  for (const b of box.querySelectorAll("[data-check]")) b.onclick = async () => {
    busy.add(b.dataset.check);
    render();
    await browser.runtime.sendMessage({ type: "watch:check", id: b.dataset.check });
    busy.delete(b.dataset.check);
    render();
  };
  for (const b of box.querySelectorAll("[data-open]")) b.onclick = () => browser.tabs.create({ url: b.dataset.open });
  for (const b of box.querySelectorAll("[data-remove]")) b.onclick = async () => {
    if (!confirm("Seite aus der Überwachung entfernen?")) return;
    await browser.runtime.sendMessage({ type: "watch:remove", id: b.dataset.remove });
    render();
  };
}

$("#add").onsubmit = async (e) => {
  e.preventDefault();
  const r = await browser.runtime.sendMessage({ type: "watch:add", url: $("#url").value.trim() });
  if (r.error) return alert(r.error);
  $("#url").value = "";
  $("#own").checked = false;
  render();
};

const prefill = new URLSearchParams(location.search).get("add");
if (prefill) $("#url").value = prefill;
browser.storage.onChanged.addListener((c) => c.watch && render());
render();
