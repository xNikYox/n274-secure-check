// n274 Secure Check – merkt sich nur den Zeitpunkt des ersten Klicks/Tastendrucks auf der Seite (für den DSGVO-Check:
// wurden Tracker schon VOR jeder Einwilligung geladen?). Liest keine Inhalte, meldet nur die Uhrzeit.
(() => {
  const types = ["pointerdown", "keydown", "touchstart"];
  const once = () => {
    for (const t of types) removeEventListener(t, once, true);
    try {
      browser.runtime.sendMessage({ type: "interaction", at: Date.now() });
    } catch {
      // Addon gerade neu geladen
    }
  };
  for (const t of types) addEventListener(t, once, { capture: true, passive: true });
})();
