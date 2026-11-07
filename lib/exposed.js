// n274 Secure Check – offene Dateien auf EIGENEN Seiten finden (nur für Seiten in der Überwachung, also mit Bestätigung).
// Gefragt wird nach Dateien, die nie öffentlich sein sollten. Gezählt wird nur, was am Inhalt eindeutig erkennbar ist –
// viele Server antworten auf alles mit 200 und der Startseite.
(function () {
  "use strict";

  const notHtml = (r) => !/<html|<!doctype/i.test(r.text.slice(0, 500));
  const PROBES = [
    { path: "/.git/HEAD", status: "bad", weight: 20, title: "Git-Ordner öffentlich (/.git)", test: (r) => /^ref: refs\//m.test(r.text),
      fix: "Zugriff auf /.git im Webserver sperren oder den Ordner vom Server löschen – sonst lässt sich der komplette Quellcode samt Verlauf und evtl. Passwörtern herunterladen." },
    { path: "/.git/config", status: "bad", weight: 0, title: "Git-Konfiguration öffentlich (/.git/config)", test: (r) => /\[core\]/.test(r.text) && notHtml(r), fix: "Zugriff auf /.git sperren." },
    { path: "/.env", status: "bad", weight: 25, title: "Umgebungsdatei mit Zugangsdaten öffentlich (/.env)", test: (r) => /^[A-Z][A-Z0-9_]{2,}\s*=/m.test(r.text) && notHtml(r),
      fix: "Datei sofort sperren/entfernen und ALLE darin stehenden Passwörter und Schlüssel ändern." },
    { path: "/.env.local", status: "bad", weight: 0, title: "Umgebungsdatei öffentlich (/.env.local)", test: (r) => /^[A-Z][A-Z0-9_]{2,}\s*=/m.test(r.text) && notHtml(r), fix: "Sperren/entfernen, Zugangsdaten ändern." },
    { path: "/.env.production", status: "bad", weight: 0, title: "Umgebungsdatei öffentlich (/.env.production)", test: (r) => /^[A-Z][A-Z0-9_]{2,}\s*=/m.test(r.text) && notHtml(r), fix: "Sperren/entfernen, Zugangsdaten ändern." },
    ...["/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save", "/wp-config.old", "/wp-config.txt"].map((path) => ({
      path, status: "bad", weight: 0, title: `WordPress-Zugangsdaten als Kopie lesbar (${path})`, test: (r) => /DB_PASSWORD|DB_NAME|AUTH_KEY/.test(r.text),
      fix: "Sicherungskopie löschen und das Datenbank-Passwort ändern." })),
    { path: "/config.php.bak", status: "bad", weight: 0, title: "Konfiguration als Kopie lesbar (/config.php.bak)", test: (r) => /<\?php/.test(r.text) && /pass|db_|database/i.test(r.text), fix: "Kopie löschen, Zugangsdaten ändern." },
    ...["/backup.sql", "/dump.sql", "/database.sql", "/db.sql"].map((path) => ({
      path, status: "bad", weight: 0, title: `Datenbank-Sicherung öffentlich (${path})`, test: (r) => /CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump/i.test(r.text),
      fix: "Datei löschen – sie enthält meist alle Kundendaten und Passwort-Hashes." })),
    ...["/backup.zip", "/site.zip", "/www.zip", "/backup.tar.gz"].map((path) => ({
      path, status: "bad", weight: 0, title: `Sicherungsarchiv öffentlich (${path})`, test: (r) => r.text.startsWith("PK\u0003\u0004") || r.text.startsWith("\u001f\u008b"),
      fix: "Archiv vom Webserver entfernen." })),
    { path: "/.DS_Store", status: "warn", weight: 3, title: "macOS-Ordnerdatei öffentlich (/.DS_Store) – verrät Dateinamen", test: (r) => r.text.includes("Bud1"), fix: "Datei löschen und beim Hochladen ausschließen." },
    { path: "/.svn/wc.db", status: "bad", weight: 0, title: "SVN-Ordner öffentlich (/.svn)", test: (r) => r.text.startsWith("SQLite format 3"), fix: "Zugriff auf /.svn sperren." },
    { path: "/.hg/requires", status: "bad", weight: 0, title: "Mercurial-Ordner öffentlich (/.hg)", test: (r) => /revlogv1|store|fncache/.test(r.text) && notHtml(r), fix: "Zugriff auf /.hg sperren." },
    ...["/phpinfo.php", "/info.php", "/test.php"].map((path) => ({
      path, status: "warn", weight: 0, title: `PHP-Infoseite öffentlich (${path})`, test: (r) => /phpinfo\(\)|<title>PHP \d|PHP Version \d/.test(r.text),
      fix: "Datei löschen – sie verrät Versionen, Pfade und Einstellungen des Servers." })),
    { path: "/server-status", status: "warn", weight: 4, title: "Apache-Statusseite öffentlich (/server-status)", test: (r) => /Apache Server Status/i.test(r.text), fix: "mod_status nur für localhost erlauben." },
    { path: "/.htaccess", status: "warn", weight: 3, title: ".htaccess lesbar", test: (r) => /RewriteEngine|Deny from|Require all|AuthType/i.test(r.text) && notHtml(r), fix: "Zugriff auf .ht*-Dateien im Webserver sperren." },
    { path: "/docker-compose.yml", status: "warn", weight: 4, title: "docker-compose.yml öffentlich", test: (r) => /^services:|^version:\s*['"]?\d/m.test(r.text) && notHtml(r), fix: "Datei aus dem öffentlichen Ordner entfernen (enthält oft Passwörter)." },
    { path: "/.vscode/sftp.json", status: "bad", weight: 10, title: "Editor-Zugangsdaten öffentlich (/.vscode/sftp.json)", test: (r) => /"host"\s*:/.test(r.text) && notHtml(r), fix: "Ordner .vscode entfernen und das FTP/SFTP-Passwort ändern." },
    { path: "/wp-json/wp/v2/users", status: "warn", weight: 3, title: "WordPress verrät Benutzernamen (/wp-json/wp/v2/users)", test: (r) => /^\s*\[\s*\{.*"slug"\s*:/s.test(r.text),
      fix: "REST-Endpunkt users für nicht angemeldete Besucher sperren (z. B. per Sicherheits-Plugin) – sonst kennen Angreifer die Login-Namen." },
    { path: "/xmlrpc.php", status: "warn", weight: 2, title: "WordPress xmlrpc.php aktiv (beliebtes Ziel für Passwort-Raten)", test: (r) => /XML-RPC server accepts POST requests only/i.test(r.text), fix: "xmlrpc.php sperren, wenn keine App sie braucht." },
    ...["/wp-content/uploads/", "/uploads/", "/backup/", "/images/", "/files/"].map((path) => ({
      path, status: "warn", weight: 0, title: `Verzeichnisliste sichtbar (${path})`, test: (r) => /<title>Index of \//i.test(r.text) || /<h1>Index of \//i.test(r.text),
      fix: "Verzeichnislisten abschalten (Apache: Options -Indexes, nginx: autoindex off)." })),
  ];

  /**
   * Ergebnisse auswerten. results = [{ path, status, finalUrl, text }] (text = Anfang der Antwort als Latin-1).
   * Weiterleitungen auf andere Pfade (z. B. Login oder Startseite) zählen nicht.
   */
  function evaluate(results) {
    const found = [];
    for (const p of PROBES) {
      const r = results.find((x) => x.path === p.path);
      if (!r || r.status !== 200 || !r.text) continue;
      try {
        if (r.finalUrl && new URL(r.finalUrl).pathname !== p.path) continue;
      } catch {
        continue;
      }
      if (p.test(r)) found.push(p);
    }
    // Gewicht: das erste Kritische zählt voll, weitere gleichartige ohne Zusatzgewicht (weight 0 → 10)
    return found.map((p) => ({ id: "exp" + p.path.replace(/\W+/g, "-"), cat: "exposed", status: p.status, title: p.title, detail: p.path, fix: p.fix, weight: p.weight || (p.status === "bad" ? 10 : 2) }));
  }

  const api = { PROBES, evaluate, paths: () => PROBES.map((p) => p.path) };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else globalThis.Exposed = api;
})();
