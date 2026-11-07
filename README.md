# n274 Secure Check (Firefox-Addon)

Prüft die Website im aktuellen Tab – passiv und komplett lokal:

- **Sicherheit (Note A+–F):** HTTPS, TLS-Version, Zertifikat, HTTP→HTTPS, Mixed Content, Sicherheits-Header (HSTS, CSP, Clickjacking, nosniff, Referrer, Permissions), Versions-Lecks, CORS, Cookies (Secure/HttpOnly/SameSite), Formulare, veraltete Bibliotheken mit bekannten Lücken, fremde Skripte ohne SRI, Tracker, heikle HTML-Kommentare, security.txt
- **Leistung:** TTFB, Ladezeit, LCP, Seitengewicht, Anfragen, HTTP/2/3, Komprimierung, zu große Bilder
- **SEO:** Titel, Beschreibung, h1, Sprache, viewport, canonical, noindex, Alt-Texte, Open Graph, JSON-LD, robots.txt, sitemap.xml
- **Technik:** Server, CDN, CMS, Frameworks, Bibliotheken

Bericht als Markdown kopieren oder als JSON speichern. Keine Daten verlassen den Browser; abgerufen werden nur `security.txt`, `robots.txt`, `sitemap.xml` und die HTTP-Version der geprüften Seite.

Entwicklung: `npm test` · `npm run lint` · `npm run build`
