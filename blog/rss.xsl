<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="UTF-8" />
  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title><xsl:value-of select="/rss/channel/title" /></title>
        <link rel="icon" type="image/png" href="/assets/favicon-512.png" />
                <style>
          :root { color-scheme: dark; }
          body {
            margin: 0;
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            color: #e5f0f7;
            background:
              radial-gradient(circle at 12% 0%, rgba(216, 27, 96, 0.22), transparent 32rem),
              linear-gradient(180deg, #081018 0%, #05070a 58%, #030507 100%);
          }
          main { width: min(920px, calc(100% - 32px)); margin: 0 auto; padding: 64px 0; }
          .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 32px; }
          .brand img { width: 44px; height: 44px; border-radius: 14px; }
          .eyebrow { color: #fb7185; font-size: 0.78rem; letter-spacing: 0.16em; text-transform: uppercase; }
          h1 { margin: 0 0 12px; font-size: clamp(2.2rem, 6vw, 4.8rem); line-height: 0.95; }
          p { color: #93a6b8; line-height: 1.7; }
          a { color: inherit; }
          .actions { display: flex; flex-wrap: wrap; gap: 12px; margin: 28px 0 36px; }
          .button {
            border: 1px solid rgba(229, 240, 247, 0.16);
            border-radius: 999px;
            padding: 10px 14px;
            text-decoration: none;
            background: rgba(255, 255, 255, 0.04);
          }
          article {
            margin: 18px 0;
            padding: 22px;
            border: 1px solid rgba(145, 170, 190, 0.18);
            border-radius: 24px;
            background: rgba(10, 16, 23, 0.82);
          }
          article h2 { margin: 0 0 10px; }
          time { color: #c9d8e3; font-size: 0.9rem; }
        </style>
      </head>
      <body>
        <main>
          <div class="brand">
            <img src="/assets/favicon-512.png" alt="SecOpsAI icon" />
            <span class="eyebrow">RSS Feed</span>
          </div>
          <h1><xsl:value-of select="/rss/channel/title" /></h1>
          <p><xsl:value-of select="/rss/channel/description" /></p>
          <div class="actions">
            <a class="button" href="/">Open the blog</a>
            <a class="button" href="/feed.json">JSON feed</a>
          </div>
          <xsl:for-each select="/rss/channel/item">
            <article>
              <h2><a href="{link}"><xsl:value-of select="title" /></a></h2>
              <time><xsl:value-of select="pubDate" /></time>
              <p><xsl:value-of select="description" /></p>
            </article>
          </xsl:for-each>
        </main>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
