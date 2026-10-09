module.exports = {
  darkMode: "class",
  content: ["./www/index.html", "./www/assets/site.js"],
  theme: {
    extend: {
      colors: {
        near: "#05070a",
        ink: "#dbe7f2",
        muted: "#8ea0b5",
        panel: "#0c1117",
        "panel-strong": "#101722",
        line: "rgba(148, 163, 184, 0.18)",
        accent: "#2dd4a8",
        "accent-soft": "#6ee7c8",
        "accent-dim": "rgba(45, 212, 168, 0.12)",
        "accent-border": "rgba(45, 212, 168, 0.2)",
        amber: "#f59e0b",
      },
      fontFamily: {
        display: ['"Space Grotesk"', "sans-serif"],
        body: ["Inter", "sans-serif"],
        mono: ['"JetBrains Mono"', "monospace"],
      },
      boxShadow: {
        card: "0 28px 80px rgba(0, 0, 0, 0.35)",
        glow: "0 0 0 1px rgba(45, 212, 168, 0.08), 0 32px 90px rgba(0, 0, 0, 0.42)",
      },
    },
  },
};
