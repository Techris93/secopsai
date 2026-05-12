const header = document.getElementById("site-header");
const menuToggle = document.getElementById("menu-toggle");
const mobileMenu = document.getElementById("mobile-menu");
const openIcon = document.getElementById("menu-open-icon");
const closeIcon = document.getElementById("menu-close-icon");
const mobileLinks = mobileMenu ? mobileMenu.querySelectorAll("a") : [];
const copyButton = document.getElementById("copy-quickstart");
const copyLabel = document.getElementById("copy-label");
const quickstartCode = document.getElementById("quickstart-code");
const quickstartTabs = document.querySelectorAll("[data-quickstart-profile]");
const quickstartEyebrow = document.getElementById("quickstart-eyebrow");
const quickstartTitle = document.getElementById("quickstart-title");
const quickstartDescription = document.getElementById("quickstart-description");
const quickstartSupport = document.getElementById("quickstart-support");
const quickstartSupportPill = document.getElementById("quickstart-support-pill");
const quickstartModePill = document.getElementById("quickstart-mode-pill");
const quickstartShellLabel = document.getElementById("quickstart-shell-label");
const quickstartTerminalLabel = document.getElementById("quickstart-terminal-label");
const quickstartProfiles = {
  oneliner: {
    eyebrow: "One-liner",
    title: "Recommended install for most operators",
    description: "Use the bootstrap script when you want the fastest local path from zero to SecOpsAI on a fresh machine.",
    support: "macOS is the smoothest path today. Windows teams can use the same installer from WSL2.",
    supportLabel: "macOS & Linux",
    supportTone: "production",
    modeLabel: "Quick Start",
    shellLabel: "bash",
    terminalLabel: "bootstrap installer",
    lines: [
      { type: "comment", text: "Quick Start" },
      { type: "command", text: "curl -fsSL https://secopsai.dev/install.sh | bash" },
      { type: "command", text: "cd ~/secopsai && source .venv/bin/activate" },
      { type: "command", text: "secopsai refresh" },
      { type: "command", text: "secopsai correlate" },
      { type: "command", text: "secopsai adaptive-response --persist-memory" },
    ],
  },
  npm: {
    eyebrow: "npm",
    title: "Package-manager path for JavaScript-heavy teams",
    description: "Keep the install familiar for Node users while still landing in the same SecOpsAI workflow once the CLI is available.",
    support: "Great when your workstation already centers around npm and you want a lighter-weight entry path.",
    supportLabel: "Hackable",
    supportTone: "production",
    modeLabel: "Node.js",
    shellLabel: "npm",
    terminalLabel: "global cli install",
    lines: [
      { type: "comment", text: "npm install" },
      { type: "command", text: "npm install -g secopsai" },
      { type: "command", text: "secopsai refresh" },
      { type: "command", text: "secopsai refresh --platform macos,openclaw" },
      { type: "command", text: "secopsai correlate" },
      { type: "command", text: "secopsai adaptive-response --persist-memory" },
    ],
  },
  hackable: {
    eyebrow: "Hackable",
    title: "Manual install you can inspect, tweak, and extend",
    description: "Clone the repo, create a local virtualenv, and install in editable mode when you want maximum transparency or a development-friendly setup.",
    support: "Best for teams that want to inspect installer behavior first or patch the local stack directly.",
    supportLabel: "macOS & Linux",
    supportTone: "production",
    modeLabel: "Manual",
    shellLabel: "bash",
    terminalLabel: "editable install",
    lines: [
      { type: "comment", text: "Manual install" },
      { type: "command", text: "git clone https://github.com/Techris93/secopsai.git" },
      { type: "command", text: "cd secopsai" },
      { type: "command", text: "python3 -m venv .venv" },
      { type: "command", text: "source .venv/bin/activate" },
      { type: "command", text: "pip install -e ." },
      { type: "command", text: "secopsai adaptive-response --persist-memory" },
    ],
  },
  windows: {
    eyebrow: "Windows",
    title: "WSL-first install path while Windows stays in beta",
    description: "Windows support is improving, but today the cleanest route is still to enable WSL2 and run the same SecOpsAI bootstrap from Ubuntu.",
    support: "Install WSL2 first, then continue with the Linux installer inside Ubuntu.",
    supportLabel: "Beta",
    supportTone: "beta",
    modeLabel: "Windows",
    shellLabel: "powershell + bash",
    terminalLabel: "wsl + ubuntu",
    lines: [
      { type: "comment", text: "Windows beta path" },
      { type: "command", text: "wsl --install -d Ubuntu" },
      { type: "blank", text: "" },
      { type: "comment", text: "Then inside Ubuntu" },
      { type: "command", text: "curl -fsSL https://secopsai.dev/install.sh | bash" },
      { type: "command", text: "cd ~/secopsai && source .venv/bin/activate" },
      { type: "command", text: "secopsai adaptive-response --persist-memory" },
    ],
  },
};
let activeQuickstartProfile = "oneliner";

const escapeHtml = (value) =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const renderQuickstartCode = (profile) =>
  profile.lines
    .map((line) => {
      if (line.type === "blank") {
        return "";
      }
      if (line.type === "comment") {
        return `<span class="text-muted"># ${escapeHtml(line.text)}</span>`;
      }

      const command = line.text.trim();
      const firstSpace = command.indexOf(" ");
      const lead = firstSpace === -1 ? command : command.slice(0, firstSpace);
      const tail = firstSpace === -1 ? "" : command.slice(firstSpace);
      return `<span class="text-muted">$ </span><span class="text-accent-soft">${escapeHtml(lead)}</span>${escapeHtml(tail)}`;
    })
    .join("\n");

const updateQuickstart = (profileKey) => {
  const profile = quickstartProfiles[profileKey];
  if (!profile) return;

  activeQuickstartProfile = profileKey;
  quickstartEyebrow.textContent = profile.eyebrow;
  quickstartTitle.textContent = profile.title;
  quickstartDescription.textContent = profile.description;
  quickstartSupport.textContent = profile.support;
  quickstartModePill.textContent = profile.modeLabel;
  quickstartShellLabel.textContent = profile.shellLabel;
  quickstartTerminalLabel.textContent = profile.terminalLabel;
  quickstartSupportPill.className = `status-pill ${profile.supportTone}`;
  quickstartSupportPill.innerHTML =
    profile.supportTone === "beta"
      ? '<span class="h-2 w-2 rounded-full bg-amber"></span>Beta'
      : `<span class="h-2 w-2 rounded-full bg-accent"></span>${profile.supportLabel}`;
  quickstartCode.innerHTML = renderQuickstartCode(profile);

  quickstartTabs.forEach((tab) => {
    tab.setAttribute("aria-pressed", String(tab.dataset.quickstartProfile === profileKey));
  });

  if (copyButton) {
    copyButton.dataset.copied = "false";
  }
  if (copyLabel) {
    copyLabel.textContent = "Copy commands";
  }
};

const syncHeaderState = () => {
  if (!header) return;
  if (window.scrollY > 20 || (mobileMenu && !mobileMenu.hidden)) {
    header.classList.add("is-scrolled");
  } else {
    header.classList.remove("is-scrolled");
  }
};

const setMenuState = (isOpen) => {
  if (!menuToggle || !mobileMenu || !openIcon || !closeIcon) return;
  mobileMenu.hidden = !isOpen;
  mobileMenu.classList.toggle("hidden", !isOpen);
  menuToggle.setAttribute("aria-expanded", String(isOpen));
  openIcon.classList.toggle("hidden", isOpen);
  closeIcon.classList.toggle("hidden", !isOpen);
  syncHeaderState();
};

if (menuToggle) {
  menuToggle.addEventListener("click", () => {
    setMenuState(mobileMenu.hidden);
  });
}

mobileLinks.forEach((link) => {
  link.addEventListener("click", () => {
    setMenuState(false);
  });
});

window.addEventListener("scroll", syncHeaderState, { passive: true });
syncHeaderState();

updateQuickstart(activeQuickstartProfile);
quickstartTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    updateQuickstart(tab.dataset.quickstartProfile);
  });
});

if (copyButton && copyLabel && quickstartCode) {
  const getQuickstartText = () =>
    quickstartProfiles[activeQuickstartProfile].lines
      .map((line) => {
        if (line.type === "comment") return `# ${line.text}`;
        return line.text;
      })
      .join("\n");

  copyButton.addEventListener("click", async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(getQuickstartText());
      } else {
        const input = document.createElement("textarea");
        input.value = getQuickstartText();
        input.style.position = "fixed";
        input.style.opacity = "0";
        document.body.appendChild(input);
        input.focus();
        input.select();
        document.execCommand("copy");
        document.body.removeChild(input);
      }

      copyButton.dataset.copied = "true";
      copyLabel.textContent = "Copied";
      window.setTimeout(() => {
        copyButton.dataset.copied = "false";
        copyLabel.textContent = "Copy commands";
      }, 1800);
    } catch (error) {
      copyLabel.textContent = "Copy failed";
      window.setTimeout(() => {
        copyLabel.textContent = "Copy commands";
      }, 1800);
    }
  });
}
