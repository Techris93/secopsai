const tabs = Array.from(document.querySelectorAll(".tab"));
const panels = Array.from(document.querySelectorAll(".tab-panel"));

const activateTab = (selectedTab, moveFocus = false) => {
  tabs.forEach((tab) => {
    const isSelected = tab === selectedTab;
    tab.setAttribute("aria-selected", String(isSelected));
    tab.tabIndex = isSelected ? 0 : -1;
  });

  panels.forEach((panel) => {
    panel.hidden = panel.dataset.panel !== selectedTab.dataset.tab;
  });

  if (moveFocus) {
    selectedTab.focus();
  }
};

tabs.forEach((tab, index) => {
  tab.addEventListener("click", () => activateTab(tab));
  tab.addEventListener("keydown", (event) => {
    let nextIndex = index;

    if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
    if (event.key === "ArrowLeft") nextIndex = (index - 1 + tabs.length) % tabs.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = tabs.length - 1;
    if (nextIndex === index) return;

    event.preventDefault();
    activateTab(tabs[nextIndex], true);
  });
});

document.querySelectorAll(".copy-btn").forEach((button) => {
  button.addEventListener("click", async () => {
    const originalLabel = button.textContent;

    try {
      await navigator.clipboard.writeText(button.dataset.copy || "");
      button.textContent = "COPIED";
    } catch (error) {
      button.textContent = "COPY FAILED";
    }

    window.setTimeout(() => {
      button.textContent = originalLabel;
    }, 1600);
  });
});
