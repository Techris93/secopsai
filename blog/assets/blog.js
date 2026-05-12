(async () => {
  const search = document.querySelector("#post-search");
  const cards = [...document.querySelectorAll("[data-search]")];
  const sort = document.querySelector("#post-sort");
  const filters = [...document.querySelectorAll("[data-topic-filter]")];
  const postList = document.querySelector("#posts");
  let activeTopic = "all";

  const applyFilters = () => {
    const term = search?.value.trim().toLowerCase() || "";
    for (const card of cards) {
      const matchesSearch = card.dataset.search.includes(term);
      const matchesTopic = activeTopic === "all" || card.dataset.topic.includes(activeTopic);
      card.style.display = matchesSearch && matchesTopic ? "" : "none";
    }
  };

  const applySort = () => {
    if (!postList || !sort) return;
    const sorted = [...cards].sort((a, b) => {
      if (sort.value === "oldest") return String(a.dataset.date).localeCompare(String(b.dataset.date));
      if (sort.value === "severity") return Number(b.dataset.severity || 0) - Number(a.dataset.severity || 0);
      if (sort.value === "reading") return Number(b.dataset.reading || 0) - Number(a.dataset.reading || 0);
      return String(b.dataset.date).localeCompare(String(a.dataset.date));
    });
    const feedAside = postList.querySelector("aside");
    for (const card of sorted) postList.insertBefore(card, feedAside);
  };

  search?.addEventListener("input", applyFilters);
  sort?.addEventListener("change", () => {
    applySort();
    applyFilters();
  });
  for (const filter of filters) {
    filter.addEventListener("click", () => {
      activeTopic = filter.dataset.topicFilter || "all";
      filters.forEach((item) => item.classList.toggle("active", item === filter));
      applyFilters();
    });
  }

  document.addEventListener("click", async (event) => {
    const target = event.target.closest("[data-copy]");
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.dataset.copy || "");
      target.classList.add("copied");
      setTimeout(() => target.classList.remove("copied"), 1200);
    } catch {
      target.classList.add("copy-failed");
    }
  });

  applySort();
  applyFilters();
})();
