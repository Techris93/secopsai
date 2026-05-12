(async () => {
  const search = document.querySelector("#post-search");
  const cards = [...document.querySelectorAll("[data-search]")];
  search?.addEventListener("input", () => {
    const term = search.value.trim().toLowerCase();
    for (const card of cards) {
      card.style.display = card.dataset.search.includes(term) ? "" : "none";
    }
  });
})();
