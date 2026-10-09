// Copy-link and native share sheet for the docs share bar. Event delegation
// keeps it working with Material's instant navigation.
(function () {
  function revealNative() {
    if (typeof navigator.share !== "function") return;
    document.querySelectorAll("[data-share-native]").forEach(function (button) { button.hidden = false; });
  }
  document.addEventListener("click", function (event) {
    var copy = event.target.closest("[data-copy]");
    if (copy) {
      navigator.clipboard.writeText(copy.getAttribute("data-copy") || location.href).then(function () {
        copy.classList.add("is-copied");
        setTimeout(function () { copy.classList.remove("is-copied"); }, 1200);
      }, function () {});
      return;
    }
    var native = event.target.closest("[data-share-native]");
    if (native && typeof navigator.share === "function") {
      navigator.share({ title: native.getAttribute("data-share-title") || document.title, url: native.getAttribute("data-share-url") || location.href }).catch(function () {});
    }
  });
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(revealNative);
  } else {
    document.addEventListener("DOMContentLoaded", revealNative);
  }
})();
