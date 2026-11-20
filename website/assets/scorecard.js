// Renders the public frontier scorecard. Data is inserted as text only.
(function () {
  "use strict";
  var SOURCE = "https://ledger.secopsai.dev/public/frontier-scorecard";
  var LABELS = { "pass": "Pass", "fail": "Fail", "not measured": "Not measured" };
  var CLASSES = { "pass": "pass", "fail": "fail", "not measured": "none" };

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) { node.setAttribute(key, attrs[key]); });
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function fmt(value, metric) {
    if (value === null || value === undefined) return "—";
    if (typeof value !== "number") return String(value);
    if (/minutes$|_ms$/.test(metric || "")) return String(value);
    if (value <= 1 && /recall|coverage|rate|false_positive/.test(metric || "")) return (value * 100).toFixed(1) + "%";
    return String(value);
  }

  function setLink(id, href) {
    var link = document.getElementById(id);
    if (href && /^https:\/\/github\.com\//.test(href)) { link.href = href; link.textContent = href.replace("https://github.com/", ""); }
    else { link.removeAttribute("href"); link.textContent = "—"; }
  }

  function render(card) {
    var results = card.results || [];
    var met = results.filter(function (row) { return row.outcome === "pass"; }).length;
    document.getElementById("met").textContent = met + " of " + results.length;
    document.getElementById("generated").textContent = String(card.generated_at || "—").replace("T", " ").replace("Z", " UTC");
    var prov = card.provenance || {};
    document.getElementById("cutoff").textContent = prov.held_out_cutoff || "—";
    document.getElementById("commit").textContent = (prov.code_commit || "—").slice(0, 12);
    document.getElementById("rule").textContent = prov.rule || "";
    document.getElementById("targets-hash").textContent = prov.targets_sha256 || "—";
    if (prov.code_commit && /^[0-9a-f]{7,40}$/.test(prov.code_commit)) {
      document.getElementById("targets-link").href = "https://github.com/Techris93/secopsai/blob/" + prov.code_commit + "/eval/frontier/targets.json";
    }
    setLink("benchmark-link", prov.benchmark_run);
    setLink("scorecard-link", prov.scorecard_run);
    var inputs = (card.meta || {}).benchmark_inputs || {};
    var corpora = [];
    if (inputs.dataset_commit) corpora.push("DataDog malicious-software-packages-dataset @ " + String(inputs.dataset_commit).slice(0, 12));
    if (inputs.registry_commit) corpora.push("pypi_malregistry @ " + String(inputs.registry_commit).slice(0, 12));
    document.getElementById("corpora").textContent = corpora.join("; ") || "—";

    var container = document.getElementById("phases");
    (card.phases || []).forEach(function (phase) {
      var rows = results.filter(function (row) { return row.phase === phase.id; });
      if (!rows.length) return;
      var section = el("section");
      var heading = el("h2");
      heading.appendChild(el("span", { "class": "id" }, phase.id.replace("phase-", "")));
      heading.appendChild(document.createTextNode(phase.title));
      section.appendChild(heading);
      var wrap = el("div", { "class": "table-wrap" });
      var table = el("table");
      var head = el("tr");
      ["Target", "Baseline", "Goal", "Measured", "Result"].forEach(function (name) { head.appendChild(el("th", { scope: "col" }, name)); });
      table.appendChild(el("thead")).appendChild(head);
      var body = el("tbody");
      rows.forEach(function (row) {
        var tr = el("tr");
        tr.appendChild(el("td", null, row.name));
        tr.appendChild(el("td", { "class": "num" }, fmt(row.baseline, row.metric)));
        tr.appendChild(el("td", { "class": "num" }, (row.op === ">=" ? "≥ " : "≤ ") + fmt(row.target, row.metric)));
        tr.appendChild(el("td", { "class": "num" }, fmt(row.measured, row.metric)));
        var cell = el("td");
        cell.appendChild(el("span", { "class": "result " + (CLASSES[row.outcome] || "none") }, LABELS[row.outcome] || row.outcome));
        tr.appendChild(cell);
        body.appendChild(tr);
      });
      table.appendChild(body);
      wrap.appendChild(table);
      section.appendChild(wrap);
      container.appendChild(section);
    });
    document.getElementById("status").remove();
  }

  fetch(SOURCE, { headers: { "Accept": "application/json" } })
    .then(function (response) { if (!response.ok) throw new Error(String(response.status)); return response.json(); })
    .then(render)
    .catch(function () { document.getElementById("status").textContent = "The scorecard could not be loaded."; });
})();
