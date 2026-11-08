/* Controls for Python-validated embedded data. No browser import or schema adapter. */
(function () {
  "use strict";
  const MAX_EMBEDDED_CHARS = 12 * 1024 * 1024;
  const states = new Set(["all", "complete", "incomplete", "missing", "unknown"]);
  const conditions = new Set(["all", "attack", "clean", "authorized_control"]);

  function matchesCase(item, filters) {
    const state = states.has(filters.state) ? filters.state : "all";
    const condition = conditions.has(filters.condition) ? filters.condition : "all";
    const query = String(filters.query || "").slice(0, 256).trim().toLowerCase();
    return (state === "all" || (state === "unknown" ? item.unknown === "true" : item.state === state))
      && (condition === "all" || item.condition === condition)
      && String(item.search || "").toLowerCase().includes(query);
  }

  function exportJSON(embeddedText) {
    if (typeof embeddedText !== "string" || embeddedText.length > MAX_EMBEDDED_CHARS) {
      throw new Error("Embedded data exceeds the dashboard limit");
    }
    // The only data source is the Python-validated inert JSON element. This is
    // serialization, not a second contract validator or authenticity check.
    return JSON.stringify(JSON.parse(embeddedText), null, 2) + "\n";
  }

  function boot(doc, browser) {
    const byId = id => doc.getElementById(id);
    const status = byId("action-status");
    const download = byId("export");
    let exported;
    try {
      exported = exportJSON(byId("workflow-data").textContent);
    } catch {
      status.textContent = "Embedded JSON is unreadable. Regenerate this dashboard from a validated report.";
      return;
    }
    const cases = Array.from(doc.querySelectorAll("[data-case]"));
    const search = byId("search"), state = byId("state"), condition = byId("condition");
    function filter() {
      let visible = 0;
      for (const node of cases) {
        node.hidden = !matchesCase(node.dataset, {query: search.value, state: state.value, condition: condition.value});
        if (!node.hidden) visible++;
      }
      byId("filter-status").textContent = `Showing ${visible} of ${cases.length} declared cases. Summary counts are unchanged.`;
      byId("empty").hidden = visible !== 0;
    }
    for (const input of [search, state, condition]) input.addEventListener("input", filter);
    byId("reset").addEventListener("click", () => {
      search.value = ""; state.value = "all"; condition.value = "all"; filter();
    });
    byId("filters").hidden = false;
    byId("filter-note").hidden = false;
    const theme = byId("theme");
    theme.hidden = false;
    theme.addEventListener("click", () => {
      const next = doc.documentElement.dataset.theme === "dark" ? "light" : "dark";
      doc.documentElement.dataset.theme = next;
      theme.textContent = next === "dark" ? "Use light theme" : "Use dark theme";
    });
    download.hidden = false;
    download.addEventListener("click", () => {
      let url, anchor;
      try {
        const blob = new browser.Blob([exported], {type: "application/json;charset=utf-8"});
        url = browser.URL.createObjectURL(blob);
        anchor = doc.createElement("a");
        anchor.href = url;
        anchor.download = "workflow-run-report.json";
        doc.body.appendChild(anchor);
        anchor.click();
        status.textContent = "Recorded JSON download requested. Field values are preserved; formatting may differ.";
      } catch {
        status.textContent = "JSON download unavailable in this browser. The full recorded JSON remains readable below.";
      } finally {
        if (anchor) anchor.remove();
        if (url) browser.setTimeout(() => browser.URL.revokeObjectURL(url), 1000);
      }
    });
  }

  if (typeof module === "object" && module.exports) module.exports = {matchesCase, exportJSON, boot};
  if (typeof document !== "undefined") boot(document, window);
})();
