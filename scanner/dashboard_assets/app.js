(() => {
  "use strict";

  const PAGE_SIZE = 50;
  const POLL_MS = 5000;
  let page = 1;
  let totalItems = 0;
  let pollTimer = null;
  let latestStatus = null;

  const byId = (id) => document.getElementById(id);
  const text = (element, value) => { element.textContent = value == null || value === "" ? "—" : String(value); };
  const read = (object, key, fallback = "") => object && object[key] != null ? object[key] : fallback;
  const counters = (status) => read(status, "counters", {});

  async function fetchJson(path, options = {}) {
    const response = await fetch(path, { cache: "no-store", ...options });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(read(read(payload, "error", {}), "message", `Request failed (${response.status})`));
    }
    return payload;
  }

  function unwrap(payload) {
    return payload && payload.data && !payload.status ? payload.data : payload;
  }

  function setMessage(message, kind = "") {
    const element = byId("control-message");
    element.className = `inline-message ${kind}`.trim();
    text(element, message);
  }

  function displayStatus(status) {
    latestStatus = unwrap(status) || {};
    const state = String(read(latestStatus, "status", "idle"));
    const pill = byId("scan-state");
    text(pill, state.replaceAll("_", " "));
    pill.dataset.state = state;
    text(byId("last-updated"), read(latestStatus, "updatedAt", "Waiting for status"));

    const counts = counters(latestStatus);
    text(byId("metric-findings"), read(counts, "findings", 0));
    text(byId("metric-queued"), read(counts, "queued", 0));
    text(byId("metric-done"), read(counts, "done", 0));
    text(byId("metric-failed"), read(counts, "failed", 0));
    text(byId("metric-requests"), read(counts, "requests", 0));

    const active = ["running", "paused", "rate_limited"].includes(state);
    byId("start-scan").disabled = active;
    byId("pause-scan").disabled = state !== "running";
    byId("stop-scan").disabled = !active;
    if (read(latestStatus, "lastError")) setMessage(read(latestStatus, "lastError"), "error");
    schedulePoll(state);
  }

  function schedulePoll(state) {
    if (pollTimer) window.clearTimeout(pollTimer);
    if (!["running", "paused", "rate_limited"].includes(state)) return;
    pollTimer = window.setTimeout(async () => {
      await refreshDashboard(true);
    }, POLL_MS);
  }

  function sourceUrl(value) {
    try {
      const url = new URL(String(value));
      if (url.protocol !== "https:" || url.hostname.toLowerCase() !== "github.com") return null;
      return url.href;
    } catch (_) {
      return null;
    }
  }

  function cell(row, value, className = "") {
    const element = document.createElement("td");
    if (className) element.className = className;
    text(element, value);
    row.appendChild(element);
    return element;
  }

  function renderFindings(payload) {
    const data = Array.isArray(read(payload, "data")) ? payload.data : [];
    totalItems = Number(read(payload, "totalItems", data.length)) || 0;
    const body = byId("findings-body");
    body.replaceChildren();
    byId("page-summary").textContent = `Page ${page} · ${totalItems} total`;
    byId("previous-page").disabled = page <= 1;
    byId("next-page").disabled = page * PAGE_SIZE >= totalItems;

    if (!data.length) {
      showTableState(totalItems ? "No findings match this provider filter." : "No findings yet. Start a scan to populate the evidence register.");
      return;
    }
    byId("findings-state").classList.add("is-hidden");
    data.forEach((finding) => {
      const row = document.createElement("tr");
      const provider = read(finding, "provider", "Unknown provider");
      cell(row, provider);
      cell(row, `${read(finding, "confidence", 0)}%`, "confidence-value");
      cell(row, read(finding, "repository"));
      cell(row, read(finding, "path"), "path-value");
      cell(row, read(finding, "line_number", read(finding, "lineNumber", read(finding, "line"))));
      cell(row, read(finding, "commit_sha", read(finding, "commitSha", read(finding, "commit"))), "commit-value");
      cell(row, read(finding, "masked_preview", read(finding, "maskedPreview", "Masked preview unavailable")), "masked-value");

      const statusCell = cell(row, read(finding, "status", "open"));
      const findingId = String(read(finding, "finding_id", read(finding, "findingId", read(finding, "id"))));
      if (/^[a-f0-9]{64}$/.test(findingId)) {
        const preview = document.createElement("button");
        preview.type = "button";
        preview.className = "preview-button";
        preview.textContent = "Preview disclosure";
        preview.addEventListener("click", () => showDisclosure(findingId, finding));
        statusCell.appendChild(document.createElement("br"));
        statusCell.appendChild(preview);
      }

      const sourceCell = document.createElement("td");
      const href = sourceUrl(read(finding, "permalink", read(finding, "source_url", read(finding, "sourceUrl"))));
      if (href) {
        const link = document.createElement("a");
        link.className = "source-link";
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.href = href;
        link.textContent = "Open source";
        sourceCell.appendChild(link);
      } else {
        text(sourceCell, "Unavailable");
      }
      row.appendChild(sourceCell);
      body.appendChild(row);
    });
  }

  function showTableState(message, kind = "") {
    const state = byId("findings-state");
    state.className = `table-state ${kind}`.trim();
    text(state, message);
  }

  function summaryEntries(value) {
    if (Array.isArray(value)) return value.map((item) => [read(item, "label", read(item, "name", "Unknown")), Number(read(item, "count", 0)) || 0]);
    return Object.entries(value && typeof value === "object" ? value : {}).map(([label, count]) => [label, Number(count) || 0]);
  }

  function renderBars(id, value, emptyMessage) {
    const host = byId(id);
    host.replaceChildren();
    const entries = summaryEntries(value).sort((left, right) => right[1] - left[1]);
    if (!entries.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = emptyMessage;
      host.appendChild(empty);
      return;
    }
    const max = Math.max(...entries.map((entry) => entry[1]), 1);
    entries.slice(0, 8).forEach(([label, count]) => {
      const item = document.createElement("div");
      item.className = "bar-item";
      item.setAttribute("role", "listitem");
      const header = document.createElement("div");
      header.className = "bar-label";
      const name = document.createElement("span");
      name.textContent = label;
      const amount = document.createElement("strong");
      amount.textContent = String(count);
      header.append(name, amount);
      const track = document.createElement("div");
      track.className = "bar-track";
      const fill = document.createElement("div");
      fill.className = "bar-fill";
      fill.setAttribute("role", "progressbar");
      fill.setAttribute("aria-label", `${label}: ${count}`);
      fill.setAttribute("aria-valuenow", String(count));
      fill.setAttribute("aria-valuemin", "0");
      fill.setAttribute("aria-valuemax", String(max));
      fill.style.width = `${Math.max(4, Math.round((count / max) * 100))}%`;
      track.appendChild(fill);
      item.append(header, track);
      host.appendChild(item);
    });
  }

  function renderSummary(payload) {
    const summary = unwrap(payload) || {};
    const providers = read(summary, "providers", read(summary, "provider_distribution", read(summary, "provider_counts", {})));
    renderBars("provider-summary", providers, "No provider data yet.");
    renderBars("confidence-summary", read(summary, "confidence", read(summary, "confidence_distribution", read(summary, "confidence_buckets", {}))), "No confidence data yet.");
    renderBars("daily-summary", read(summary, "daily", read(summary, "daily_findings", read(summary, "by_date", {}))), "No daily findings yet.");

    const filter = byId("provider-filter");
    const selected = filter.value;
    filter.replaceChildren();
    const all = document.createElement("option");
    all.value = "";
    all.textContent = "All providers";
    filter.appendChild(all);
    summaryEntries(providers).forEach(([provider]) => {
      const option = document.createElement("option");
      option.value = provider;
      option.textContent = provider;
      filter.appendChild(option);
    });
    filter.value = selected;
  }

  async function loadStatus() {
    try {
      displayStatus(await fetchJson("/api/status"));
    } catch (error) {
      byId("scan-state").dataset.state = "failed";
      text(byId("scan-state"), "Unavailable");
      setMessage(`Could not load status: ${error.message}`, "error");
    }
  }

  async function loadFindings() {
    showTableState("Loading findings…");
    const provider = byId("provider-filter").value;
    const query = new URLSearchParams({ page: String(page), pageSize: String(PAGE_SIZE) });
    if (provider) query.set("provider", provider);
    try {
      renderFindings(await fetchJson(`/api/findings?${query.toString()}`));
    } catch (error) {
      showTableState(`Could not load findings: ${error.message}`, "error");
    }
  }

  async function loadSummary() {
    try {
      renderSummary(await fetchJson("/api/summary"));
    } catch (error) {
      ["provider-summary", "confidence-summary", "daily-summary"].forEach((id) => renderBars(id, {}, `Could not load summary: ${error.message}`));
    }
  }

  async function refreshDashboard(quiet = false) {
    if (!quiet) showTableState("Loading findings…");
    await Promise.allSettled([loadStatus(), loadFindings(), loadSummary()]);
  }

  async function sendScanAction(path, body) {
    try {
      const payload = await fetchJson(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : "{}" });
      setMessage(`Scan ${read(unwrap(payload), "status", "updated")} acknowledged.`, "success");
      await refreshDashboard(true);
    } catch (error) {
      setMessage(error.message, "error");
    }
  }

  async function showDisclosure(findingId, finding) {
    const panel = byId("draft-panel");
    panel.classList.remove("is-hidden");
    text(byId("draft-path"), "Loading safe disclosure draft…");
    byId("draft-content").textContent = "";
    try {
      const draft = unwrap(await fetchJson(`/api/disclosures/${encodeURIComponent(findingId)}`));
      text(byId("draft-path"), read(draft, "path", "Local draft path unavailable"));
      byId("draft-content").textContent = read(draft, "content", "No safe draft content returned.");
      const source = sourceUrl(read(finding, "permalink", read(finding, "source_url", read(finding, "sourceUrl"))));
      const link = byId("draft-source");
      if (source) { link.href = source; link.classList.remove("is-hidden"); } else link.classList.add("is-hidden");
    } catch (error) {
      text(byId("draft-path"), `Could not load draft: ${error.message}`);
    }
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function bindEvents() {
    byId("scan-mode").addEventListener("change", (event) => {
      byId("repository-field").classList.toggle("is-hidden", event.target.value !== "repo");
    });
    byId("scan-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const mode = byId("scan-mode").value;
      const repository = byId("repository").value.trim();
      if (mode === "repo" && !/^[^/\s]+\/[^/\s]+$/.test(repository)) {
        setMessage("Enter a repository as OWNER/REPO before starting a targeted scan.", "error");
        byId("repository").focus();
        return;
      }
      const body = { mode, once: byId("run-once").checked };
      if (mode === "repo") body.repository = repository;
      sendScanAction("/api/scans", body);
    });
    byId("pause-scan").addEventListener("click", () => sendScanAction("/api/scans/pause"));
    byId("stop-scan").addEventListener("click", () => sendScanAction("/api/scans/stop"));
    byId("provider-filter").addEventListener("change", () => { page = 1; loadFindings(); });
    byId("previous-page").addEventListener("click", () => { if (page > 1) { page -= 1; loadFindings(); } });
    byId("next-page").addEventListener("click", () => { if (page * PAGE_SIZE < totalItems) { page += 1; loadFindings(); } });
    byId("close-draft").addEventListener("click", () => byId("draft-panel").classList.add("is-hidden"));
  }

  document.addEventListener("DOMContentLoaded", () => { bindEvents(); refreshDashboard(); });
})();
