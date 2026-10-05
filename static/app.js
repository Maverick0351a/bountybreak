"use strict";

const $ = (selector) => document.querySelector(selector);
const state = { engagements: [], tools: [], csrf: "", selected: null, runPlanId: null };
const titles = { overview: "Overview", engagements: "Engagements", intelligence: "Exploit intelligence",
  sandbox: "Logic sandbox", assistant: "AI assistant", tools: "Tool catalog", about: "About & limits" };

function el(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = content;
  return node;
}

function flash(message, persistent = false) {
  $("#message").textContent = message;
  window.clearTimeout(flash.timer);
  if (!persistent) flash.timer = window.setTimeout(() => { $("#message").textContent = ""; }, 8000);
}

async function api(path, method = "GET", data) {
  const options = { method, headers: {} };
  if (data !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = state.csrf;
    options.body = JSON.stringify(data);
  }
  const response = await fetch(path, options);
  const raw = await response.text();
  let body = {};
  try { body = raw ? JSON.parse(raw) : {}; }
  catch (_error) { /* Preserve the HTTP status below instead of surfacing a JSON parser error. */ }
  if (!response.ok) throw new Error(body.error || `Request failed: ${response.status}`);
  if (!raw || typeof body !== "object" || body === null) throw new Error("Server returned an invalid response");
  return body;
}

function show(view) {
  for (const section of document.querySelectorAll(".view")) section.classList.toggle("hidden", section.id !== view);
  for (const button of document.querySelectorAll(".nav")) button.classList.toggle("active", button.dataset.view === view);
  $("#page-title").textContent = titles[view];
}

function renderCases() {
  const list = $("#engagement-list");
  list.replaceChildren();
  $("#engagement-count").textContent = String(state.engagements.length);
  if (!state.engagements.length) {
    list.append(el("div", "empty", "No engagements yet. Create a researcher-owned lab engagement to try the complete workflow."));
    return;
  }
  for (const item of state.engagements) {
    const card = el("button", "case");
    card.type = "button";
    const assetCount = (item.assets || []).length;
    card.append(el("span", "meta", item.kind.replace("_", " ")), el("h4", "", item.name),
      el("p", "", item.authority), el("small", "", `${assetCount} ${assetCount === 1 ? "asset" : "assets"} · ${item.plans.length} ${item.plans.length === 1 ? "plan" : "plans"} · ${item.runs.length} ${item.runs.length === 1 ? "run" : "runs"}`));
    card.addEventListener("click", () => openCase(item.id));
    list.append(card);
  }
}

function renderTools() {
  const list = $("#tool-list");
  list.replaceChildren();
  for (const tool of state.tools) {
    const card = el("article", "tool");
    card.append(el("span", "meta", tool.mode), el("h4", "", tool.name), el("p", "", tool.role));
    const link = el("a", "", "Project site ↗");
    link.href = tool.link;
    link.rel = "noopener noreferrer";
    link.target = "_blank";
    card.append(link);
    list.append(card);
  }
}

function renderAiEngagements() {
  const select = $("#ai-engagement");
  select.replaceChildren();
  const none = el("option", "", "No engagement"); none.value = ""; select.append(none);
  for (const item of state.engagements) {
    const option = el("option", "", `${item.name} (${item.kind.replace("_", " ")})`);
    option.value = item.id;
    select.append(option);
  }
  const enabled = Number.isInteger(state.ai_port);
  $("#model-status").textContent = enabled
    ? `Local AI enabled at 127.0.0.1:${state.ai_port}. The question and selected context go to that model.`
    : "AI drafting is off. Restart BountyBreak with --model-port PORT after choosing a local model.";
  $("#ai-form button.primary").disabled = !enabled;
}

function localAssets(item) {
  return (item.assets || []).map((entry) => entry.value)
    .filter((value) => /^https?:\/\/127\.0\.0\.1:\d+\/?$/i.test(value));
}

function showLocalRun(planId) {
  state.runPlanId = planId;
  const select = $("#local-asset");
  select.replaceChildren();
  for (const value of localAssets(state.selected)) {
    const option = el("option", "", value);
    option.value = value;
    select.append(option);
  }
  $("#local-run-dialog").showModal();
}

async function refresh() {
  const data = await api("/api/state");
  Object.assign(state, data);
  renderCases();
  renderTools();
  renderAiEngagements();
  if ((state.data_warnings || []).length) {
    const ids = state.data_warnings.map((item) => item.engagement_id).join(", ");
    flash(`Data warning: ${state.data_warnings.length} engagement record could not be loaded (${ids}). The file was preserved on disk.`, true);
  }
}

$("#intel-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const query = new FormData(event.currentTarget).get("query");
  const output = $("#intel-results");
  output.replaceChildren(el("p", "intro", "Searching local index…"));
  try {
    const data = await api("/api/intelligence/search", "POST", { query });
    output.replaceChildren();
    if (!data.records.length) output.append(el("p", "intro", "No matching records in the bundled index."));
    for (const record of data.records) {
      const box = el("article", "intel-card");
      box.append(el("span", "meta", `${record.cve_id} · ${record.status} · ${record.confidence} confidence`),
        el("h4", "", record.title), el("p", "", `Product: ${record.product}`),
        el("p", "", `Prerequisites: ${record.prerequisites}`),
        el("p", "", `Validation: ${record.validation_notes}`),
        el("small", "", `Last verified: ${record.last_verified}`));
      for (const source of record.sources) {
        const link = el("a", "", `${source.publisher} ↗`);
        link.href = source.url; link.target = "_blank"; link.rel = "noopener noreferrer";
        box.append(link);
      }
      output.append(box);
    }
  } catch (error) { output.replaceChildren(el("p", "intro", error.message)); }
});

$("#load-sandbox-example").addEventListener("click", async () => {
  try {
    const example = await api("/api/sandbox/example");
    $("#sandbox-world").value = JSON.stringify(example.world, null, 2);
    $("#sandbox-plan").value = JSON.stringify(example.plan, null, 2);
    $("#sandbox-summary").replaceChildren(el("p", "intro", "Synthetic example loaded. Run the simulation to inspect both cases."));
    $("#sandbox-raw").hidden = true;
  } catch (error) { flash(error.message); }
});

function renderSandboxSummary(data) {
  const summary = $("#sandbox-summary");
  const verdict = data.result === "supported_in_model" ? "Supported in this model" : "Not supported in this model";
  summary.replaceChildren(el("div", "sandbox-verdict", verdict));
  const cases = el("div", "sandbox-case-grid");
  for (const item of data.cases || []) {
    const card = el("article", "sandbox-case");
    const title = item.kind === "negative_control" ? "Negative control" : "Hypothesis";
    const blocked = (item.trace || []).filter((step) => step.result !== "applied").length;
    card.append(el("span", "eyebrow", title),
      el("strong", "", item.goal ? "Goal reached" : "Goal blocked"),
      el("p", "", `${item.case} · ${item.matches_expectation ? "Matched" : "Did not match"} expected outcome · ${blocked} blocked ${blocked === 1 ? "step" : "steps"}`));
    cases.append(card);
  }
  summary.append(cases, el("p", "sandbox-boundary", "Symbolic result only. No real target was tested."));
}

$("#sandbox-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const world = JSON.parse(form.elements.world.value);
    const plan = JSON.parse(form.elements.plan.value);
    const data = await api("/api/sandbox/simulate", "POST", { world, plan, explore: form.elements.explore.checked });
    renderSandboxSummary(data);
    $("#sandbox-result").textContent = JSON.stringify(data, null, 2);
    $("#sandbox-raw").hidden = false;
  } catch (error) {
    $("#sandbox-summary").replaceChildren(el("p", "intro", error.message));
    $("#sandbox-raw").hidden = true;
  }
});

$("#ai-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button.primary");
  const result = $("#ai-result");
  button.disabled = true; result.textContent = "Waiting for the local model…";
  try {
    const payload = Object.fromEntries(new FormData(form));
    if (form.elements.include_sandbox.checked) {
      if (!$("#sandbox-world").value || !$("#sandbox-plan").value) {
        throw new Error("Load or enter a Logic sandbox world and plan first.");
      }
      payload.world = JSON.parse($("#sandbox-world").value);
      payload.plan = JSON.parse($("#sandbox-plan").value);
      delete payload.include_sandbox;
    }
    const answer = await api("/api/ai/draft", "POST", payload);
    const sources = answer.prior_art.flatMap((item) => item.sources.map((source) => source.url));
    result.textContent = `${answer.draft}\n\nClassification: unverified · model: ${answer.model}${answer.sandbox_result ? ` · sandbox: ${answer.sandbox_result}` : ""}\nPrior-art sources:\n${sources.join("\n") || "No matching bundled record"}`;
  } catch (error) { result.textContent = error.message; }
  finally { button.disabled = !Number.isInteger(state.ai_port); }
});

async function openCase(id) {
  const item = await api(`/api/engagements/${id}`);
  state.selected = item;
  show("engagements");
  const detail = $("#detail");
  detail.classList.remove("hidden");
  detail.replaceChildren();
  const top = el("div", "detail-top");
  const heading = el("div");
  heading.append(el("span", "eyebrow", item.kind.replace("_", " ").toUpperCase()), el("h3", "", item.name),
    el("p", "", `Authority / scope source: ${item.authority}`));
  const actions = el("div", "detail-actions");
  const assetButton = el("button", "secondary", "+ Add asset");
  assetButton.addEventListener("click", () => $("#asset-dialog").showModal());
  const planButton = el("button", "primary", "+ Add plan");
  planButton.addEventListener("click", () => $("#plan-dialog").showModal());
  actions.append(assetButton, planButton);
  top.append(heading, actions);
  detail.append(top, el("h4", "panel-title", "Recorded URLs & assets"));
  const assets = el("div", "asset-list");
  if (!(item.assets || []).length) assets.append(el("p", "intro", "No assets recorded yet. Add an exact URL or asset identifier for planning."));
  for (const asset of item.assets || []) assets.append(el("div", "asset", asset.value));
  detail.append(assets, el("h4", "panel-title", "Hypotheses & plans"));
  if (!item.plans.length) detail.append(el("p", "intro", "No plan yet. Start with one testable hypothesis and a concrete impact."));
  for (const plan of item.plans) {
    const box = el("article", "plan");
    box.append(el("small", "", `PLAN ${plan.id} · ${plan.status.toUpperCase()}`),
      el("p", "", plan.hypothesis), el("small", "", `Potential impact: ${plan.impact}`));
    if (item.kind === "owned_lab") {
      const planActions = el("div", "plan-actions");
      const run = el("button", "secondary", "Run bundled lab check →");
      run.addEventListener("click", () => runDemo(item.id, plan.id, run));
      planActions.append(run);
      if (localAssets(item).length) {
        const localRun = el("button", "primary", "Check a local URL →");
        localRun.addEventListener("click", () => showLocalRun(plan.id));
        planActions.append(localRun);
      } else {
        box.append(el("small", "plan-hint", "The bundled lab is ready. Add a recorded http://127.0.0.1:PORT origin only for your separate local service."));
      }
      box.append(planActions);
    }
    detail.append(box);
  }
  detail.append(el("h4", "panel-title", "Evidence"));
  if (!item.runs.length) detail.append(el("p", "intro", "No runs recorded."));
  for (const run of [...item.runs].reverse()) {
    const box = el("article", "run");
    box.append(el("small", "", `${run.created_at} · ${run.environment}`), el("p", "", run.finding));
    const row = el("div", "run-grid");
    row.append(el("span", "pill", `${run.requests_sent}/${run.request_budget} requests`),
      el("span", "pill", `Negative control: ${run.negative_control_passed === null ? "not reached" : run.negative_control_passed ? "passed" : "failed"}`));
    if (run.target_origin) row.append(el("span", "pill", run.target_origin));
    if (run.stopped_reason) row.append(el("span", "pill", `Stopped: ${run.stopped_reason}`));
    for (const observation of run.observations) {
      const label = observation.error ? `${observation.path}: ${observation.error}`
        : `${observation.path}: HTTP ${observation.status}${observation.body_sha256 ? ` · SHA-256 ${observation.body_sha256.slice(0, 12)}…` : ""}`;
      row.append(el("span", "pill", label));
    }
    box.append(row);
    detail.append(box);
  }
}

async function runDemo(id, planId, button) {
  button.disabled = true;
  try {
    await api(`/api/engagements/${id}/demo-run`, "POST", { plan_id: planId });
    await refresh();
    await openCase(id);
    flash("Two-request lab check complete. Evidence saved locally.");
  } catch (error) { flash(error.message); button.disabled = false; }
}

$("#local-run-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button.primary");
  const data = Object.fromEntries(new FormData(form));
  data.plan_id = state.runPlanId;
  data.expected_control_status = Number(data.expected_control_status);
  data.owned_lab_attested = form.elements.owned_lab_attested.checked;
  button.disabled = true;
  try {
    const run = await api(`/api/engagements/${state.selected.id}/local-run`, "POST", data);
    form.reset(); $("#local-run-dialog").close(); await refresh(); await openCase(state.selected.id);
    flash(run.status === "stopped" ? `Local check stopped: ${run.stopped_reason}` : "Bounded local check complete. Evidence saved locally.");
  } catch (error) { flash(error.message); }
  finally { button.disabled = false; }
});

document.querySelectorAll(".nav").forEach((button) => button.addEventListener("click", () => show(button.dataset.view)));
$("#new-from-overview").addEventListener("click", () => $("#engagement-dialog").showModal());
$("#new-engagement").addEventListener("click", () => $("#engagement-dialog").showModal());
document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
$("#engagement-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  try {
    const item = await api("/api/engagements", "POST", data);
    form.reset(); $("#engagement-dialog").close(); await refresh(); await openCase(item.id);
    flash("Engagement created locally.");
  } catch (error) { flash(error.message); }
});
$("#plan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    await api(`/api/engagements/${state.selected.id}/plans`, "POST", Object.fromEntries(new FormData(form)));
    form.reset(); $("#plan-dialog").close(); await refresh(); await openCase(state.selected.id);
    flash("Hypothesis saved. Owned-lab checks are available when their target is ready.");
  } catch (error) { flash(error.message); }
});

$("#asset-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    await api(`/api/engagements/${state.selected.id}/assets`, "POST", Object.fromEntries(new FormData(form)));
    form.reset(); $("#asset-dialog").close(); await refresh(); await openCase(state.selected.id);
    flash("Asset recorded for planning. No target traffic was sent.");
  } catch (error) { flash(error.message); }
});

refresh().catch((error) => flash(error.message));
