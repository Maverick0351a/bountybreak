"use strict";

const $ = (selector) => document.querySelector(selector);
const state = { engagements: [], tools: [], csrf: "", selected: null };
const titles = { overview: "Overview", engagements: "Engagements", tools: "Tool catalog", about: "About & limits" };

function el(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = content;
  return node;
}

function flash(message) {
  $("#message").textContent = message;
  window.clearTimeout(flash.timer);
  flash.timer = window.setTimeout(() => { $("#message").textContent = ""; }, 8000);
}

async function api(path, method = "GET", data) {
  const options = { method, headers: {} };
  if (data !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = state.csrf;
    options.body = JSON.stringify(data);
  }
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `Request failed: ${response.status}`);
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
    card.append(el("span", "meta", item.kind.replace("_", " ")), el("h4", "", item.name),
      el("p", "", item.authority), el("small", "", `${item.plans.length} plans · ${item.runs.length} runs`));
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

async function refresh() {
  const data = await api("/api/state");
  Object.assign(state, data);
  renderCases();
  renderTools();
}

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
  const planButton = el("button", "primary", "+ Add plan");
  planButton.addEventListener("click", () => $("#plan-dialog").showModal());
  actions.append(planButton);
  top.append(heading, actions);
  detail.append(top, el("h4", "panel-title", "Hypotheses & plans"));
  if (!item.plans.length) detail.append(el("p", "intro", "No plan yet. Start with one testable hypothesis and a concrete impact."));
  for (const plan of item.plans) {
    const box = el("article", "plan");
    box.append(el("small", "", `PLAN ${plan.id} · ${plan.status.toUpperCase()}`),
      el("p", "", plan.hypothesis), el("small", "", `Potential impact: ${plan.impact}`));
    if (item.kind === "owned_lab") {
      const run = el("button", "secondary", "Run bundled lab check →");
      run.addEventListener("click", () => runDemo(item.id, plan.id, run));
      box.append(el("br"), run);
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
      el("span", "pill", `Negative control: ${run.negative_control_passed ? "passed" : "failed"}`));
    for (const observation of run.observations) row.append(el("span", "pill", `${observation.path}: HTTP ${observation.status} · SHA-256 ${observation.body_sha256.slice(0, 12)}…`));
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
    flash("Hypothesis saved. The local demo is ready for owned-lab engagements.");
  } catch (error) { flash(error.message); }
});

refresh().catch((error) => flash(error.message));
