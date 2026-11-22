// Warden App - main window logic.
//
// SECURITY RULE FOR THIS FILE: stories can contain an attacker's text (the hidden
// line). It must ALWAYS be inserted with textContent / createElement, NEVER as
// HTML. Otherwise a hidden "<img onerror=...>" in an email could run code inside
// the window that has the Protect and Allow buttons (cross-site scripting).
// tests/test_app_ui.py fails if this file ever uses an HTML-inserting API.

"use strict";

let api = null;                 // Python side (window.pywebview.api), or the demo data
let showAll = false;
let pendingConfirm = null;

// ---------- tiny safe DOM helpers ----------
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function $(id) { return document.getElementById(id); }

// ---------- navigation ----------
function showPage(name) {
  for (const button of document.querySelectorAll(".nav")) {
    button.classList.toggle("active", button.dataset.page === name);
  }
  for (const page of ["home", "history", "lab"]) {
    $("page-" + page).hidden = page !== name;
  }
  if (name === "history") refreshHistory();
}

// ---------- Home ----------
const MARKS = { ok: "M9 12l2 2 4-4", warn: "M12 8v5M12 16.5v.5", bad: "M9.5 9.5l5 5M14.5 9.5l-5 5" };

async function refreshStatus() {
  const s = await api.get_status();
  const hero = $("hero");
  hero.classList.remove("state-ok", "state-warn", "state-bad");
  hero.classList.add("state-" + s.overall);
  $("hero-mark").setAttribute("d", MARKS[s.overall] || MARKS.warn);
  $("headline").textContent = s.headline;
  $("subline").textContent = s.subline;

  $("stat-actions").textContent = s.today.actions;
  $("stat-attacks").textContent = s.today.attacks;
  $("stat-blocked").textContent = s.today.blocked;
  $("stat-allowed").textContent = s.today.you_allowed;

  const checks = $("checks");
  checks.replaceChildren();
  for (const c of s.checks) {
    const row = el("div", "row");
    const kind = c.ok === true ? "ok" : c.ok === false ? "bad" : "none";
    row.append(el("div", "dot " + kind, kind === "ok" ? "✓" : kind === "bad" ? "!" : "–"));
    row.append(el("div", "row-main row-title", c.text));
    checks.append(row);
  }

  const apps = $("apps");
  apps.replaceChildren();
  if (!s.apps.length) apps.append(el("div", "muted", "No supported AI app found on this PC."));
  for (const a of s.apps) {
    const row = el("div", "row");
    const main = el("div", "row-main");
    main.append(el("div", "row-title", a.name));
    main.append(el("div", "row-sub", a.note || a.path));
    const pill = { protected: ["ok", "PROTECTED"], not_protected: a.has_tools ? ["bad", "NOT PROTECTED"] : ["none", "NO AI TOOLS"],
                   unreadable: ["warn", "CAN'T READ CONFIG"] }[a.state] || ["none", a.state];
    const button = el("button", "btn" + (a.state === "protected" ? "" : " primary"),
                      a.state === "protected" ? "Unprotect" : "Protect");
    button.disabled = a.state === "unreadable";
    button.addEventListener("click", () => confirmProtection(a));
    row.append(main, el("span", "pill " + pill[0], pill[1]), button);
    apps.append(row);
  }
}

function confirmProtection(app) {
  const protecting = app.state !== "protected";
  $("modal-title").textContent = (protecting ? "Protect " : "Unprotect ") + app.name + "?";
  const body = $("modal-body");
  body.replaceChildren();
  if (protecting) {
    body.append(el("p", "flush", "Warden will:"));
    const list = el("ol");
    list.append(el("li", null, "back up " + app.name + "'s config file,"));
    list.append(el("li", null, "move its tools behind Warden (kept in your private Warden folder),"));
    list.append(el("li", null, "make " + app.name + " talk only to Warden."));
    body.append(list, el("p", "muted", "You can undo this any time with Unprotect."));
  } else {
    body.append(el("p", "flush", app.name + " will talk to its tools directly again, without Warden checking them."));
    body.append(el("p", "muted", "A backup of its config is made first."));
  }
  $("modal-ok").textContent = protecting ? "Protect" : "Unprotect";
  $("modal-ok").className = "btn " + (protecting ? "primary" : "danger");
  pendingConfirm = async () => {
    const result = await api.toggle_protection(app.id);
    showResult(result);
    refreshStatus();
  };
  $("modal").hidden = false;
  $("modal-cancel").focus();
}

function showResult(result) {
  $("modal-title").textContent = result.ok ? "Done" : "Nothing was changed";
  const body = $("modal-body");
  body.replaceChildren();
  for (const line of result.lines) body.append(el("p", "flush", line));
  $("modal-ok").textContent = "OK";
  $("modal-ok").className = "btn primary";
  $("modal-cancel").hidden = true;
  pendingConfirm = null;
  $("modal").hidden = false;
}

function closeModal() {
  $("modal").hidden = true;
  $("modal-cancel").hidden = false;
}

// ---------- History ----------
const BADGES = {
  "ATTACK FOUND": "bad", "BLOCKED": "bad", "TOOL HIDDEN": "bad",
  "NEEDED OK": "warn", "YOU ALLOWED": "info", "allowed": "none",
};
let lastHistoryKey = null;

async function refreshHistory() {
  const events = await api.get_history(showAll);
  const key = showAll + ":" + (events[0] ? events[0].id : "") + ":" + events.length;
  if (key === lastHistoryKey) return;          // nothing new: keep open items open
  lastHistoryKey = key;

  const list = $("events");
  list.replaceChildren();
  if (!events.length) {
    list.append(el("div", "card empty", showAll ? "Nothing logged yet." : "Warden hasn't had to step in yet."));
    return;
  }
  for (const e of events) {
    const card = el("div", "card event");
    const head = el("button", "event-head");
    head.append(el("span", "pill " + (BADGES[e.badge] || "none"), e.badge.toUpperCase()));
    const title = el("span", "event-title", e.title);
    title.dir = "auto";
    head.append(title, el("span", "event-time", e.when));
    const body = el("div", "event-body");
    body.hidden = true;
    const story = el("p", "story", e.story || "No story for this action.");
    story.dir = "auto";                          // Arabic stories display right-to-left
    body.append(story, el("div", "details", e.details));
    head.addEventListener("click", () => { body.hidden = !body.hidden; });
    card.append(head, body);
    list.append(card);
  }
}

// ---------- Attack Lab ----------
let labTimer = null;

async function runLab() {
  const started = await api.run_lab($("lab-ai").checked);
  if (!started) return;
  $("lab-run").disabled = true;
  $("lab-progress").hidden = false;
  $("lab-output").textContent = "";
  $("lab-details").open = true;
  labTimer = setInterval(pollLab, 500);
}

async function pollLab() {
  const state = await api.lab_poll();
  if (state.lines.length) $("lab-output").textContent += state.lines.join("");
  $("lab-output").scrollTop = $("lab-output").scrollHeight;
  if (state.running) return;
  clearInterval(labTimer);
  $("lab-run").disabled = false;
  $("lab-progress").hidden = true;
  if (state.score) {
    $("lab-score").hidden = false;
    $("score-stopped").textContent = state.score.stopped;
    $("score-blocked").textContent = state.score.blocked;
    $("score-missed").textContent = state.score.missed;
    $("score-safe").textContent = state.score.safe;
    $("lab-details").open = false;
  }
}

// ---------- start ----------
function start(backend) {
  api = backend;
  for (const button of document.querySelectorAll(".nav")) {
    button.addEventListener("click", () => showPage(button.dataset.page));
  }
  $("recheck").addEventListener("click", refreshStatus);
  for (const button of document.querySelectorAll("#history-filter button")) {
    button.addEventListener("click", () => {
      showAll = button.dataset.all === "1";
      for (const b of document.querySelectorAll("#history-filter button")) b.classList.toggle("active", b === button);
      refreshHistory();
    });
  }
  $("lab-run").addEventListener("click", runLab);
  $("modal-cancel").addEventListener("click", closeModal);
  $("modal-ok").addEventListener("click", async () => {
    const action = pendingConfirm;
    closeModal();
    if (action) await action();
  });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeModal(); });

  refreshStatus();
  refreshHistory();
  setInterval(refreshStatus, 15000);
  setInterval(() => { if (!$("page-history").hidden) refreshHistory(); }, 3000);
}

// Real app: pywebview injects window.pywebview.api. Preview in a browser: add ?demo to the URL.
if (window.location.search.includes("demo") && window.WardenDemo) {
  start(window.WardenDemo);
} else {
  window.addEventListener("pywebviewready", () => start(window.pywebview.api));
}
