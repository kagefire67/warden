// Warden approval popup.
// SECURITY: the request text comes from the AI's action (and may quote an attacker),
// so it is only ever inserted with textContent - never as HTML.
// Safe defaults: Deny has the keyboard focus, Escape = Deny, no answer in time = "timeout".

"use strict";

let api = null;
let answered = false;

function answer(decision) {
  if (answered) return;
  answered = true;
  document.getElementById("allow").disabled = true;
  document.getElementById("deny").disabled = true;
  api.answer(decision);
}

async function start(backend) {
  api = backend;
  const request = await api.get_request();
  document.getElementById("title").textContent = request.title || "An AI action needs your approval";
  document.getElementById("story").textContent = request.story || "";
  document.getElementById("details").textContent =
    "Tool: " + request.server + "/" + request.tool + "\nDetails: " + (request.arguments || "");

  document.getElementById("allow").addEventListener("click", () => answer("allow"));
  document.getElementById("deny").addEventListener("click", () => answer("deny"));
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") answer("deny"); });
  document.getElementById("deny").focus();

  // Countdown: a little shorter than Warden's own timeout, so the popup answers first.
  const total = Math.max(5, Math.floor((request.timeout || 60) - 2));
  let left = total;
  const tick = () => {
    if (answered) return;
    document.getElementById("countdown-text").textContent = "No answer = not allowed, in " + left + "s";
    document.getElementById("countdown-bar").style.width = (100 * left / total) + "%";
    if (left <= 0) { answer("timeout"); return; }
    left -= 1;
    setTimeout(tick, 1000);
  };
  tick();
}

if (window.location.search.includes("demo")) {
  start({
    get_request: async () => ({
      title: "Needs your approval: send an email to recruiter@talent.example",
      story: "The AI tried to send an email to recruiter@talent.example with the attachment cv.pdf. " +
             "The AI wants to send an email outside your trusted domains.",
      server: "email", tool: "send_email", arguments: "{\"to\": \"recruiter@talent.example\", \"attachment\": \"cv.pdf\"}",
      timeout: 60,
    }),
    answer: async (d) => console.log("answer:", d),
  });
} else {
  window.addEventListener("pywebviewready", () => start(window.pywebview.api));
}
