(function () {
  "use strict";

  var endpoint = "https://plausible.io/api/event";
  var eventUrl = "https://readtheplan.dev/activation";
  var eventDomain = "readtheplan.dev";
  var allowedEvents = [
    "verify_change_click",
    "copy_install",
    "playground_run",
    "generate_ci",
    "setup_help_click"
  ];

  function trackActivation(eventName) {
    if (allowedEvents.indexOf(eventName) === -1) return false;
    if (typeof window.fetch !== "function") return false;

    var payload = { name: eventName, url: eventUrl, domain: eventDomain };
    window.fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify(payload),
      credentials: "omit",
      referrerPolicy: "no-referrer",
      keepalive: true
    }).catch(function () {});
    return true;
  }

  window.readtheplanTrack = trackActivation;

  document.addEventListener("click", function (event) {
    if (!event.target || typeof event.target.closest !== "function") return;
    var target = event.target.closest("[data-activation-event]");
    if (!target) return;
    trackActivation(target.getAttribute("data-activation-event"));
  });
})();
