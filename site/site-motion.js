(function () {
  "use strict";

  function ready(callback) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", callback);
    else callback();
  }

  ready(function () {
    var body = document.body;
    var reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var progress = document.getElementById("progress-bar");
    var nav = document.querySelector(".site-nav");
    var navToggle = document.querySelector(".site-nav__toggle");
    var navLinks = document.querySelector(".site-nav__links");

    function closeNav() {
      if (!navToggle || !navLinks) return;
      navLinks.classList.remove("is-open");
      navToggle.setAttribute("aria-expanded", "false");
    }

    if (navToggle && navLinks) {
      navToggle.addEventListener("click", function () {
        var open = !navLinks.classList.contains("is-open");
        navLinks.classList.toggle("is-open", open);
        navToggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
      navLinks.querySelectorAll("a").forEach(function (link) { link.addEventListener("click", closeNav); });
      document.addEventListener("keydown", function (event) { if (event.key === "Escape") closeNav(); });
    }

    document.querySelectorAll(".site-nav__links a").forEach(function (link) {
      var href = link.getAttribute("href") || "";
      if (href.startsWith("/") && href !== "/" && window.location.pathname.startsWith(href)) {
        link.setAttribute("aria-current", "page");
      }
    });

    function updatePageState() {
      var scrollable = document.documentElement.scrollHeight - window.innerHeight;
      var ratio = scrollable > 0 ? window.scrollY / scrollable : 0;
      if (progress) progress.style.transform = "scaleX(" + Math.min(1, ratio) + ")";
      if (nav) nav.classList.toggle("is-scrolled", window.scrollY > 18);
    }

    updatePageState();
    window.addEventListener("scroll", updatePageState, { passive: true });
    window.addEventListener("resize", updatePageState, { passive: true });

    /* Shared copy behavior — single owner for every copy affordance.
       (Replaces the copy handlers formerly duplicated in app.js.) */
    function flashCopied(button) {
      var original = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(function () { button.textContent = original; }, 1400);
    }

    document.addEventListener("click", function (event) {
      var button = event.target.closest("[data-copy-block], [data-copy]");
      if (!button) return;
      var text = "";
      if (button.hasAttribute("data-copy")) {
        var target = document.getElementById(button.getAttribute("data-copy"));
        if (!target) return;
        text = target.textContent || "";
      } else {
        var block = button.closest(".mini-terminal, .terminal-box, .terminal-frame, .code-shell, .evidence-paper");
        if (!block) return;
        var clone = block.cloneNode(true);
        clone.querySelectorAll("button").forEach(function (b) { b.remove(); });
        text = (clone.textContent || "").replace(/\n{3,}/g, "\n\n").trim();
      }
      navigator.clipboard.writeText(text).then(function () { flashCopied(button); });
    });

    /* Every code block gets a copy affordance (bare <pre> included —
       docs pages rely on this; formerly app.js enhanceCodeCopy). */
    document.querySelectorAll("pre, .code-output").forEach(function (block) {
      if (block.dataset.copyEnhanced === "true") return;
      if (block.closest(".code-shell, .mini-terminal, .terminal-body, .msg")) return;
      block.dataset.copyEnhanced = "true";
      var shell = document.createElement("div");
      shell.className = "code-shell";
      block.parentNode.insertBefore(shell, block);
      shell.appendChild(block);

      var copy = document.createElement("button");
      copy.type = "button";
      copy.className = "code-shell__copy";
      copy.textContent = "Copy";
      copy.setAttribute("aria-label", "Copy code to clipboard");
      copy.addEventListener("click", function () {
        navigator.clipboard.writeText(block.textContent || "").then(function () {
          copy.textContent = "Copied";
          window.setTimeout(function () { copy.textContent = "Copy"; }, 1400);
        });
      });
      shell.appendChild(copy);
    });

    if (body.classList.contains("route-home") || reducedMotion) return;

    var revealTargets = document.querySelectorAll(
      ".workspace > .g, .workspace > .hero, .blog-shell > *, .pricing-grid, .faq, .chat-container, .not-found"
    );
    revealTargets.forEach(function (target) { target.classList.add("site-reveal"); });

    if (!("IntersectionObserver" in window)) {
      revealTargets.forEach(function (target) { target.classList.add("is-visible"); });
      return;
    }

    document.documentElement.classList.add("site-motion-ready");
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.08, rootMargin: "0px 0px -5% 0px" });
    revealTargets.forEach(function (target) { observer.observe(target); });

    document.querySelectorAll(
      ".g, .card, .post-card, .pricing-card, .metric-card, .risk-badge, .control-map-row"
    ).forEach(function (surface) {
      surface.classList.add("site-interactive-surface");
      surface.addEventListener("pointermove", function (event) {
        var rect = surface.getBoundingClientRect();
        surface.style.setProperty("--surface-x", event.clientX - rect.left + "px");
        surface.style.setProperty("--surface-y", event.clientY - rect.top + "px");
      });
    });
  });
})();
