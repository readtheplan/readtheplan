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

    document.querySelectorAll("pre.code-output, pre.gen-block, .copyable-code pre").forEach(function (block) {
      if (block.parentElement && block.parentElement.classList.contains("code-shell")) return;
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
