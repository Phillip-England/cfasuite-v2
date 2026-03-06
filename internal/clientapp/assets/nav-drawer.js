(function () {
  var DESKTOP_BREAKPOINT = 768;

  function initMobileDrawer() {
    var navMobile = document.getElementById("nav-mobile");
    var originalToggle = document.getElementById("nav-toggle");
    if (!navMobile || !originalToggle) {
      return;
    }

    // Replace the toggle node to drop any inline listeners attached by page templates.
    var navToggle = originalToggle.cloneNode(true);
    if (originalToggle.parentNode) {
      originalToggle.parentNode.replaceChild(navToggle, originalToggle);
    }

    setupToggleIcon(navToggle);
    setupDrawerPanel(navMobile);

    var panel = navMobile.querySelector(".nav-drawer-panel");

    var closeTimeout = null;

    function setExpanded(open) {
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
      navToggle.classList.toggle("is-open", open);
      navToggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    }

    function isDesktop() {
      return window.innerWidth >= DESKTOP_BREAKPOINT;
    }

    function openDrawer() {
      if (isDesktop()) {
        return;
      }
      if (closeTimeout) {
        window.clearTimeout(closeTimeout);
        closeTimeout = null;
      }

      navMobile.classList.remove("hidden");
      navMobile.style.display = "block";
      window.requestAnimationFrame(function () {
        navMobile.classList.add("is-open");
      });
      document.body.classList.add("nav-drawer-open");
      setExpanded(true);
    }

    function closeDrawer() {
      if (closeTimeout) {
        window.clearTimeout(closeTimeout);
        closeTimeout = null;
      }

      navMobile.classList.remove("is-open");
      document.body.classList.remove("nav-drawer-open");
      setExpanded(false);

      closeTimeout = window.setTimeout(function () {
        if (!navMobile.classList.contains("is-open")) {
          navMobile.classList.add("hidden");
          navMobile.style.removeProperty("display");
        }
      }, 240);
    }

    navToggle.addEventListener("click", function (event) {
      event.preventDefault();
      if (navMobile.classList.contains("is-open")) {
        closeDrawer();
      } else {
        openDrawer();
      }
    });

    navMobile.addEventListener("click", function (event) {
      if (event.target === navMobile) {
        closeDrawer();
      }
    });

    Array.prototype.forEach.call(navMobile.querySelectorAll("a"), function (link) {
      link.addEventListener("click", function () {
        closeDrawer();
      });
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        closeDrawer();
      }
    });

    var resizeTimer = null;
    window.addEventListener("resize", function () {
      if (resizeTimer) {
        window.clearTimeout(resizeTimer);
      }
      resizeTimer = window.setTimeout(function () {
        if (isDesktop()) {
          closeDrawer();
        }
      }, 80);
    });

    // Ensure initial state and no overflow clipping.
    if (panel) {
      panel.scrollTop = 0;
    }
    closeDrawer();
  }

  function setupToggleIcon(navToggle) {
    var label = navToggle.querySelector(".sr-only");
    if (!label) {
      label = document.createElement("span");
      label.className = "sr-only";
      label.textContent = "Open menu";
      navToggle.appendChild(label);
    }

    var icon = navToggle.querySelector(".nav-toggle-icon");
    if (icon) {
      return;
    }

    // Replace existing icon markup with controlled animated bars.
    Array.prototype.slice.call(navToggle.childNodes).forEach(function (node) {
      if (node !== label) {
        navToggle.removeChild(node);
      }
    });

    icon = document.createElement("span");
    icon.className = "nav-toggle-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.innerHTML = "<span></span><span></span><span></span>";
    navToggle.appendChild(icon);
  }

  function setupDrawerPanel(navMobile) {
    if (navMobile.querySelector(".nav-drawer-panel")) {
      return;
    }

    var panel = document.createElement("div");
    panel.className = "nav-drawer-panel";

    var links = document.createElement("div");
    links.className = "nav-drawer-links";

    while (navMobile.firstChild) {
      links.appendChild(navMobile.firstChild);
    }

    panel.appendChild(links);
    navMobile.appendChild(panel);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initMobileDrawer);
  } else {
    initMobileDrawer();
  }
})();
