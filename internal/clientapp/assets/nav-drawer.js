(function () {
  var DESKTOP_BREAKPOINT = 768;
  var LOGO_LIGHT_SRC = "/assets/logo-light.png";
  var LOGO_DARK_SRC = "/assets/logo-dark.png";
  var LOGO_POSITION_CLASSES = [
    "fixed",
    "top-3",
    "left-3",
    "z-[1200]",
    "inline-flex",
    "items-center",
    "justify-start"
  ];

  function initSharedBranding() {
    pinThemeToggleTopRight();
    replaceHeaderBrandWithLogo();
    replacePublicNavBrandWithLogo();
  }

  function initMobileDrawer() {
    initSharedBranding();

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
    pinNavToggleTopRight(navToggle);
    var drawerLinks = setupDrawerPanel(navMobile);
    flattenDrawerLinks(drawerLinks);
    moveHeaderLinksIntoDrawer(navMobile, drawerLinks);

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

    function syncDrawerMode() {
      var desktop = isDesktop();
      var open = navMobile.classList.contains("is-open");

      navMobile.classList.toggle("desktop-drawer", desktop);

      if (desktop) {
        // Desktop menu is always open and always pushes content.
        if (closeTimeout) {
          window.clearTimeout(closeTimeout);
          closeTimeout = null;
        }
        navMobile.classList.remove("hidden");
        navMobile.classList.add("is-open");
        document.body.classList.add("nav-drawer-desktop-open");
        document.body.classList.remove("nav-drawer-open");
        setExpanded(true);
        syncThemeToggleForViewport();
        return;
      }

      document.body.classList.toggle("nav-drawer-open", open);
      document.body.classList.remove("nav-drawer-desktop-open");
      syncThemeToggleForViewport();
    }

    function openDrawer() {
      if (isDesktop()) {
        syncDrawerMode();
        return;
      }
      if (closeTimeout) {
        window.clearTimeout(closeTimeout);
        closeTimeout = null;
      }

      navMobile.classList.remove("hidden");
      window.requestAnimationFrame(function () {
        navMobile.classList.add("is-open");
        syncDrawerMode();
      });
      setExpanded(true);
      syncThemeToggleForViewport();
    }

    function closeDrawer() {
      if (isDesktop()) {
        syncDrawerMode();
        return;
      }
      if (closeTimeout) {
        window.clearTimeout(closeTimeout);
        closeTimeout = null;
      }

      navMobile.classList.remove("is-open");
      document.body.classList.remove("nav-drawer-open", "nav-drawer-desktop-open");
      setExpanded(false);
      syncThemeToggleForViewport();

      closeTimeout = window.setTimeout(function () {
        if (!navMobile.classList.contains("is-open")) {
          navMobile.classList.add("hidden");
        }
      }, 240);
    }

    function syncThemeToggleForViewport() {
      var toggle = document.getElementById("theme-toggle");
      if (!toggle) {
        return;
      }
      if (isDesktop()) {
        toggle.classList.remove("hidden");
        toggle.style.right = "0.75rem";
        toggle.style.left = "auto";
        return;
      }
      // On mobile keep theme toggle persistently next to the menu button/X.
      toggle.classList.remove("hidden");
      toggle.style.right = "3.5rem";
      toggle.style.left = "auto";
    }

    navToggle.addEventListener("click", function (event) {
      event.preventDefault();
      if (isDesktop()) {
        return;
      }
      if (navMobile.classList.contains("is-open")) {
        closeDrawer();
      } else {
        openDrawer();
      }
    });

    navMobile.addEventListener("click", function (event) {
      if (isDesktop()) {
        return;
      }
      if (event.target === navMobile) {
        closeDrawer();
      }
    });

    Array.prototype.forEach.call(navMobile.querySelectorAll("a"), function (link) {
      link.addEventListener("click", function () {
        if (!isDesktop()) {
          closeDrawer();
        }
      });
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && !isDesktop()) {
        closeDrawer();
      }
    });

    var resizeTimer = null;
    var wasDesktop = isDesktop();
    window.addEventListener("resize", function () {
      if (resizeTimer) {
        window.clearTimeout(resizeTimer);
      }
      resizeTimer = window.setTimeout(function () {
        var desktop = isDesktop();
        if (desktop !== wasDesktop) {
          wasDesktop = desktop;
          if (desktop) {
            syncDrawerMode();
          } else {
            closeDrawer();
            syncDrawerMode();
          }
        }
      }, 80);
    });

    // Ensure initial state and no overflow clipping.
    if (panel) {
      panel.scrollTop = 0;
    }
    if (isDesktop()) {
      syncDrawerMode();
    } else {
      closeDrawer();
      syncDrawerMode();
    }
    syncThemeToggleForViewport();
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

  function pinThemeToggleTopRight() {
    var toggle = document.getElementById("theme-toggle");
    if (!toggle) {
      return;
    }

    toggle.classList.add(
      "fixed",
      "top-3",
      "right-3",
      "z-[1200]",
      "h-8",
      "w-8",
      "inline-flex",
      "items-center",
      "justify-center",
      "rounded-md",
      "border",
      "border-zinc-200",
      "dark:border-zinc-700",
      "bg-white/90",
      "dark:bg-zinc-900/90",
      "text-zinc-500",
      "dark:text-zinc-400",
      "hover:bg-zinc-100",
      "dark:hover:bg-zinc-800",
      "transition-colors",
      "backdrop-blur"
    );
    toggle.style.right = "0.75rem";
    toggle.style.left = "auto";
  }

  function pinNavToggleTopRight(navToggle) {
    if (!navToggle) {
      return;
    }

    navToggle.classList.add(
      "fixed",
      "top-3",
      "right-3",
      "z-[1200]"
    );
  }

  function replaceHeaderBrandWithLogo() {
    var header = document.querySelector("header.fixed");
    if (!header) {
      return;
    }

    var topRow = header.querySelector(".mx-auto > div:first-child");
    if (!topRow) {
      return;
    }

    var brandAnchor = topRow.querySelector("a");
    if (!brandAnchor) {
      return;
    }

    brandAnchor.removeAttribute("style");
    brandAnchor.classList.remove("text-sm", "font-bold", "text-zinc-900", "dark:text-zinc-100", "shrink-0");
    brandAnchor.classList.add.apply(brandAnchor.classList, LOGO_POSITION_CLASSES);
    renderLogoInto(brandAnchor);
  }

  function replacePublicNavBrandWithLogo() {
    var appNav = document.getElementById("app-nav");
    if (!appNav) {
      return;
    }

    var label = appNav.querySelector(".text-sm.font-extrabold");
    if (!label) {
      return;
    }

    label.classList.remove(
      "text-sm",
      "font-extrabold",
      "tracking-[0.06em]",
      "uppercase",
      "text-zinc-800",
      "dark:text-zinc-100"
    );
    label.classList.add.apply(label.classList, LOGO_POSITION_CLASSES);
    renderLogoInto(label);
  }

  function renderLogoInto(node) {
    if (!node) {
      return;
    }

    if (node.getAttribute("data-logo-applied") === "true") {
      return;
    }

    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }

    var lightLogo = document.createElement("img");
    lightLogo.src = LOGO_LIGHT_SRC;
    lightLogo.alt = "CFA Suite";
    lightLogo.className = "h-8 w-auto block dark:hidden";
    node.appendChild(lightLogo);

    var darkLogo = document.createElement("img");
    darkLogo.src = LOGO_DARK_SRC;
    darkLogo.alt = "CFA Suite";
    darkLogo.className = "h-8 w-auto hidden dark:block";
    node.appendChild(darkLogo);

    node.setAttribute("data-logo-applied", "true");
  }

  function moveHeaderLinksIntoDrawer(navMobile, drawerLinks) {
    if (!drawerLinks) {
      return;
    }

    var header = navMobile.closest("header.fixed") || document.querySelector("header.fixed");
    if (!header) {
      return;
    }

    var topRow = header.querySelector(".mx-auto > div:first-child");
    var brandAnchor = topRow ? topRow.querySelector("a") : header.querySelector("a");

    Array.prototype.forEach.call(header.querySelectorAll("a"), function (anchor) {
      if (anchor === brandAnchor) {
        return;
      }
      if (anchor.closest("#nav-mobile")) {
        return;
      }
      drawerLinks.appendChild(anchor);
    });

    dedupeAndNormalizeDrawerLinks(drawerLinks);
  }

  function dedupeAndNormalizeDrawerLinks(drawerLinks) {
    var seen = {};

    Array.prototype.forEach.call(drawerLinks.querySelectorAll("a"), function (anchor) {
      var href = (anchor.getAttribute("href") || "").trim();
      var label = (anchor.textContent || "").replace(/\s+/g, " ").trim().toLowerCase();
      var key = href + "|" + label;

      if (seen[key]) {
        if (anchor.parentNode) {
          anchor.parentNode.removeChild(anchor);
        }
        return;
      }
      seen[key] = true;

      anchor.classList.add("block", "w-full");
    });
  }

  function flattenDrawerLinks(drawerLinks) {
    if (!drawerLinks) {
      return;
    }

    var anchors = Array.prototype.slice.call(drawerLinks.querySelectorAll("a"));
    if (!anchors.length) {
      return;
    }

    while (drawerLinks.firstChild) {
      drawerLinks.removeChild(drawerLinks.firstChild);
    }

    anchors.forEach(function (anchor) {
      drawerLinks.appendChild(anchor);
    });
  }

  function setupDrawerPanel(navMobile) {
    if (navMobile.querySelector(".nav-drawer-panel")) {
      return navMobile.querySelector(".nav-drawer-links");
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
    return links;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initMobileDrawer);
  } else {
    initMobileDrawer();
  }
})();
