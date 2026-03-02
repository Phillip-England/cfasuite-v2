(() => {
  const baseClass = "qa";
  const classByTag = {
    header: "qa-header",
    main: "qa-main",
    aside: "qa-aside",
    footer: "qa-footer",
    article: "qa-article",
    div: "qa-div",
    button: "qa-btn",
    a: "qa-link",
    input: "qa-input",
    select: "qa-select",
    textarea: "qa-textarea",
    form: "qa-form",
    section: "qa-section",
    nav: "qa-nav",
    table: "qa-table",
  };
  const idPrefixByTag = {
    header: "header",
    main: "main",
    aside: "aside",
    footer: "footer",
    article: "article",
    div: "div",
    button: "btn",
    a: "link",
    input: "input",
    select: "select",
    textarea: "text",
    form: "form",
    section: "section",
    nav: "nav",
    table: "table",
  };

  function slugify(value) {
    return (value || "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 32);
  }

  function pageSlug() {
    const path = (window.location.pathname || "/")
      .replace(/^\/+|\/+$/g, "")
      .replace(/\//g, "-");
    return slugify(path || "home") || "home";
  }

  function getText(el) {
    if (!el) return "";
    return (el.textContent || "")
      .trim()
      .replace(/\s+/g, " ");
  }

  function guessBase(el, index) {
    const attrs = [
      "data-panel-target",
      "data-panel-name",
      "data-target",
      "data-process-target",
      "data-process-panel",
      "data-sub-target",
      "data-sub-panel",
      "data-app-tab",
      "data-sub-tab",
      "aria-label",
      "name",
      "placeholder",
      "title",
      "id",
    ];
    for (const attr of attrs) {
      const value = slugify(el.getAttribute(attr));
      if (value) return value;
    }
    if (el.tagName.toLowerCase() === "a") {
      const href = (el.getAttribute("href") || "").split("?")[0].split("#")[0];
      const hrefBase = slugify(href.split("/").filter(Boolean).slice(-2).join("-"));
      if (hrefBase) return hrefBase;
    }
    const textBase = slugify(getText(el));
    if (textBase) return textBase;
    return `item-${index + 1}`;
  }

  function ensureClasses(el) {
    el.classList.add(baseClass);
    const tagClass = classByTag[el.tagName.toLowerCase()];
    if (tagClass) el.classList.add(tagClass);
  }

  function ensureId(el, usedIds, index, page) {
    if (el.id) {
      usedIds.add(el.id);
      el.setAttribute("data-e2e-id", el.id);
      return;
    }
    const tag = el.tagName.toLowerCase();
    const prefix = idPrefixByTag[tag] || "el";
    const base = guessBase(el, index) || "item";
    let candidate = `e2e-${page}-${prefix}-${base}`;
    let n = 2;
    while (usedIds.has(candidate) || document.getElementById(candidate)) {
      candidate = `e2e-${page}-${prefix}-${base}-${n}`;
      n += 1;
    }
    el.id = candidate;
    el.setAttribute("data-e2e-id", candidate);
    usedIds.add(candidate);
  }

  function annotate() {
    const page = pageSlug();
    const targets = Array.from(
      document.querySelectorAll("header, main, aside, footer, article, nav, form, section, table, button, a, input:not([type='hidden']), select, textarea, [role='tab'], [role='dialog'], [role='menuitem']")
    );
    const indexByTag = {};
    const usedIds = new Set(
      Array.from(document.querySelectorAll("[id]"))
        .map((el) => el.id)
        .filter(Boolean)
    );
    document.body.classList.add("qa-page");
    document.body.setAttribute("data-e2e-page", page);
    targets.forEach((el, index) => {
      const tag = el.tagName.toLowerCase();
      const next = (indexByTag[tag] || 0) + 1;
      indexByTag[tag] = next;
      el.setAttribute("data-e2e", `${tag}-${next}`);
      ensureClasses(el);
      ensureId(el, usedIds, index, page);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", annotate);
    return;
  }
  annotate();
})();
