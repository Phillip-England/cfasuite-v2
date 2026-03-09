# Tailwind-Only Policy

This project uses **Tailwind CSS as the default styling system**.

## Rules
- Prefer Tailwind utility classes in templates and components.
- Do not add new custom CSS blocks unless Tailwind cannot express the requirement.
- Do not add inline `style="..."` attributes for normal styling.
- In JavaScript, prefer toggling Tailwind classes (`classList.add/remove/toggle`) instead of writing inline styles via `element.style.*`.
- If custom CSS is unavoidable, keep it minimal, scoped, and document why in the PR/commit notes.

## Allowed Exceptions (Niche/Functional)
- Browser quirks that utilities cannot solve safely.
- Third-party widgets that require specific CSS hooks.
- Complex keyframes/animations that cannot be represented cleanly with utilities.
- Accessibility or print-specific adjustments that need targeted selectors.

## Navigation/Dashboard Guidance
- Header should not be used as the primary nav surface.
- Navigation links should live in the side drawer/menu and remain full-width, using Tailwind classes.

## Build & Fresh CSS
- Always rebuild Tailwind output before app startup.
- Dev startup should compile `internal/clientapp/assets/tailwind.input.css` into `internal/clientapp/assets/app.css`.
- File watching should include Tailwind inputs/config and templates, while excluding generated `app.css` to avoid rebuild loops.
