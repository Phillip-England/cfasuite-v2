<!-- bdr-seed-format: 1 -->
<!-- bdr-cli-version: 0.3.0 -->

# BDR Project Seed

This file is machine-oriented context for code agents and LLMs working in this repository.
It describes how to write and validate `.bdr` automation scripts correctly.

## Source Of Truth

- CLI version: `0.3.0`
- Primary docs: `README.md`
- Runtime entrypoint: `bdr/cli.py`
- Script parser: `bdr/lexer.py`
- Script runtime: `bdr/interpreter.py`

## What BDR Is

BDR is a browser automation DSL that runs `.bdr` scripts using Playwright.
Scripts are plain text and primarily use CSS selector chains for actions/assertions.

## CLI Quick Use

- `bdr run script.bdr`
- `bdr check script.bdr`
- `bdr new script.bdr`
- `bdr extract URL SELECTOR`

Use `bdr check` before `bdr run` when generating scripts automatically.

## Script Basics

- Comments: `//`, `/* ... */`, `#` (legacy style)
- Variables: `$name = "value"` (must include `$`)
- Settings: `timeout = 15000`, `slow = 0.3` (no `$`)
- Function calls: `command(arg1, arg2)`
- Element chain calls: `SELECTOR.action(args)`

## Core Syntax Patterns

```bdr
$url = "https://example.com/login"
timeout = 15000
slow = 0.2

load($url)
# load_clipboard()   # navigate using the URL currently in the clipboard
#email.fill("me@example.com")
#password.fill("hunter2")
#submit.click()
assert_title("Dashboard")
screenshot("done.png")
```

Element chain examples:

```bdr
#submit.click()
[name="q"].fill("playwright")
.result[0].assert_text("Playwright")
```

## Function Authoring (Required Pattern)

Functions are reusable command blocks with positional parameters.
Parameters must start with `$`. Functions do not return values.

```bdr
func login($email, $password) {
  #email.fill($email)
  #password.fill($password)
  #submit.click()
}

load("https://example.com/login")
login("me@example.com", "hunter2")
```

Function rules:

- Name format: lowercase letters, digits, underscores.
- Opening `{` must be on the same line as `func`.
- Nested function definitions are not supported.
- Wrong argument counts fail validation and runtime.
- Parameters and variables inside function bodies are local in scope.
- `timeout` and `slow` are session settings and are not local-scoped.

## Shared Functions Across Files

Use `exec(...)` to load shared function libraries before first call:

```bdr
exec("./shared/helpers.bdr")
login(env("EMAIL"), env("PASSWORD"))
```

## File Upload

Use `.upload(path)` on an `<input type="file">` element to attach a local file.
Multiple files can be uploaded at once with additional arguments.

```bdr
input[type="file"].upload("./docs/contract.pdf")
input[type="file"].upload("./docs/id-front.jpg", "./docs/id-back.jpg")
$doc = "./signed-form.pdf"
#doc-upload.upload($doc)
```

Paths are resolved relative to the script's directory.
Raises an error immediately if the file does not exist.

## Mouse Drawing / Signature Pads

Use `.draw()` on a canvas or signature-pad element to simulate a handwritten signature.

```bdr
// Default wave signature — covers the full element width
canvas.draw()
#signature-pad.draw()

// Custom path — space-separated relative "x,y" offsets from element top-left
canvas.draw("10,60 60,20 120,70 180,25 240,55")
```

Tips:
- The element must be visible before `.draw()` is called (use `.wait_visible()` if needed).
- For signature-pad libraries (e.g. `signature_pad.js`), target the `<canvas>` directly.
- Combine with `screenshot(...)` to capture the result for inspection.

## Generation Checklist For LLMs

When generating or editing `.bdr` scripts:

1. Use only valid BDR syntax (no Python/JS mixed in).
2. Prefer CSS selectors that are stable (`#id`, `[name=]`, semantic classes).
3. Put reusable flows into `func ... { ... }` blocks.
4. Keep each function focused on one task.
5. If reusing helpers, place them in a shared `.bdr` file and load with `exec(...)`.
6. Run `bdr check` and fix all errors before `bdr run`.
7. Use `screenshot(...)` at key checkpoints for debugging.
8. For file upload: use `.upload(path)` on `<input type="file">` — path resolves relative to script.
9. For canvas signatures: use `.draw()` for a default wave, or `.draw("x,y ...")` for custom path.

## Common Errors To Avoid

- Missing `$` on variable declarations.
- Using unsupported command names.
- Calling functions with wrong argument count.
- Forgetting to `exec(...)` helper files before use.
- Assuming functions return values.
- Using `.upload()` on a non-file-input element (must be `<input type="file">`).
- Calling `.draw()` before the canvas is visible (add `.wait_visible()` first if needed).

## Validation Workflow

```bash
bdr check script.bdr
bdr run script.bdr
```

If this seed file version does not match the installed CLI version, regenerate it:

```bash
bdr seed
```
