<!-- bdr-seed-format: 1 -->
<!-- bdr-cli-version: 0.2.0 -->

# BDR Project Seed

This file is machine-oriented context for code agents and LLMs working in this repository.
It describes how to write and validate `.bdr` automation scripts correctly.

## Source Of Truth

- CLI version: `0.2.0`
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

## Generation Checklist For LLMs

When generating or editing `.bdr` scripts:

1. Use only valid BDR syntax (no Python/JS mixed in).
2. Prefer CSS selectors that are stable (`#id`, `[name=]`, semantic classes).
3. Put reusable flows into `func ... { ... }` blocks.
4. Keep each function focused on one task.
5. If reusing helpers, place them in a shared `.bdr` file and load with `exec(...)`.
6. Run `bdr check` and fix all errors before `bdr run`.
7. Use `screenshot(...)` at key checkpoints for debugging.

## Common Errors To Avoid

- Missing `$` on variable declarations.
- Using unsupported command names.
- Calling functions with wrong argument count.
- Forgetting to `exec(...)` helper files before use.
- Assuming functions return values.

## Validation Workflow

```bash
bdr check script.bdr
bdr run script.bdr
```

If this seed file version does not match the installed CLI version, regenerate it:

```bash
bdr seed
```
