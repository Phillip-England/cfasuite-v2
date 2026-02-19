import os
import time
from pathlib import Path

from playwright.sync_api import Browser, Error, Page, Playwright, sync_playwright


BASE_URL = os.getenv("E2E_BASE_URL", "http://127.0.0.1:3000")
ADMIN_USERNAME = os.getenv("E2E_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("E2E_ADMIN_PASSWORD", "change-me-please")
RUN_ID = "".join(ch for ch in os.getenv("E2E_RUN_ID", "") or str(int(__import__("time").time())) if ch.isalnum() or ch in "_-")

LOCATION_NAME = f"E2E Location {RUN_ID}"
LOCATION_NUMBER = f"E2E-{RUN_ID}"

EMPLOYEES = {
    "paperwork": {"first_name": f"Paper{RUN_ID[-4:]}", "last_name": "Worker"},
    "ops": {"first_name": f"Ops{RUN_ID[-4:]}", "last_name": "Crew"},
    "front": {"first_name": f"Front{RUN_ID[-4:]}", "last_name": "Desk"},
}

CANDIDATES = {
    "one": {"first_name": f"Hire{RUN_ID[-4:]}", "last_name": "One"},
    "two": {"first_name": f"Hire{RUN_ID[-4:]}", "last_name": "Two"},
}


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name, "").strip().lower()
    if value == "":
        return default
    return value not in {"0", "false", "no"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def launch_page() -> tuple[Playwright, Browser, Page]:
    headless = _env_bool("E2E_HEADLESS", False)
    slow_mo = _env_int("E2E_SLOW_MO", 0 if headless else 250)
    channel = os.getenv("E2E_BROWSER_CHANNEL", "chrome").strip()
    playwright = sync_playwright().start()
    launch_kwargs: dict = {
        "headless": headless,
        "slow_mo": slow_mo,
        "args": ["--start-maximized"],
    }
    if channel:
        launch_kwargs["channel"] = channel
    try:
        browser = playwright.chromium.launch(**launch_kwargs)
    except Error:
        launch_kwargs.pop("channel", None)
        browser = playwright.chromium.launch(**launch_kwargs)
        channel = "chromium"
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()
    page.set_default_timeout(30_000)
    print(
        f"[e2e] browser launch: headless={headless} slow_mo={slow_mo} channel={channel or 'chromium'}",
        flush=True,
    )
    return playwright, browser, page


def close_browser(playwright: Playwright, browser: Browser) -> None:
    hold_ms = _env_int("E2E_HOLD_MS", 500)
    if hold_ms > 0:
        time.sleep(hold_ms / 1000)
    browser.close()
    playwright.stop()


def login_as_admin(page: Page) -> None:
    page.goto(f"{BASE_URL}/", wait_until="networkidle")
    page.fill('input[name="username"]', ADMIN_USERNAME)
    page.fill('input[name="password"]', ADMIN_PASSWORD)
    with page.expect_navigation(wait_until="networkidle"):
        page.click('button[type="submit"]')
    assert "/admin" in page.url


def ensure_location_exists(page: Page) -> None:
    page.goto(f"{BASE_URL}/admin", wait_until="networkidle")
    page.wait_for_selector("#create-location-form")

    if page.evaluate("(n) => document.body.innerHTML.includes(n)", LOCATION_NUMBER):
        return

    page.fill("#name", LOCATION_NAME)
    page.fill("#number", LOCATION_NUMBER)
    page.fill("#employer_rep_signature", "E2E Manager")
    page.fill("#business_name", "E2E Chick-fil-A LLC")
    page.fill("#business_street", "123 Test St")
    page.fill("#business_city", "Nashville")
    page.fill("#business_state", "TN")
    page.fill("#business_ein_1", "12")
    page.fill("#business_ein_2", "3456789")

    page.click("#submit-btn")
    page.wait_for_function("(n) => document.body.innerText.includes(n)", arg=LOCATION_NUMBER)


def goto_location_employees(page: Page) -> None:
    page.goto(f"{BASE_URL}/admin/locations/{LOCATION_NUMBER}/employees", wait_until="networkidle")
    page.wait_for_selector('section[data-panel="add-employees"] form', state="attached")


def goto_candidates(page: Page) -> None:
    page.goto(f"{BASE_URL}/admin/locations/{LOCATION_NUMBER}/candidates", wait_until="networkidle")
    page.wait_for_selector('section[data-panel="new-candidate"] form', state="attached")


def click_hub_button(page: Page, target: str) -> None:
    page.click(f'.hub-btn[data-target="{target}"]')


def ensure_employee_exists(page: Page, first_name: str, last_name: str) -> None:
    full_name = f"{first_name} {last_name}"
    goto_location_employees(page)
    click_hub_button(page, "view-employees")
    page.wait_for_selector('section[data-panel="view-employees"]', state="visible")

    links = page.locator("a.location-link")
    for i in range(links.count()):
        if links.nth(i).inner_text().strip() == full_name:
            return

    click_hub_button(page, "add-employees")
    page.fill('form[action$="/employees/create"] input[name="first_name"]', first_name)
    page.fill('form[action$="/employees/create"] input[name="last_name"]', last_name)
    with page.expect_navigation(wait_until="networkidle"):
        page.click('form[action$="/employees/create"] button[type="submit"]')


def open_employee_detail_by_name(page: Page, full_name: str) -> None:
    goto_location_employees(page)
    click_hub_button(page, "view-employees")
    page.wait_for_selector('section[data-panel="view-employees"]', state="visible")

    links = page.locator("a.location-link")
    clicked = False
    for i in range(links.count()):
        if links.nth(i).inner_text().strip().startswith(full_name):
            with page.expect_navigation(wait_until="networkidle"):
                links.nth(i).click()
            clicked = True
            break

    assert clicked
    assert "/employees/" in page.url


def create_and_open_candidate(page: Page, first_name: str, last_name: str) -> None:
    goto_candidates(page)
    click_hub_button(page, "new-candidate")

    page.fill('section[data-panel="new-candidate"] input[name="first_name"]', first_name)
    page.fill('section[data-panel="new-candidate"] input[name="last_name"]', last_name)

    with page.expect_navigation(wait_until="networkidle"):
        page.click('section[data-panel="new-candidate"] button[type="submit"]')

    click_hub_button(page, "interviews")
    page.wait_for_selector("#active-candidate-list")

    full_name = f"{first_name} {last_name}"
    cards = page.locator(".active-candidate-row")
    clicked = False
    for i in range(cards.count()):
        if cards.nth(i).get_attribute("data-search-name") == full_name:
            with page.expect_navigation(wait_until="networkidle"):
                cards.nth(i).click()
            clicked = True
            break

    assert clicked
    assert "/candidates/" in page.url


def upload_fixture_pdf(page: Page, selector: str) -> None:
    fixture_path = Path("docs/i9.pdf").resolve()
    page.set_input_files(selector, str(fixture_path))


def draw_signature(page: Page, selector: str) -> None:
    canvas = page.locator(selector)
    box = canvas.bounding_box()
    assert box is not None

    start_x = box["x"] + 40
    start_y = box["y"] + (box["height"] / 2)

    page.mouse.move(start_x, start_y)
    page.mouse.down()
    page.mouse.move(start_x + 100, start_y + 10, steps=12)
    page.mouse.move(start_x + 180, start_y - 8, steps=12)
    page.mouse.up()
