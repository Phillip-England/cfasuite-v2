from .helpers import (
    CANDIDATES,
    click_hub_button,
    close_browser,
    create_and_open_candidate,
    ensure_location_exists,
    goto_candidates,
    launch_page,
    login_as_admin,
)


def _hire_candidate(first_name: str, last_name: str) -> None:
    playwright, browser, page = launch_page()
    try:
        login_as_admin(page)
        ensure_location_exists(page)
        create_and_open_candidate(page, first_name, last_name)

        page.click('.hub-btn[data-target="decision"]')
        page.wait_for_selector('form[action$="/decision"] button.btn-primary')

        with page.expect_navigation(wait_until="networkidle"):
            page.click('form[action$="/decision"] button.btn-primary')

        assert "/candidates" in page.url

        goto_candidates(page)
        click_hub_button(page, "archive")
        page.wait_for_selector("table tbody")
        body = page.inner_text("body")

        assert f"{first_name} {last_name}" in body
        assert "hired" in body.lower()
    finally:
        close_browser(playwright, browser)


def test_hire_candidates() -> None:
    _hire_candidate(CANDIDATES["one"]["first_name"], CANDIDATES["one"]["last_name"])
    _hire_candidate(CANDIDATES["two"]["first_name"], CANDIDATES["two"]["last_name"])
