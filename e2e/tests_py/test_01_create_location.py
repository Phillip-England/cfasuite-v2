from .helpers import (
    LOCATION_NAME,
    LOCATION_NUMBER,
    close_browser,
    ensure_location_exists,
    launch_page,
    login_as_admin,
)


def test_create_location() -> None:
    playwright, browser, page = launch_page()
    try:
        login_as_admin(page)
        ensure_location_exists(page)
        body = page.inner_text("body")
        assert LOCATION_NUMBER in body
        assert LOCATION_NAME in body
    finally:
        close_browser(playwright, browser)
