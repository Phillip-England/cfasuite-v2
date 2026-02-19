from .helpers import (
    EMPLOYEES,
    click_hub_button,
    close_browser,
    ensure_employee_exists,
    ensure_location_exists,
    goto_location_employees,
    launch_page,
    login_as_admin,
)


def test_create_employees() -> None:
    playwright, browser, page = launch_page()
    try:
        login_as_admin(page)
        ensure_location_exists(page)

        ensure_employee_exists(page, EMPLOYEES["paperwork"]["first_name"], EMPLOYEES["paperwork"]["last_name"])
        ensure_employee_exists(page, EMPLOYEES["ops"]["first_name"], EMPLOYEES["ops"]["last_name"])
        ensure_employee_exists(page, EMPLOYEES["front"]["first_name"], EMPLOYEES["front"]["last_name"])

        goto_location_employees(page)
        click_hub_button(page, "view-employees")
        body = page.inner_text("body")

        assert f"{EMPLOYEES['paperwork']['first_name']} {EMPLOYEES['paperwork']['last_name']}" in body
        assert f"{EMPLOYEES['ops']['first_name']} {EMPLOYEES['ops']['last_name']}" in body
        assert f"{EMPLOYEES['front']['first_name']} {EMPLOYEES['front']['last_name']}" in body
    finally:
        close_browser(playwright, browser)
