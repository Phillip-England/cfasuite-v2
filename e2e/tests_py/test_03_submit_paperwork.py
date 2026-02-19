from .helpers import (
    EMPLOYEES,
    close_browser,
    draw_signature,
    ensure_employee_exists,
    ensure_location_exists,
    launch_page,
    login_as_admin,
    open_employee_detail_by_name,
    upload_fixture_pdf,
)


def test_submit_paperwork() -> None:
    playwright, browser, page = launch_page()
    try:
        login_as_admin(page)
        ensure_location_exists(page)
        ensure_employee_exists(page, EMPLOYEES["paperwork"]["first_name"], EMPLOYEES["paperwork"]["last_name"])

        full_name = f"{EMPLOYEES['paperwork']['first_name']} {EMPLOYEES['paperwork']['last_name']}"
        open_employee_detail_by_name(page, full_name)

        page.click('.submenu-btn[data-target="paperwork-upload"]')
        page.wait_for_selector("#paperwork-link-input")

        paperwork_link = page.input_value("#paperwork-link-input")
        assert "/employee/paperwork/" in paperwork_link

        page.goto(paperwork_link, wait_until="networkidle")
        page.wait_for_selector("#paperwork-form")

        page.fill("#personal_middle_initial", "Q")
        page.fill("#personal_address", "111 Testing Ave")
        page.fill("#personal_city", "Nashville")
        page.fill("#personal_state", "TN")
        page.fill("#personal_zip", "37203")
        page.fill("#personal_email", "paperwork.e2e@example.com")

        page.fill("#personal_phone_1", "615")
        page.fill("#personal_phone_2", "555")
        page.fill("#personal_phone_3", "1234")

        page.fill("#personal_ssn_1", "123")
        page.fill("#personal_ssn_2", "45")
        page.fill("#personal_ssn_3", "6789")

        page.select_option("#personal_dob_month", "01")
        page.select_option("#personal_dob_day", "15")
        page.select_option("#personal_dob_year", "1998")
        page.select_option("#i9_status", "citizen")

        page.click("#show-legal")
        page.select_option("select[name='i9_document_list[]']", "a")
        page.fill("input[name='i9_document_title[]']", "U.S. Passport")
        page.fill("input[name='i9_document_issuing_authority[]']", "U.S. Department of State")
        page.fill("input[name='i9_document_number[]']", "A1234567")
        upload_fixture_pdf(page, "input[name='i9_document_file[]']")

        page.click("#show-w4")
        page.select_option("#w4_filing_status", "single")

        page.click("#show-signature")
        page.wait_for_selector("#i9-signature-pad")
        draw_signature(page, "#i9-signature-pad")

        with page.expect_navigation(wait_until="networkidle"):
            page.click("#paperwork-submit-btn")

        assert "/admin/locations/" in page.url
        assert "/employees/" in page.url

        page.click('.submenu-btn[data-target="paperwork-view"]')
        page.wait_for_function("() => document.body.innerText.includes('View Document')")
        body = page.inner_text("body")

        assert "I-9 FORM" in body
        assert "W-4 FORM" in body
    finally:
        close_browser(playwright, browser)
