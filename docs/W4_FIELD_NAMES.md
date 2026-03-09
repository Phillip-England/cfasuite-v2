# W-4 PDF Field Name Reference

This project populates the following W-4 PDF text fields:

- `2200 SUM`
  - Value: total dollar amount for dependents under 17.
  - Formula: `under17_count * 2200`.
  - Example: `3` under 17 -> `6600`.

- `500 SUM`
  - Value: total dollar amount for other dependents (over 17).
  - Formula: `over17_count * 500`.
  - Example: `2` over 17 -> `1000`.

- `2200 AND 500 SUM`
  - Value: combined dependent credit amount.
  - Formula: `("2200 SUM") + ("500 SUM")`.
  - Example: `6600 + 1000 = 7600`.

- `OTHER INCOME`
  - Value: employee's other income amount from the W-4 form.

- `DEDUCTIONS`
  - Value: employee's deductions amount from the W-4 form.

- `EXTRA WITHOLDING`
  - Value: employee's extra withholding amount from the W-4 form.

## Notes

- The code also fills legacy/internal template field aliases for backward compatibility.
- The canonical names above are the ones to validate against for the current `docs/w4.pdf`.
