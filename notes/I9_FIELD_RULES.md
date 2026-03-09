# I-9 Field Rules

The I-9 PDF field mappings for List A, List B, and List C use these exact field names:

- `LIST A DOCUMENT TITLE`
- `LIST A ISSUING AUTHORITY`
- `LIST A DOCUMENT NUMBER (IF ANY)`
- `LIST A EXPIRATION DATE (IF ANY)`
- `LIST B DOCUMENT TITLE`
- `LIST B ISSUING AUTHORITY`
- `LIST B DOCUMENT NUMBER (IF ANY)`
- `LIST B EXPIRATION DATE (IF ANY)`
- `LIST C DOCUMENT TITLE`
- `LIST C ISSUING AUTHORITY`
- `LIST C DOCUMENT NUMBER (IF ANY)`
- `LIST C EXPIRATION DATE (IF ANY)`

Citizenship and immigration conditional rules:

- If the employee selects `An alien authorized to work until`, show `Alien To Work Expiration (If Any)` and map it to `ALIEN TO WORK EXPIRATION (IF ANY)`.
- For `An alien authorized to work until`, exactly one of these identifiers must be filled:
  - `USCIS NUMBER`
  - `FORM I94 ADMISSION NUMBER`
  - `FOREIGN PASSPORT NUMBER OR COUNTRY OF ISSUANCE`
- If the employee selects `A lawful permanent resident`, show `USCIS Number` and `A-Number`.
- For `A lawful permanent resident`, exactly one of `USCIS Number` or `A-Number` must be filled.
- The lawful permanent resident identifier is currently written into the PDF field named `FOREIGN PASSPORT NUMBER OR COUNTRY OF ISSUANCE`.

Implementation expectations:

- The UI must hide and disable irrelevant status-specific fields unless their matching citizenship status is selected.
- The client and server must both enforce the exact-one-of rules so invalid combinations cannot be submitted into the generated I-9 PDF.
