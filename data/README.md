# QueryShield evaluation dataset

A labelled set of SQL-injection payloads and benign inputs used to measure the
detector honestly: detection rate (recall), false-positive rate, precision and
a confusion matrix (Phase 5 onward).

> All payloads are generic, textbook forms used only to test QueryShield
> against its own localhost demo app. Nothing here is novel, targeted, or a
> working exploit against any real system.

## Files

| File | What it is |
|------|------------|
| `build_dataset.py` | The source of truth. Holds every payload and writes the two CSVs with a deterministic split. |
| `attacks.csv` | Attack payloads (should be detected). |
| `benign.csv` | Benign inputs (must **not** be flagged), including hard negatives. |

Regenerate at any time — the output is byte-identical because the split is
seeded:

```bash
python3 data/build_dataset.py
```

## Columns

`id, input, label, category, split`

- `id` — stable identifier (`a001…` attacks, `b001…` benign).
- `input` — the raw field value, exactly as it would arrive in a request
  (still URL-encoded where that is the point, e.g. the `encoded` category).
- `label` — `attack` or `benign`.
- `category` — technique (attacks) or kind of hard negative (benign).
- `split` — `dev` or `test` (see below).

## Counts

Produced by `build_dataset.py` (re-run it to reproduce these numbers):

| File | Rows | dev | test |
|------|-----:|----:|----:|
| attacks.csv | 103 | 55 | 48 |
| benign.csv | 102 | 55 | 47 |
| **total** | **205** | **110** | **95** |

Attack categories (count): tautology 13, union 13, error 13, boolean 13,
time 13, stacked 13, comment 13, encoded 12.

Benign categories include the hard negatives that keep the false-positive rate
meaningful: apostrophe names (`O'Brien`, `D'Souza`), brand names (`Levi's`,
`McDonald's`), prose containing SQL keywords (`union station timetable`,
`select your seat`, `drop-down menu`, `order by phone or email`), `or`/`and`
sentences, maths that looks like a tautology (`1=1`, `2+2=4`), `--` used as a
dash, `#` used as a hashtag (`C#`, `#throwback`), emails, contractions
(`it's`, `don't`), JSON-ish text, semicolon lists, and comment-like text
(`/* note to self */`).

## The dev/test split (why it exists and how it works)

Rules and weights are tuned **only on the `dev` rows**. Final numbers are
reported **only on the untouched `test` rows**. This is the difference between
"my detector scores well" and "my detector scores well *on data I tuned it
against*", which would be meaningless. Keeping the split in the committed CSV —
rather than re-rolling it at runtime — means the test rows are fixed in git
history and cannot quietly leak into tuning.

**Method** (`assign_splits` in `build_dataset.py`): within each category the
rows are shuffled with a per-category seeded RNG (`SEED = 20261107`), then
assigned `dev`/`test` alternately. Shuffling first makes the split independent
of authoring order; alternating guarantees each category is 50/50, off by at
most one row for an odd count. Because the RNG is seeded, the assignment is
identical on every run — verified by regenerating and diffing.

Stratifying by category matters because the categories are not equally easy:
reporting on a test set that happened to contain only tautologies would
overstate recall. Equal dev/test representation per category keeps both splits
representative.

## Sources

Payloads are standard forms drawn from well-known public references. They are
idiomatic techniques, not copied text:

- OWASP — *SQL Injection* and the OWASP Web Security Testing Guide.
  <https://owasp.org/www-community/attacks/SQL_Injection>
- PortSwigger Web Security Academy — *SQL injection cheat sheet*.
  <https://portswigger.net/web-security/sql-injection/cheat-sheet>
- PayloadsAllTheThings — *SQL Injection*.
  <https://github.com/swisskyrepo/PayloadsAllTheThings>

Some payloads use dialect-specific functions (e.g. `WAITFOR DELAY` and
`xp_cmdshell` for SQL Server, `pg_sleep` for PostgreSQL, `utl_inaddr` for
Oracle). They are included because the detector matches on the *signature*
regardless of backend; the demo app itself is MySQL, so those particular
payloads are not expected to execute there — only to be recognised.
