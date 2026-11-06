#!/usr/bin/env python3
"""
Build the QueryShield evaluation dataset.

This script is the single source of truth for the labelled payloads. It holds
the attack and benign inputs (grouped by category, with the public cheat sheets
they come from cited in data/README.md), assigns a deterministic, stratified
50/50 dev/test split, and writes two committed CSVs:

    data/attacks.csv   ~attack payloads
    data/benign.csv    ~benign inputs, including hard negatives

Columns: id, input, label, category, split

Re-running produces byte-identical CSVs (the split is seeded), so the split can
never drift silently: `python3 data/build_dataset.py` and `git diff` must show
no change. Rules are tuned on the `dev` rows only; final numbers are reported on
the untouched `test` rows (see data/README.md).

Why a script and not hand-edited CSVs: the split must be reproducible and
auditable. Here the payloads are plain data and the split is one documented
algorithm, so anyone can regenerate and verify it.
"""

import csv
import os
import random
from collections import Counter, defaultdict

SEED = 20261107  # fixed so the split is reproducible; changing it reshuffles.

# ---------------------------------------------------------------------------
# Attack payloads, grouped by category. These are standard, textbook forms of
# each technique taken from well-known public references (OWASP, PortSwigger,
# PayloadsAllTheThings) -- see data/README.md for the citations. They are kept
# deliberately generic; nothing here is novel or targeted.
# ---------------------------------------------------------------------------
ATTACKS = {
    "tautology": [
        "' OR '1'='1",
        "' OR 1=1 -- ",
        "admin' -- ",
        "' OR 'a'='a",
        "\") OR (\"1\"=\"1",
        "' OR 1=1#",
        "1' OR '1'='1",
        "' OR 1=1 LIMIT 1 -- ",
        "\" OR \"\"=\"",
        "') OR ('x'='x",
        "' OR 'x'='x' -- ",
        "or 1=1",
        "' OR 1 -- ",
    ],
    "union": [
        "' UNION SELECT NULL -- ",
        "' UNION SELECT username, password FROM users -- ",
        "' UNION ALL SELECT NULL,NULL -- ",
        "' UNION SELECT 1,2,3 -- ",
        "-1 UNION SELECT 1,2,3",
        "' UNION SELECT table_name,NULL FROM information_schema.tables -- ",
        "' UNION SELECT @@version -- ",
        "' UNION SELECT NULL,concat(username,0x3a,password) FROM users -- ",
        "' UNION DISTINCT SELECT 1,2 -- ",
        "0' UNION SELECT schema_name FROM information_schema.schemata -- ",
        "' UNION SELECT NULL,NULL,NULL,NULL -- ",
        "1 UNION SELECT load_file('/etc/passwd')",
        "' UNION SELECT user(),database(),version() -- ",
    ],
    "error": [
        "' AND extractvalue(1,concat(0x7e,version())) -- ",
        "' AND updatexml(1,concat(0x7e,(SELECT database())),1) -- ",
        "' AND (SELECT 1 FROM(SELECT count(*),concat(version(),floor(rand(0)*2))x "
        "FROM information_schema.tables GROUP BY x)a) -- ",
        "' AND extractvalue(1,concat(0x7e,(SELECT user()))) -- ",
        "' procedure analyse(extractvalue(1,concat(0x7e,version())),1) -- ",
        "' AND exp(~(SELECT * FROM(SELECT version())x)) -- ",
        "' OR 1 GROUP BY concat(version(),floor(rand(0)*2)) HAVING min(0) -- ",
        "' AND gtid_subset(version(),1) -- ",
        "' AND 1=convert(int,(SELECT @@version)) -- ",
        "' AND json_keys((SELECT version())) -- ",
        "' AND extractvalue(1,concat(0x5c,(SELECT table_name "
        "FROM information_schema.tables LIMIT 1))) -- ",
        "' AND 1=cast((SELECT version()) as int) -- ",
        "' AND 1=utl_inaddr.get_host_address((SELECT user FROM dual)) -- ",
    ],
    "boolean": [
        "' AND 1=1 -- ",
        "' AND 1=2 -- ",
        "1 AND substring(version(),1,1)='8'",
        "' AND (SELECT substring(username,1,1) FROM users LIMIT 1)='a' -- ",
        "' AND length(database())>5 -- ",
        "' AND ascii(substr((SELECT database()),1,1))>64 -- ",
        "' OR exists(SELECT * FROM users) -- ",
        "' AND (SELECT count(*) FROM users)>0 -- ",
        "' AND 1=(SELECT 1 FROM users WHERE username='admin') -- ",
        "1' AND '1'='2",
        "' AND substring((SELECT password FROM users LIMIT 1),1,1)>'a' -- ",
        "' AND user() LIKE 'root%' -- ",
        "' AND (SELECT count(*) FROM information_schema.columns)>100 -- ",
    ],
    "time": [
        "' OR sleep(5) -- ",
        "' AND sleep(5) -- ",
        "1 AND sleep(5)",
        "'; WAITFOR DELAY '0:0:5' -- ",
        "' OR benchmark(10000000,sha1(1)) -- ",
        "' AND IF(1=1,sleep(5),0) -- ",
        "' RLIKE sleep(5) -- ",
        "' AND (SELECT * FROM (SELECT(sleep(5)))a) -- ",
        "1)) OR sleep(5)#",
        "' OR pg_sleep(5) -- ",
        "'; SELECT pg_sleep(5) -- ",
        "' AND IF(substring(user(),1,1)='r',sleep(5),0) -- ",
        "' || (SELECT sleep(5)) || '",
    ],
    "stacked": [
        "'; DROP TABLE users -- ",
        "'; INSERT INTO users VALUES ('x','y') -- ",
        "1; DROP TABLE products",
        "'; UPDATE users SET is_admin=1 WHERE username='alice' -- ",
        "'; DELETE FROM secrets -- ",
        "'; EXEC xp_cmdshell('whoami') -- ",
        "'; CREATE USER hacker -- ",
        "'; SHUTDOWN -- ",
        "1; SELECT sleep(5)",
        "'; TRUNCATE TABLE logs -- ",
        "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%' -- ",
        "'; ALTER TABLE users ADD COLUMN pwned int -- ",
        "'; INSERT INTO secrets(name,value) VALUES('x','y') -- ",
    ],
    "comment": [
        "'/**/OR/**/1=1 -- ",
        "admin'#",
        "' OR 1=1-- -",
        "UNION/**/SELECT/**/1,2",
        "' OR/**/'1'='1",
        "/*!50000UNION*/ /*!50000SELECT*/ 1,2",
        "' OR 1=1 -- comment",
        "';-- ",
        "' UNION/**/SELECT/**/NULL-- ",
        "'/*!50000 OR */1=1-- ",
        "'-- -",
        "' OR/*x*/1/*y*/=/*z*/1 -- ",
        "' OR 1=1;#",
    ],
    "encoded": [
        "%27%20OR%201=1--",
        "%2527%20OR%201=1--",
        "' OR 0x31=0x31 -- ",
        "uNiOn sElEcT 1,2",
        "' OR char(49)=char(49) -- ",
        "%55NION%20%53ELECT%201,2",
        "' oR 1=1%23",
        "＇ OR 1=1 -- ",
        "0x27206f7220313d3120",
        "%2555NION %2553ELECT",
        "%27%20OR%20%271%27%3D%271",
        "0x756e696f6e2073656c656374",
    ],
}

# ---------------------------------------------------------------------------
# Benign inputs, grouped by sub-category. Many are "hard negatives": ordinary
# text that contains SQL keywords, operators, quotes, comments or semicolons
# and must NOT be flagged. These are what keep the false-positive rate honest.
# ---------------------------------------------------------------------------
BENIGN = {
    "name_apostrophe": [
        "O'Brien",
        "D'Souza",
        "O'Connor",
        "D'Angelo",
        "Sarah O'Neil",
        "Patrick O'Brien",
        "Shaquille O'Neal",
        "N'Golo Kante",
        "Conor O'Sullivan",
        "Flannery O'Connor",
    ],
    "keyword_in_prose": [
        "union station timetable",
        "select your seat",
        "drop-down menu",
        "order by phone or email",
        "update your profile picture",
        "insert your card to pay",
        "please delete the old file",
        "we are having fun today",
        "table for two at seven",
        "join us for dinner",
        "from here to there",
        "where are you going",
        "group photo after lunch",
        "the grand union canal",
        "left join the queue",
        "natural selection documentary",
        "drop a line when you arrive",
        "union jack flag",
        "having said that, let's begin",
        "the order was delivered today",
        "select all that apply",
    ],
    "or_and_prose": [
        "rain or shine we go",
        "cats and dogs",
        "now or never",
        "bread and butter",
        "true or false quiz",
        "coffee or tea",
        "salt and pepper",
        "this or that game",
    ],
    "math_text": [
        "1=1",
        "2+2=4",
        "a=b and b=c",
        "x = y in algebra",
        "the equation 1=1 is always true",
    ],
    "dash_as_dash": [
        "pre-- order now",
        "wait -- what happened",
        "high--five everyone",
        "well-- maybe later",
        "-- heading line",
    ],
    "hash_as_hashtag": [
        "#throwback thursday",
        "C# programming language",
        "F# is functional",
        "see issue #42",
        "room #301",
    ],
    "email": [
        "john.doe@example.com",
        "sarah_oneil@test.org",
        "a.brien@mail.co.uk",
        "support+billing@shop.com",
    ],
    "search_term": [
        "sql injection tutorial",
        "how to prevent sql injection",
        "union select explained",
        "what is a tautology in logic",
        "order by clause examples",
        "difference between union and union all",
        "best sql tutorial for beginners",
    ],
    "brand_apostrophe": [
        "Levi's jeans",
        "McDonald's fries",
        "Reese's cups",
        "Kellogg's cereal",
        "Hershey's chocolate bar",
        "Macy's winter sale",
        "Wendy's menu prices",
    ],
    "json_ish": [
        "{\"name\":\"test\"}",
        "[1,2,3]",
        "{\"q\":\"running shoes\"}",
        "{\"id\": 42, \"ok\": true}",
    ],
    "semicolon_text": [
        "hello; world",
        "milk; eggs; bread",
        "wait; then go",
        "red; green; blue",
    ],
    "contraction": [
        "it's a lovely day",
        "don't stop believing",
        "can't wait to see you",
        "y'all come back now",
        "we're almost there",
        "a 9 o'clock meeting",
        "rock 'n' roll all night",
    ],
    "comment_like": [
        "/* note to self */",
        "a/b testing results",
        "/path/to/my/file",
        "5 * 3 = 15",
    ],
    "numbers_ids": [
        "12345",
        "order 007 confirmed",
        "3.14159",
        "building 42, room 7",
    ],
    "keyword_verbs": [
        "sleep tight",
        "benchmark test results are in",
        "beauty sleep matters",
        "character development arc",
        "the cast of the show",
        "broadcast the news",
        "please load the next page",
    ],
}


def rows_from(groups, label, prefix):
    """Flatten a {category: [inputs]} map into row dicts with stable ids."""
    rows = []
    i = 0
    for category in groups:  # preserve declaration order for id assignment
        for text in groups[category]:
            i += 1
            rows.append({
                "id": f"{prefix}{i:03d}",
                "input": text,
                "label": label,
                "category": category,
                "split": "",  # filled in by assign_splits
            })
    return rows


def assign_splits(rows):
    """
    Stratified 50/50 dev/test split, deterministic and reproducible.

    Within each category the rows are shuffled with a per-category seeded RNG,
    then alternated dev/test. Shuffling first means the split is not an artifact
    of authoring order; alternating guarantees the per-category balance is 50/50
    (off by at most one row for an odd count). Because the RNG is seeded, the
    assignment is identical on every run.
    """
    by_cat = defaultdict(list)
    for r in rows:
        by_cat[r["category"]].append(r)
    for category in sorted(by_cat):
        items = sorted(by_cat[category], key=lambda r: r["id"])
        rng = random.Random(f"{SEED}:{category}")
        rng.shuffle(items)
        for idx, r in enumerate(items):
            r["split"] = "dev" if idx % 2 == 0 else "test"


def write_csv(path, rows):
    rows = sorted(rows, key=lambda r: r["id"])
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "input", "label", "category", "split"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return rows


def summarize(name, rows):
    cat = Counter(r["category"] for r in rows)
    split = Counter(r["split"] for r in rows)
    print(f"\n{name}: {len(rows)} rows  (dev={split['dev']}, test={split['test']})")
    for c in sorted(cat):
        per = Counter(r["split"] for r in rows if r["category"] == c)
        print(f"  {c:20s} {cat[c]:3d}  (dev={per['dev']}, test={per['test']})")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    attacks = rows_from(ATTACKS, "attack", "a")
    benign = rows_from(BENIGN, "benign", "b")

    # Split each file independently so both are stratified within themselves.
    assign_splits(attacks)
    assign_splits(benign)

    attacks = write_csv(os.path.join(here, "attacks.csv"), attacks)
    benign = write_csv(os.path.join(here, "benign.csv"), benign)

    summarize("attacks.csv", attacks)
    summarize("benign.csv", benign)
    total = len(attacks) + len(benign)
    print(f"\ntotal rows: {total}")


if __name__ == "__main__":
    main()
