# QueryShield — resume bullets

Two candidate bullets. Every number is measured by a script in this repo
(`make eval`, `make loadtest`) on the recorded machine; nothing is invented.
Pick one or use both. Phrasing is a starting point — tighten to your resume's
voice.

## Bullet 1 — detection quality (lead with this)

> **QueryShield — SQL-injection detection proxy (Java).** Built a reverse proxy
> that screens HTTP requests for SQL injection using a hand-written
> Aho-Corasick multi-pattern matcher and SQL tokenizer; on a 205-payload
> labelled set (held-out test split) raised detection from an 89.6% /
> 6.4%-false-positive signatures-only baseline to **100% detection at a 2.1%
> false-positive rate (98% precision)** by adding a normalizer and weighted
> structural rules.

## Bullet 2 — engineering + performance

> Engineered the proxy on the JDK's `HttpServer`/`HttpClient` with per-field
> request normalization, an Aho-Corasick automaton, and threshold scoring;
> measured **~0.3 ms added p50 latency and ~24k req/s** on a no-database path
> (single machine) and backed the system with **562 automated tests**,
> including a 500-iteration property test of the Aho-Corasick automaton against
> a brute-force oracle.

## Shorter one-line variant (if space is tight)

> **QueryShield (Java):** hand-written Aho-Corasick + SQL-tokenizer reverse
> proxy that blocks SQL injection; 100% detection at 2.1% false positives on a
> held-out test set, ~0.3 ms added latency, 562 tests.

---

## Supporting evidence (so you can defend each number)

| Claim | Source |
|---|---|
| 205-payload labelled set, 50/50 stratified dev/test | `data/`, `data/README.md` |
| v1 89.6% recall / 6.4% FPR; v3 100% / 2.1% / 98% precision (test split) | `make eval` → `eval/results/eval.md` |
| ~0.3 ms added p50, ~24k req/s (no-DB path, one machine) | `make loadtest` → `eval/results/phase9-loadtest.md` |
| 562 tests incl. 500-run Aho-Corasick property test | `make test` |

## Claims NOT yet supported — do not use until measured

- **needs:** "defeats / resists sqlmap" — the sqlmap stretch goal has not been
  run. Do not claim any sqlmap result until `make`-ing that comparison against
  the local victim and recording the output.
- **needs:** any production-scale throughput or latency figure — the numbers
  above are single-machine, loopback, and labelled as such; don't generalise
  them to "handles N req/s in production".
- **needs:** "zero false positives" — the test set still has one benign false
  positive (`union select explained`); the honest figure is 2.1% FPR.
