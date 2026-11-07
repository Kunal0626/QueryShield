# QueryShield — interview notes

The design decisions behind the project (what the alternatives were and why I
chose this one), then the 15 hardest questions an interviewer could ask, each
with a short, correct answer. Everything here reflects code in this repo.

---

## Design decisions

**Build: plain `javac` + `Makefile`, not Maven/Gradle.** The pitch of the
project is "I wrote the algorithm by hand", so a ~60-line build you can read top
to bottom fits better than a tool whose main feature (transitive dependency
resolution) this project — two leaf jars — doesn't need. Cost: no automatic
dependency resolution, so `make deps` is a `curl` of two pinned URLs with
SHA-256 verification. Targets Java 21 (current LTS) though built on JDK 25, so a
clean clone builds anywhere.

**One `Detector`, two callers.** The offline eval harness and the live proxy
call the *same* `Detector`. If they didn't, every published number would
describe code that isn't the code in the request path. One class, one code path.

**Score each field independently, never a concatenated request.** Scoring one
blob lets unrelated fragments add up into a phantom attack (a `User-Agent`
ending in a quote + a search for "or"), and loses the one fact an alert needs:
*which* parameter was dirty. Cost: a payload split across two fields evades the
per-field score — documented.

**The normalizer is the riskiest component, by design.** Normalizing is
matching's precondition, but it makes us a second parser beside MySQL, and every
disagreement is a bug ("parser differential"). So the pipeline matches MySQL's
semantics deliberately (comment-as-delimiter, MySQL-only whitespace,
`Locale.ROOT` lowercasing) and the aggressive knobs are bounded (3 decode
rounds) with the gaps written down rather than hidden.

**Hand-tuned weights, not a learned model, with a frozen split.** ~200 labelled
rows would overfit any classifier, and you couldn't explain it in an interview.
Hand-set weights are defensible line by line. To make "tuned on dev, measured on
test" auditable rather than asserted, the `split` column is committed to git
with a fixed seed.

**Error-tolerant lexer: an unterminated quote is a breakout.** A parameter value
lives inside the app's `'...'`, so a lone quote closes that string and the rest
becomes SQL. The lexer models exactly that — on an unterminated quote it emits a
breakout token and re-lexes the remainder as SQL — which is what exposes the
comment in `admin'#` while leaving `O'Brien` alone.

**Scoring with a threshold, not block-on-any-match.** Pure signatures force a
bad trade: include `--` and you flag every hyphen; exclude it and you miss
comment attacks. Weighted scoring lets a weak signal (`--` = 2) sit below the
block line while structure pushes real attacks over it. The threshold (3) was
chosen from a sweep on the dev split.

**Forwarding correctness before inspection.** A proxy that mangles responses is
useless no matter how good its detector. Hop-by-hop headers are stripped both
ways, the headers `HttpClient` reserves are left to it, and the body is read so
a clean `Content-Length` goes downstream.

---

## The 15 hardest questions

**1. Aho-Corasick vs naive matching — complexity, and why failure links work?**
Naive multi-pattern search (loop `contains` over N patterns) is
O(N · |text| · |pattern|) and re-reads the text once per pattern. Aho-Corasick
is O(Σ pattern lengths) to build and O(|text| + matches) to scan — independent
of N. A **failure link** points from a node to the longest proper suffix of the
string matched so far that is also a prefix of some pattern; following it on a
mismatch means we never move the text cursor backwards (the same idea as the KMP
failure function, generalised to many patterns), so each input character is
consumed once.

**2. Why normalize before matching, and what is a parser differential?** Because
`%55NION`, `UNION/**/SELECT`, fullwidth letters and mixed case are the same
attack to the database but different bytes on the wire; matching raw bytes
misses every obfuscated variant. The risk: after normalizing, we and MySQL are
two parsers of one string. If we decode *more* than the backend we flag innocent
text (false positives); *less* and a payload slips through. That gap is a parser
differential, and it's why the normalizer mirrors MySQL's rules and bounds its
aggressive steps.

**3. Why do precision and recall matter more than accuracy here?** Real traffic
is overwhelmingly benign, so a detector that blocks nothing scores ~99%
accuracy and is useless. Recall answers "did we catch attacks?"; false-positive
rate / precision answer "did we wrongly block real users?" — the two failures
that actually matter. Accuracy hides both behind the majority class.

**4. Walk through UNION-based injection.** In `... WHERE name LIKE '%<q>%'`, set
`q = ' UNION SELECT id, value, 1 FROM secrets -- `. The first `'` closes the
app's string; `UNION SELECT` appends a second result set from another table;
the columns must match the original query's count and compatible types (here 3:
`id, value, 1`); `-- ` comments out the trailing `%'`. The endpoint then renders
the attacker's rows — the `secrets` table — as if they were products.

**5. Why is the real fix parameterized queries, not this proxy?** A
`PreparedStatement` sends the SQL text and the parameter values to the database
*separately*, so a value can never change the query's structure — the quote in
`admin'--` is just data in a string. The proxy only guesses at malice from the
outside and can be bypassed; it's a defence-in-depth layer for apps that haven't
been fixed, not a fix. The `/safe/*` endpoints demonstrate this: the same
payloads that bypass `/login` fail against `/safe/login`.

**6. Why cap percent-decoding at 3 rounds?** Unbounded decoding is its own bug:
it would decode text the backend never would (anything containing a literal
`%25…`), inventing attacks out of ordinary input. Three rounds covers the
double/triple encoding seen in practice. The cost — a 4×-encoded payload gets
through — is a documented gap, asserted by a test.

**7. `admin'#` looks benign as a standalone string. How is it caught?** In the
app's query it becomes `… username='admin'#'` — the value's `'` closes the app's
string and `#` comments out the rest. The lexer models this: an unterminated
quote is treated as a breakout and the following `#` is lexed as a comment, so
the `comment-after-quote` rule fires. `O'Brien` also breaks out, but is followed
by letters, not a comment, so only the weak `unbalanced-quote` signal fires and
it stays below the threshold.

**8. Why is the tautology rule "gated by SQL context"?** Because `1=1` on its own
is benign maths (a real dataset hard negative), but `' OR 1=1` is an attack. The
rule fires on an equal-operand comparison *only* when there's an OR/AND keyword
or a quote nearby. Without the gate you flag "the equation 1=1 is always true";
too strict and you miss `' OR 1=1`.

**9. How does scoring fix the false positives that pure signatures caused?** A
lone `--` (a hyphen like `high--five`) scores 2; a benign apostrophe name scores
2 (unbalanced-quote). With a block threshold of 3, neither blocks on its own,
but a real attack accumulates signature + structural weight well past it. This
dropped the test false-positive rate from 6.4% (block-on-any-match) to 2.1%.

**10. Your threshold is 3. How did you choose it, and why not higher?** A sweep
on the dev split: thresholds 1–2 give ~29% FPR (weak signals block), 3 gives
0% FPR at 98% recall (the knee), and 4+ start dropping real attacks. Picked on
dev, then frozen before measuring test. Higher trades recall for no precision
gain here.

**11. Why Aho-Corasick for signatures but a separate tokenizer for rules?**
Signatures answer "does this substring appear?" in one fast pass — great for
literal indicators. Rules answer "do these tokens stand in this relationship?"
— needed to tell `union select` (attack) from `union station` (benign), which
no substring can. They're complementary: signatures scan the text, rules scan
the token stream, and both feed one score.

**12. A proxy must forward correctly. What are hop-by-hop headers and why strip
them?** Headers like `Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`,
`Trailer`, `Upgrade` describe a single connection, not the end-to-end message
(RFC 7230). Relaying them corrupts framing or connection handling between two
different connections. QueryShield strips them both ways and lets the HTTP
client set `Host`/`Content-Length` itself.

**13. In the load test the proxy looked faster than direct. Is that real?** No —
on the DB-backed request the MySQL query (~50 ms) dominates, so the proxy's
sub-millisecond cost is below run-to-run variance and the sign can flip. To
measure the proxy's actual cost I load-tested a no-DB endpoint, where it adds
~0.3 ms (p50) and sustains ~24k req/s. Reporting the DB-backed "win" as overhead
would be dishonest.

**14. Why dev/test splits, and why stratified?** Tuning and reporting on the same
data measures how well you fit it, not how well it generalises — recall would be
inflated. So rules are tuned on dev and reported on an untouched test split,
frozen in git. Stratifying by category keeps both splits representative: a test
set of only tautologies would overstate recall on the easy class.

**15. What can't QueryShield catch, and what would you build next?** Second-order
injection (stored now, used later), a payload split across multiple fields,
encodings beyond the 3-round decode cap, and anything a `PreparedStatement`
would make moot anyway. Next: run `sqlmap` against the victim with and without
the proxy and report what it still extracts; add cross-field correlation; and
measure overhead on a non-loopback setup where network latency is realistic.
