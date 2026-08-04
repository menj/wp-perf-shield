# WP Perf Shield — security remediation roadmap

**Status document. Current as of 1.4.61.** This is the file to read first when picking up the remediation programme, whether you are a person or a tool. It states what has been repaired, what has not, what to do next, and how to prove it.

It exists because the rest of the documentation cannot answer that question quickly. `doc/changelog.md` is over half a megabyte of release history and `doc/ssot.md` is the reasoning behind it. Both are worth having. Neither tells you where the work stopped.

---

## 1. Confirm you have the right build before you touch anything

```bash
grep "WPS_VERSION" wp-perf-shield.php          # expect 1.4.61
grep "^Stable tag:" readme.txt                 # must match
grep "INDICATOR_VERSION" includes/class-wps-indicators.php
```

All four version markers move together, plus `doc/readme.md`. A mismatch means a partial edit — reconcile before continuing.

The external review that started this programme assessed **1.4.59**, archive SHA-256 `38ee657bf24d8bdcb878ee4d432909a082ef7074e6a4fe38e2f1142c584ef595`. Its line references are against that build and have shifted since. Locate code by searching for the described construct, never by line number.

---

## 2. Rebuild the test environment first

**The build container does not persist between sessions.** No PHP, no harness, no fixtures. Every session rebuilds them. Budget for this before estimating any task.

```bash
apt-get update && apt-get install -y php-cli php-xml php-zip
```

Then reconstruct a WordPress stub. The harness pattern used throughout this programme:

- `wp-stubs.php` — defines `ABSPATH`, `WP_CONTENT_DIR`, `WPS_DIR`, `WPS_OPTION`, the option/transient store as globals, and roughly 60 WordPress functions plus a fake `$wpdb`. **Derive `WPS_VERSION` from the plugin source by regex; never hardcode it.** A pinned version silently invalidates any assertion about version strings.
- Stage the plugin into a fake site tree at `<site>/wp-content/plugins/wp-perf-shield` and point `WPS_TEST_SITE` at `<site>`.
- Invoke private methods by reflection. Most checks are `private static` and take no arguments.

**Two traps that have each cost a debugging cycle:**

- After editing the build tree, **re-copy it into every staged site** before running suites. A suite reading a stale staged copy will report a fix as absent, or worse, absent as present.
- Any suite that must run against an *older* build has to honour an externally supplied `WPS_TEST_SITE`. A hardcoded `putenv()` overrides it and the suite will happily test the patched tree while claiming to test the unpatched one. This has happened.

---

## 3. Status ledger

Twenty findings. Three fixed, one partial, sixteen open.

| ID | Finding | Status |
| --- | --- | --- |
| CRIT-001 | Plugin-integrity scanner iterates an undefined variable | **Fixed** (1.4.60) |
| CRIT-002 | Failed quarantine escalates to irreversible deletion | **Fixed** (1.4.60) |
| CRIT-003 | Fixed-order time budgeting starves late checks | **Open** — next |
| CRIT-004 | No single-flight lock around scans | **Fixed** (1.4.60) |
| CRIT-005 | Event chain is not concurrency-safe | **Fixed 1.4.63; in-plugin self-test added 1.4.64** — run it once on staging to confirm on-host |
| HIGH-001 | Client-IP unsafe behind reverse proxies | Open |
| HIGH-002 | Quarantine depends on Apache-only access control | Open |
| HIGH-003 | Event-log integrity claims exceed the trust boundary | Open |
| HIGH-004 | One fatal disables nearly the whole security layer | Open |
| HIGH-005 | Uninstall leaves persistent state behind | Open |
| MED-001 | Scanner is an oversized god class | Open |
| MED-002 | Package verification does not test runtime behaviour | Open |
| MED-003 | Excessive release archaeology in source and docs | Open — **and worsened** since |
| MED-004 | Incident-specific intelligence hardcoded in scanner logic | Open |
| MED-005 | Strict ZIP blocking uses a brittle route allowlist | Open |
| MED-006 | Generic `manage_options` fallback weakens least privilege | Open |
| MED-007 | Outbound-cookie guard scope overstated | Open |
| LOW-001 | ~509 error-suppression operators | Open |
| LOW-002 | Repeated filesystem traversal | Open |
| LOW-003 | Check results need explicit execution status | **Partial** — see below |

### On MED-003, honestly

Each release in this programme adds several kilobytes to `doc/changelog.md` and `doc/ssot.md`. The review's complaint is that historical narrative obscures current contracts, and the remediation work has been making that worse rather than better. This document is a partial answer: one place stating current state. The full fix — splitting architecture and security contracts out of the changelog — is still outstanding.

### On LOW-003, precisely

`compare_plugin_files()` returns an explicit `status` of `complete`, `incomplete` or `failed` with a reason. **Nothing else does.** The 71-check registry still runs:

```php
$findings = array_merge( $findings, (array) call_user_func( $cb ) );
```

No try/catch, no per-check status, no distinction between "ran and found nothing" and "threw". Completing this is task 1 of the next phase.

---

## 4. What was fixed, and how it is proven

`harness/fixtures1460.php` — 32 checks. **32 pass against 1.4.60; 27 fail against 1.4.59.** Run it against both builds. A regression test that passes against the bug it names proves nothing, and this suite required two attempts before it genuinely failed on the old build.

| Finding | Repair | Where |
| --- | --- | --- |
| CRIT-001 | `$iterator` → `$iter`; explicit status on every return; `catch (\Throwable)` rather than `\Exception` | `class-scanner.php`, `compare_plugin_files()` |
| CRIT-002 | Quarantine *failure* short-circuits before any delete; finding stays open; `auto_remediation_withheld` event. Deletion still reachable when quarantine is disabled by policy | `class-scanner.php`, `auto_remediate()` |
| CRIT-004 | `WPS_Scan_Lock` — atomic `INSERT` acquisition, random owner token, TTL, stale recovery, release in `finally` | `includes/class-scan-lock.php` |

The `Throwable` widening was not cosmetic. The first repaired run surfaced a `TypeError`, which `catch (\Exception)` does not catch.

---

### The roadmap is machine-checked, and it bites back

`harness/fixtures1461.php` holds this document to the code. It asserts that every finding identifier appears here, that anything marked **Fixed** is genuinely present in the source, and — the useful half — that anything marked **Open** is genuinely still absent.

That last group inverts on purpose. The moment you implement continuation state, the assertion "CRIT-003 is genuinely still open" fails. **That is not a bug in the suite. It is the suite telling you to update this table in the same change as the code.** Do that rather than deleting the check.

---

## 5. Next phase — start here

### Task 1 — Per-check execution status (completes LOW-003 and Phase 1)

**Where:** `class-scanner.php`, the `foreach ( $checks as $label => $cb )` loop in `run_locked()`.

Wrap each call. Record per check: `passed`, `finding`, `failed`, `incomplete`, `skipped_budget`, `skipped_not_applicable`, `disabled_by_policy`. A check that throws must be caught as `Throwable`, recorded as `failed` with the reason, and **must not** abort the scan or trigger safe mode — one broken detector taking down the whole security layer is HIGH-004 in miniature.

**Acceptance:** an empty finding array can never be interpreted as a successful run; a deliberately throwing detector is reported as failed while every other check still executes.

### Task 2 — Delete a false statement

`class-scanner.php` still emits, on a budget-exhausted scan:

> "Run a manual scan from the Overview tab when the site is quieter; skipped checks run then."

A manual scan uses the same fixed order and the same budget, so it skips the same tail. This is untrue as written and must go with Task 3.

### Task 3 — CRIT-003, resumable scanning

**Root cause:** check order is fixed and there is no continuation state. When the budget expires the same tail is skipped, and the next scan starts at check one. Late checks — WordPress.org plugin integrity at 56, PHP inventory drift at 57, first-party integrity at 70, drop-in guard at 71 — can be starved indefinitely on a slow host.

**Required state:** `scan_run_id`, `next_check_index`, `completed_check_ids`, `skipped_check_ids`, per-check status, `start_time`, `last_resume_time`, and a configuration/generation hash so a plugin upgrade invalidates incompatible state.

**Behaviour:** resume from the first incomplete check; rotate fairly if one check repeatedly exhausts the budget; expire abandoned state; restart only when the generation hash changes.

**Acceptance:** force a budget expiry before check 56 and assert the next invocation begins there; assert every check executes within a bounded number of scans; assert an abandoned scan recovers.

**Note:** this interacts with `WPS_Scan_Lock`. Continuation state is written by the lock holder; do not let a second worker resume a scan another worker owns.

### Task 4 — CRIT-005, atomic event append

**Where:** `class-event-log.php`, `record()`.

**Root cause:** read anchor → compute hash → insert row → update anchor, with no transaction and no lock. Two concurrent writers both read head `H`, both write events claiming `prev_hash = H`, and the chain forks. Verification then reports legitimate activity as tampering.

**Prioritise this one.** The operator has an unexplained chain-verification failure on a live production site, and this is the most likely cause. Confirming or eliminating it is worth more than its position in the severity list suggests.

**Required design:** transaction plus row-level lock on the chain anchor, or a database advisory lock, or an append-only sequence table with compare-and-swap. On failure, roll back — never advance the anchor without its event row, never insert an event that cannot attach to the committed head.

**Acceptance:** concurrent writes produce one linear chain; no duplicate `prev_hash` except at genesis; failure between insert and anchor update leaves consistent state.

**Resolution (1.4.63).** `record()` now serialises the append. The critical section takes a MySQL/MariaDB advisory lock (`GET_LOCK`, name derived from the table), with a transaction + tail-row `FOR UPDATE` fallback where `GET_LOCK` is unavailable; the lock is released, and an incomplete append rolled back, in a `finally`. Inside the lock the head is read from the **table** — the newest chained row's `curr_hash` via `current_head()` — not from the cached `wps_event_chain` option. That both closes the race and makes an append self-healing: a stale or previously-forked anchor can no longer misdirect a new link, and the anchor `count` is recomputed from the table rather than blindly incremented.

**Verified in-container** (`harness/crit005-logic.php`, 9/9): the head is read from the table not the anchor (proven by seeding a deliberately forked anchor and confirming the new link ignores it), the resulting chain verifies `ok` with no duplicate predecessor, and — verify-the-verification — the same harness *fails* against a copy with the defect reintroduced, and `verify_chain()` reports an injected fork as `tampered`.

**NOT verified in-container, and must be before production:** true OS-level atomicity under concurrent MySQL connections, the `FOR UPDATE` fallback, and crash-consistency. The build box has no database. **1.4.64 moves this proof into the plugin:** Diagnostics → Event-chain self-test runs the real append path over an isolated scratch table and opens a second DB connection to prove the append lock excludes across connections, deterministically, on the host. Run it once on staging. The external `harness/crit005-concurrency.sh` remains for N-way throughput and CI.

**Scope limit, stated plainly:** this is *preventive*. It stops future forks; it does not repair a chain already forked on the live site. If the existing production tamper report is a benign concurrency fork, `verify_chain()`'s `first_bad_id` points at the first forked row — a row written within the same second as its predecessor by legitimate traffic is the tell. Repairing (re-anchoring) an already-forked historical chain is a separate task, not part of CRIT-005.

**Ratchet:** the `fixtures1461.php` assertion that CRIT-005 is *absent from source* must now flip to a presence assertion (the append is locked and the head is read from the table). That fixture file is rebuilt per session and is not in this package; the expectation change is recorded here so it travels with the code.

---

## 6. Later phases

In the review's order. Do not reorder without a reason: correctness and data-loss before architecture.

- **Phase 4 — infrastructure.** HIGH-001 trusted-proxy resolver, used consistently by blocking *and* Akismet reporting. HIGH-002 move quarantine outside the document root with a runtime accessibility self-test, since `.htaccess` does nothing on Nginx or IIS.
- **Phase 5 — lifecycle.** HIGH-005 complete uninstall including the events table, chain keys, baselines, quarantine directory and scheduled hooks, with multisite handling. MED-006 exact capability checks rather than a `manage_options` fallback.
- **Phase 6 — architecture.** MED-001 extract a filesystem inventory service and a detector interface; separate policy from remediation. MED-004 move campaign intelligence into versioned indicator packs. MED-003 split the documentation.
- **Phase 7 — release engineering.** MED-002 PHPUnit, static analysis, WordPress integration tests, CI. The gate: CI must catch the 1.4.59 iterator defect automatically.

HIGH-003 (accurate threat-model claims) and MED-007 (cookie-guard scope) are documentation-accuracy tasks and can be done in any phase.

---

## 7. Product decisions that are not defects

**Akismet reporting is enabled by default and stays that way.** Do not classify it as a privacy defect or disable it. The permitted work is: accurate documentation, failure isolation, a working opt-out, and a correctly resolved client IP.

Two Akismet settings exist and they are different data flows. `login_report_spam` *sends* confirmed attacker addresses outward. `akismet_enrichment` *asks* whether an address is already known, and contributes nothing. Both default to enabled and both now have controls — `akismet_enrichment` had none until 1.4.60 and could never be set.

**Remediation is not to be removed**, only made safe and reversible.

---

## 8. Prohibited

From the review, and each of these has a reason:

- Do not suppress the iterator warning and leave a check broken
- Do not represent a failed check as clean
- Do not restore automatic hard deletion after quarantine failure
- Do not use a non-atomic transient as a scan mutex
- Do not solve starvation by raising the global timeout
- Do not keep inaccurate comments for historical reasons
- Do not remove a security control without an equal or stronger replacement

---

## 9. House conventions

- **British spelling** throughout documentation
- **No inline `style=` attributes and no inline `<script>`** in markup; CSS in `assets/css/`, JS in `assets/js/`, images in `assets/img/`
- Settings use the shared `.wps-toggle-row` pattern; multiple settings are grouped into cards, not one continuous form
- Every release updates: `wp-perf-shield.php` (twice), `readme.txt`, `doc/readme.md`, `INDICATOR_VERSION`, `doc/changelog.md`, `doc/upgrading.md`, `doc/ssot.md`, and this file
- `doc/variants.md` is the malware catalogue; its completeness is machine-asserted by `fixtures1451.php`
- Package with `zip -rX`, then extract and `diff -rq` against the build tree before delivering

### Settings have a trap

`WPS_Admin::save_settings()` rebuilds the option array from `$_POST` and merges over the existing value. A key with no entry in that handler cannot be saved. Before 1.4.55 it did not merge at all, so such a key was *wiped on every save*. When adding a setting: add the save handler entry, the settings row, and assert the rendered default matches the code default in both states.

---

## 10. Recurring defect shapes

These have each recurred. Check for them before declaring work done.

**Pinned-literal assertions — eight occurrences.** A test asserts an exact spelling where it means an intent, then fails on a wording change or, worse, passes because the string appears somewhere irrelevant. Assert the claim.

**Verify the verification.** Twice, a regression test appeared to prove a fix and proved nothing: once because the identifier under test still appeared elsewhere in the file, once because a hardcoded environment variable pointed the suite at the patched build. Inject the defect and confirm the test fails.

**Comments are not evidence.** `compare_plugin_files()` carried a detailed docblock about what it detected, and detected nothing for its entire existence. A comment describing behaviour is a claim about behaviour, not proof of it.

**A closing PHP delimiter inside a `//` comment ends PHP mode** and dumps the rest of the file to output as HTML — while `php -l` still reports the file valid, because it is. Use block comments when discussing PHP tags.

---

## 11. Working state

Everything below is rebuilt per session; none of it ships in the plugin.

| Artefact | Purpose |
| --- | --- |
| `harness/wp-stubs.php` | WordPress stub — constants, ~60 functions, fake `$wpdb` |
| `harness/run-checks.php` | Runs every check against a staged tree, prints findings |
| `harness/fixtures14XX.php` | Per-release suites, XX matching the release |
| `harness/cov2.php` | Five-layer coverage measurement for a malware sample |
| Staged sites | Fake WordPress trees, one per sample family |

Nine suites currently pass. Run all of them before packaging; several assert on shared indicator and blocking lists and will catch collateral damage.

**One more thing.** A parallel session once shipped its own release into this same container while work was in flight, and the collision surfaced only because a file-creation call refused to overwrite an existing path. If a file you did not write already exists, stop and find out why before overwriting it.
