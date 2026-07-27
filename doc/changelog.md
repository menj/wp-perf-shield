# Changelog

## 1.4.30

### Why
The Settings rebuild in 1.4.28 was incomplete, and the screenshots showed exactly how.

That release added styling for `.wps-app .form-table th`. What it missed is that an older global rule - `.wps-app th`, written as a data-table header treatment - was still applying uppercase, an eleven-pixel size, letter spacing, a translucent white background and `color: #475467 !important` to every table heading in the plugin, form labels included.

So the field labels were being rendered as column headings. That is what read as the font being wrong: a settings form should not shout its labels in small capitals.

The `!important` on that hardcoded colour did two further things. It beat the token set in 1.4.28, so the intended colour never applied. And because the rule was never restated in either dark-scheme block, those labels stayed mid-grey on a near-black panel - the same class of omission this release series has now corrected three times.

### What changed
The form's labels are corrected in place: sentence case, the header background cleared, letter spacing normalised, and the colour taken from the token layer with enough weight to actually win. Both dark schemes now cover them.

Every data table has its own more specific header rule, so the global rule is left exactly as it is and nothing on any other screen moves.

Two smaller things visible in the same screenshots. The `define( 'WPS_DISABLE_LOGIN_GUARD', true );` snippet was breaking across two lines mid-expression, splitting the constant from its closing bracket, and inheriting a ten-pixel corner radius meant for code blocks rather than inline snippets; it now keeps its own line intact and takes a radius appropriate to its size. And the Akismet test button sat oversized beside the small status line it belongs to.

### A duplicate rule of my own
Investigating the button found two separate `.wps-btn-sm` rules. The original defined the control completely - size, height, line height, padding. A second, added in 1.4.16, changed only the font size, so the control rendered twelve-pixel text in a box sized for eleven and neither rule owned it.

The duplicate is removed and the sizing stated once, with enough specificity to beat WordPress core's own button rule rather than relying on declaration order.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all twenty-five prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 18-check suite.

The correction is asserted to override the global rule on every property that was leaking - case, background, letter spacing - and to beat the hardcoded colour with a token rather than another hex. Dark coverage is asserted for both schemes. The snippet is asserted unable to break mid-expression.

Two assertions matter more than the rest, and they are about restraint rather than appearance. Every selector added in this release is asserted to be scoped to the form or a field class, so the fix cannot reach another screen. And the three data-table header rules are asserted still present and untouched, because the global rule they depend on was deliberately left alone.

One defect in the suite itself, fixed: the scoping check sliced the stylesheet from a marker that sat inside a comment, so the comment had no opening delimiter to pair with and its prose was parsed as selectors. It reported a failure that did not exist.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.25-1`; no PHP changed at all in this release - stylesheet only.

## 1.4.29

### Why
An operator's event log arrived for review and a sixth of it was the same seven lines repeated.

The mtime scanner groups modified files by timestamp and suppresses batches above a threshold, on the reasoning that a backdoor is not planted fifty files at a time with an identical mtime. It wrote a diagnostic note explaining each suppression. That note was written on every scan, and since file mtimes do not change, every scan recorded the same handful of facts again.

Two details turn that from untidy into a defect. The note goes through the ordinary event path, so it lands in the tamper-evident store alongside real findings. And that store is capped. On the log in question, five scans over twenty-five minutes produced thirty-five duplicate rows in a two-hundred-row window - a rate that would flush every genuine security event out of retention in about two and a half hours.

A security plugin quietly destroying its own evidence is worse than one that reports nothing, because the operator has no reason to distrust what remains.

### What changed
Each suppressed batch is now reported once. The note is unchanged in wording and the suppression logic is untouched - only the repetition is gone.

The memory is keyed on both the batch's timestamp and its size, so a batch that genuinely grows is reported again rather than silenced by an earlier sighting of the same second. Entries expire after thirty days, so a long-lived batch is eventually restated rather than forgotten permanently, and the store is bounded and cleared on uninstall.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all twenty-four prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 18-check suite.

The suite replays the exact case from the log: seven batches across five scans, asserted to produce seven rows rather than thirty-five. A batch that grows from nine files to fourteen is asserted to be reported again with the new count. Two batches one second apart are asserted to stay independent. The store is asserted bounded at two hundred entries while still reporting every distinct batch once, and an entry older than the expiry is asserted to be restated rather than dropped.

The suppression threshold itself is asserted unchanged, because the point was to stop repeating the note, not to change which files get reported.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.25-1`; no detection logic touched.

## 1.4.28

### Why
The Settings screen looked wrong next to the rest of the plugin, and the reason turned out to be simple: it was the only screen with no styling of its own. Every other surface draws from the design tokens. This one inherited WordPress core's form-table wholesale, so its label column, spacing and description colour came from core - and in the dark scheme nothing overrode core's light-admin grey at all.

On top of that the screen had drifted into two different row patterns. Four checkbox rows used the established flex layout with a bold title and a description beneath. Four more - the login-guard settings added between 1.4.17 and 1.4.27, all mine - used a plain inline label with a separate description paragraph. The two do not align, wrap differently, and put their descriptions at different indents.

And the four sections were four separate tables. Two carried an inline 200px label width and two sized themselves to their own longest label, so the label column started at a different position in each section going down the page. That is what read as misalignment, and it was.

### The bug this turned up
Checking each checkbox's rendered default against the default the code actually applies found one that disagreed. Spam reporting was switched on by default in 1.4.27, but its checkbox still rendered from the old off default - so a fresh install ran with reporting on while the screen showed it off.

The second-order effect is worse than the display. An unchecked box posts nothing, so an operator who opened Settings, changed something unrelated and saved would have written a disabled value and silently switched off a feature that had been running. Nobody would have had reason to look.

Both defaults now come from the same value, and the suite asserts that every checkbox renders the default its code path applies, so the two cannot drift again.

### What changed
All eight checkbox rows use one pattern. The label column is set once in CSS rather than inline on two of four tables. Descriptions, textareas and selects are styled from the token layer, with a visible focus ring for keyboard use, and the dark scheme now covers all of them.

Field controls that are not part of a label were moved out of it. The Akismet status, its test button and the usage line had all been packed into the description paragraph and separated with line breaks; when the row was converted, that put an anchor styled as a button inside a `label` element, where clicking it would have toggled the checkbox. They now sit in their own container beneath the setting.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all twenty-three prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 31-check suite.

Every checkbox is asserted to render the default its code applies. All eight rows are asserted to use one pattern, with no bare inline checkbox labels left. No control is asserted to be nested inside a label. The markup is asserted to carry no inline styles, the label column asserted to be governed by a single CSS rule, and the token and dark-scheme coverage asserted for descriptions, textareas and selects.

The last check matters more than the rest: the suite renders the page and balances the emitted HTML, not just the source. This markup is built through PHP conditionals, so a branch can emit an unclosed tag that reading the file will never show - and that is exactly how three mis-closed rows in this release were caught, after a bulk edit closed the wrong ones.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.25-1`; no detection logic touched. Inline style attributes across the plugin drop from twenty-two to twenty.

## 1.4.27

### Why
Two operator instructions: turn automatic Akismet reporting on by default, and add a way to report an address by hand.

The manual button is an easy yes - a human looks at a specific blocked address and chooses to report it, the safest possible version of this.

On-by-default I argued against, and the reasoning is recorded here because the decision went the other way and that should be visible. Automatic reporting on every install means every site starts contributing to Akismet's shared corpus without being asked - including sites behind a CDN, where the address the plugin sees may be the CDN's edge rather than the attacker's. Reported blindly, that would flag the CDN as a spam source for everyone. The operator chose on-by-default anyway; it is their plugin. What makes it defensible for the sites this also ships to is the proxy guard below, which was a condition of building it rather than an afterthought.

### What changed
Automatic reporting now defaults to on. An address blocked on conclusive evidence is submitted to Akismet without the operator enabling anything.

A proxy guard governs the automatic path. Before auto-reporting, the address is checked against the published Cloudflare ranges and the private, loopback and link-local ranges; if it falls in any of them the report is withheld and the reason logged, because on a proxied site that address is probably not the attacker. This applies only to automatic reporting.

A manual "Report spam" button now sits on each row of the blocked-addresses list in Diagnostics. It reports that specific address by hand, and is deliberately not subject to the proxy guard or the conclusive-evidence test - a person has looked at the row and decided. It still checks a nonce and the manage_options capability, still needs an active key, and still reports each address only once. The outcome shows in a banner, and a row already reported says so instead of offering the button again.

The blocked-addresses table also now shows expiry in the site timezone rather than UTC, consistent with the rest of the plugin since 1.4.21.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all twenty-two prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 37-check suite.

Default-on is asserted, and asserted still overridable. The proxy guard is asserted across six infrastructure ranges - three Cloudflare networks, two private ranges, and loopback - each confirmed not auto-reported and each confirmed to log the skip, while a genuine public attacker in the same test is confirmed still reported. The CIDR matcher is asserted directly on both address families, including that 8.8.8.8 and ordinary IPv6 are not caught. Manual reporting is asserted to bypass the guard, to be once-per-address, to degrade without a key, and to be protected by nonce and capability. And an address in a proxy range is asserted to still be blocked - only its Akismet report is withheld.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.25-1`; no detection logic touched. Recorded plainly: on-by-default was enabled at the operator's instruction and against the recommendation in this project's notes, and the proxy guard is the mitigation that makes it safe for general distribution.

## 1.4.26

### Why
The operator's own block log showed the login guard working and, at the same time, showed it being too lenient in a way that was my fault.

Every block in that log carried the same fifteen-minute duration, including an address that had tried more than twenty different usernames - root, admin, site_admin, and a string of invented ones. The reason was always "Akismet: not known for spam, shorter cool-off". The 1.4.18 logic asked Akismet first and let a clean verdict impose the lenient duration, even on an address the site itself had already watched behave like a bot.

That was backwards. Akismet not yet knowing an address is not evidence the address is innocent - it usually just means the attack is newer than Akismet's last crawl. The site's own observation is the stronger signal and should not be overridable by an external service's silence.

### What changed

**Local evidence now leads; Akismet may only escalate.** The block duration is decided by what the site has seen. A spam verdict can lengthen a block, and a clean verdict can shorten one only in the single case it was ever meant for - a first offence against one real username, which is the genuine mistyped-password case. A clean verdict can no longer shorten a block against an address that has tried many usernames or come back after a previous block.

**Blocks escalate for repeat offenders.** An address blocked, allowed back when the block expired, and caught again now climbs a ladder: fifteen minutes, an hour, six hours, a day, a week. The offence count is remembered for fourteen days, past the lifetime of any single block, so waiting one out no longer resets it. This is the punitive behaviour that a fixed duration could not provide, and it is punitive in proportion to evidence rather than by blanket severity.

**Many usernames from one address is treated as conclusive.** Five or more distinct usernames from a single address within the window earns a twenty-four-hour block outright, regardless of what Akismet thinks, because no human logs in that way.

**Confirmed attackers can be reported back to Akismet (opt-in, off by default).** When an address is blocked on conclusive local evidence - many usernames, a repeat offence, or a bot-only username on an account that does not exist - the plugin can submit it to Akismet's spam corpus, so every site using Akismet benefits. It is off by default and deliberately so: everything Akismet learns is shared across every site, so a wrongly reported address would have its reputation degraded everywhere. The plugin therefore reports only what the site has already proven, never an address blocked on a single mistyped password, never on an Akismet verdict, once per address, after the block, and never on the login path.

### Not making lockout more likely
The gentle path is intact. A first mistyped password against your own username, from a clean address, still draws only a fifteen-minute cool-off. Escalation requires being blocked, waiting it out, and returning - which a real user does not do. Everything from earlier releases stands: your own address is never blocked, remembered administrator addresses are protected, every block still expires, and the wp-config.php constant still switches the whole thing off.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all twenty-one prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 20-check suite.

The operator's actual case is replayed: an address trying ten usernames with Akismet returning clean is asserted to draw a twenty-four-hour block rather than the fifteen minutes it drew before. The ladder is asserted to climb across three successive blocks of the same address. The mistyped-password case is asserted to still get fifteen minutes. Reporting is asserted off by default, asserted to fire only on conclusive evidence when on, asserted never to fire on a single-username block, asserted to submit each address at most once, and asserted to degrade without a key rather than fatal.

Two harness defects fixed. One asserted a flat sixty-minute default that the escalation ladder deliberately replaced. The other pinned the literal INDICATOR_VERSION string - the sixth pinned-literal defect in this codebase, and the rule is by now well established: assert the shape, never the spelling.

No test-only method was left in the shipping code; a helper added while writing the suite was removed before packaging and the suite reworked to drive the real option directly.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.25-1`; no detection logic touched.

## 1.4.25

### Why
A live infection recovered from the operator's staging site, and the uncomfortable finding that this scanner would have walked straight past it.

The malware is doorway cloaking - Japanese SEO spam. A hijacked index.php at the site root tests the visitor's user agent against a list of search crawlers and the referrer against Japanese search engines. Crawlers and search visitors are served spam product pages fetched from a remote host and cached under a random-named directory in wp-content; everyone else, including the site owner, gets the real site. `error_reporting(0)` and a nulled `error_log` keep the whole thing out of the logs.

The owner cannot see it. That is the design, not a side effect, and the damage lands in search results rather than on the page.

### The bypass, which matters more than the family
Every string this scanner matches on was present in that file, and none of them matched. They were written as hex escapes - `\x48\x54\x54\x50_USER_AGENT` rather than the constant - and the scanner compared raw bytes.

That is not one missing signature. It defeats every content-based check at once, which is why the fix belongs in the shared layer rather than in any single detector.

Escapes are now resolved before matching: hexadecimal and octal forms, plus the split-literal trick that breaks a grep just as cheaply. Only printable bytes are folded back, so a file full of binary escapes is not mangled into something that matches by accident, and content beyond a megabyte is left alone because this runs across every PHP file on a site.

### The signal that cannot be escaped away
The recovered files carry 225 and 105 `goto` statements - sixteen and eighteen per kilobyte. That is control-flow flattening: the logic is scattered behind jumps so that reading the file top to bottom tells you nothing.

PHP has `goto` and working code essentially never uses it. Measured across the 48 PHP files of the operator's production theme and the 31 of this plugin, the density is zero. Not low - zero.

Unlike a string, it cannot be renamed or escaped without the file ceasing to work, which makes it durable against re-obfuscation in a way keyword lists are not.

### What was added
Two checks. One for cloaking, requiring two independent signals before it fires - a crawler list on its own is what any legitimate bot-detection or caching plugin does, and firing on that would be useless. One for control-flow flattening, with both a floor and a rate, so a handful of jumps in a large generated file is not treated as the same thing.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all twenty prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 24-check suite.

The suite runs against the recovered sample itself. Both files are asserted detected, rated critical, and named in the finding - which caught a real bug: root-level findings reported themselves with no subject at all, because the existing path helper deliberately returns an empty string outside wp-content. The most important finding on the screen was unlabelled.

The bypass is asserted from both directions: hex-escaped text is confirmed not to match a raw signature, and confirmed to match after unescaping.

False positives are asserted against twenty-nine real theme modules sitting in the same tree as the malware, none of which fire on either check. A file that merely detects crawlers - ordinary, legitimate behaviour - is asserted not to fire. And the plugin is asserted never to flag itself.

### Meta
No new files (51 entries). `INDICATOR_VERSION` moves to `1.4.25-1`, its first change since 1.4.5, because the indicator set genuinely grew.

## 1.4.24

### Why
The server log inspection screen was called ugly. It was, and the specifics are worth recording because this is the third table in this codebase to earn the same complaint, and the causes were the same each time.

A hundred and fifty-six words of caveats sat above the first control, including a paragraph about hosts owning the access log that only matters when a log is missing. The Log column repeated "Web access log" four times and "Server log" twice, carrying no information the path did not already give. Every row had two full-weight buttons, and WordPress sizes those to be the main action on a page, so twelve of them made the chrome heavier than the data. Sizes were rendered in mixed units in a proportional font and left-aligned, so a column containing 585 B and 157 MB could not be scanned for the outlier. And the 157 MB file is the one fact on that screen worth noticing before you act, because scanning it may well time out.

The common cause across all three tables: built for completeness rather than for scanning. Every field gets a column, every column gets full-weight chrome, and all the explanation goes at the top.

### What changed
The path leads, with the kind of log following it as a quiet qualifier instead of occupying a column where it repeated. Row actions are links rather than buttons, since they are secondary to the two page-level actions above the table, which keep their weight. Sizes are right-aligned with tabular figures so the column can be scanned rather than read.

Files over fifty megabytes are marked, and say plainly that they are slow to scan. That is a functional addition rather than a cosmetic one: on a 157 MB log the scan can exceed the host's execution limit, and knowing that beforehand is worth more than finding out.

The intro is one sentence. The hosting caveat moved beneath the table, where it is read only by someone who did not find what they were looking for.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all nineteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 29-check suite.

The three JavaScript hooks are asserted still bound, since restyling controls that drive AJAX is an easy way to break them silently. The two page-level buttons are asserted to keep their full weight while the row actions lose theirs - the point was to establish a hierarchy, not to flatten everything. The caveat is asserted to appear after the controls rather than before. No inline styles were introduced, and every colour goes through a design token.

One harness defect fixed, and it is the same shape as the one in 1.4.21: an assertion counted the substring `<th` and matched `<thead` along with it, reporting four columns where there are three. Substring matching without a boundary has now caused two false failures in four releases.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched.

## 1.4.23

### Why
The per-address threshold added in 1.4.17 was the right rule for one attacker at one address, and no use at all against one attacker holding a range.

The operator's own site showed exactly that. Five failed sign-ins against a single username, from four addresses inside one /24, each address stopping before it could reach the count of five. Every individual address behaved lawfully; the attack was in the aggregate. The guard was working correctly and measuring the wrong unit.

### What changed
Failures are now counted against the address's range as well as the address itself - a /24 for IPv4, a /64 for IPv6, being the units an attacker actually rents.

Blocking a range is a much larger hammer than blocking an address, so three conditions must all hold before one is touched: twelve failures within fifteen minutes, from at least three distinct addresses, in a range that contains nobody we trust. Twelve failures from a single noisy address blocks that address and leaves its neighbours alone, because one loud host is not rotation and must not be treated as though it were.

Range blocks last thirty minutes rather than sixty. The blast radius is larger, so the hold is shorter.

They also apply to sign-in only, not to the whole site. Locking an entire range out of a site because somebody in it guessed passwords is a bigger intervention than this evidence justifies.

### Not locking anyone out
A range containing an address an administrator has signed in from, or any address on the allowlist, is never blocked - checked against every remembered administrator address rather than just the current one, so an operator on a dynamic address within their own ISP range stays safe.

The whole behaviour has its own switch, separate from the rest of the login guard, because it is the one part of this feature that can affect people who are not the attacker. Anyone whose visitors sit behind a mobile carrier's NAT or a corporate egress should consider turning it off, and the setting says so.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all eighteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 28-check suite.

The operator's actual attack is replayed and asserted to be caught, with the range blocked and no individual address blocked alongside it. An address in that range that had never been seen before is asserted to be rejected afterwards, and the neighbouring range asserted untouched.

Three negative cases matter more than the positive one. Twelve failures from a single address are asserted to block that address and not its range. Twelve failures spread over only two addresses are asserted not to trip it at all. And a range containing a remembered administrator address, or an allowlisted one, is asserted to survive twelve failures from twelve different hosts.

Bounds are asserted structurally: range counters cannot outlive their fifteen-minute window, and the addresses remembered per range are capped.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched.

The honest limit is unchanged and worth repeating: this runs in PHP, so WordPress still starts up for every attempt. Against a rotating attacker the saving is real but partial, and a firewall rule at your host or CDN still does more.

## 1.4.22

### Why
A small release, and worth saying so plainly: one word in a column heading, plus the test that should have caught it.

WordPress offers two ways to set a timezone - a city, or a plain offset like "UTC+8". These are stored differently and take different paths through the conversion added in 1.4.21. The suite exercised the city path. The operator had set the offset path, which is what the Settings screen offers first.

The conversion itself was correct on both - times matched what WordPress reports to the second. But the heading read "GMT+8" where the WordPress Settings screen says "UTC+8": the same fact in a second vocabulary, leaving the reader to work out that they refer to the same thing. A plugin that displays a value the dashboard already displays should use the dashboard's words for it.

### What changed
Offset-based timezones are labelled the way WordPress labels them - UTC+8, UTC+5:30, UTC-3:30 - rather than with GMT. Cities still show their abbreviation where one exists. A site on UTC still says UTC.

The suite now covers the offset configuration explicitly, asserted against the exact reading from the operator's own Settings screen: 01:45:09 UTC displayed as 09:45:09, labelled UTC+8.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched and no behaviour changed beyond the heading text.

## 1.4.21

### Why
Every screen printed timestamps in UTC, so an operator in Malaysia read the whole log eight hours out and did the arithmetic in their head. The site timezone had been set in WordPress and was simply ignored.

And the tables were bad again. Two faults, both mine.

### What changed
Timestamps are shown in the site's own timezone, and the column heading says which one - Time (MYT) rather than Time (UTC). Named zones give their abbreviation, offset-only configurations give GMT+8 or GMT+5:30, and a site left on UTC still says UTC.

**Storage does not change and will not.** Events are recorded in UTC and stay that way, because a log written in local time lies twice a year at the daylight-saving boundary and cannot be lined up against a server log or a host's records. Storage and presentation were different problems and only presentation was wrong.

The detail column is no longer monospaced wholesale. A sentence like "mtime check: suppressed 7 files at ..." was being rendered as terminal output, wrapping to three lines and pushing every row to triple height. Monospace is for things compared character by character - hashes, paths, addresses - and prose is not one of them, so it now uses the normal typeface with embedded tokens keeping their own styling.

The incidents activity column collapses repeated steps. An incident of seventy-eight failed sign-ins rendered as the words "login failed" repeated across the full width of the screen; it now reads "login failed x78". Runs collapse independently, alternating steps are left alone, and a long chain is truncated with a remainder count.

Column widths were rebalanced. The event name column had been sized for the longest label rather than the common case, which left a channel of empty space down the middle of the table.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all seventeen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 33-check suite.

Conversion is asserted against the operator's own configuration: 01:39:32 UTC reads as 09:39:32 in Kuala Lumpur. Half-hour offsets, negative half-hour offsets, named zones, and a site left on UTC are each asserted separately. An unparseable timestamp is asserted to be displayed as-is rather than blanked, because a value that cannot be converted is still worth showing.

Storage is asserted to remain UTC by checking that nothing writes a local timestamp into the log. Collapsing is asserted not to merge alternating steps, which would misrepresent an incident.

Two harness defects fixed. One suite asserted the absence of `date( 'Y-m-d H:i:s' )` and matched `gmdate( 'Y-m-d H:i:s' )` by substring, reporting a fault that did not exist. Another did not load the shared utilities class that the renderers now call, which the autoloader supplies in production.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched.

## 1.4.20

### Why
Requested. I had argued against it in 1.4.19 and recorded it as rejected; the operator wanted it, and it is their plugin and their key.

The reservation stands and is worth stating rather than burying: the figure this reports is dominated by Akismet's ordinary comment checking. The login guard contributes roughly one call per blocked address, so on most sites this panel describes Akismet's day job more than it describes anything here. The screen says so plainly rather than letting the number imply otherwise.

What it does add is a real answer to a question 1.4.18 could not answer - whether the key is being throttled - and a concrete figure in place of my assurance that the login checks cost almost nothing.

### What changed
Diagnostics and Settings now show monthly Akismet usage for the configured key: calls used, the plan limit, the percentage, and a prominent warning if Akismet reports the key as throttled for consistently exceeding its plan.

Built against Akismet's published specification rather than inferred: a GET to `/1.2/usage-limit` on `rest.akismet.com` over HTTPS with the key in the query string, returning `limit`, `usage`, `percentage` and `throttled`. It is requested directly rather than through the bundled plugin, because `Akismet::http_post()` posts to a hardcoded `/1.1/` path and this is a GET against `/1.2/`.

Two details from the specification that would have been easy to get wrong. `limit` is documented as possibly being the string `none` for an unlimited key, so it is not cast to an integer and is displayed as "unlimited" rather than as the literal word. And the documented error response is the plain string `invalid` rather than JSON, so a non-JSON body is handled as a contract rather than as a parse failure.

Cached for an hour, since a status panel should not consume the allowance it reports on. The existing "Test Akismet connection" button refreshes it, so the button reports one consistent picture rather than a fresh verdict beside an hour-old number. A failed read retries after five minutes instead of an hour.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all sixteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and the login-guard suite extended to 103 checks.

The documented endpoint, HTTPS scheme and query-string key are asserted rather than assumed. An unlimited key is asserted to read as "unlimited". A throttled response is asserted to be surfaced, including usage above the limit. Four failure modes - a transport error, the documented plain-text `invalid`, an HTML error page, and no key at all - are each asserted to degrade to a reported state rather than a fatal, with no request made at all when there is no key.

Two properties matter more than the rest. The hour cache is asserted to hold, so repeated page views make no further calls. And blocking an address is asserted to make no usage-limit request at all, so nothing about this reporting touches the login path.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched, and no change to when Akismet is consulted or what decides a block.

## 1.4.19

### Why
Documentation only. No code changed.

The Akismet integration in 1.4.17 was written and documented before I had seen Akismet's published API specification, so the docs hedged in two places where the spec turns out to be explicit. The integration was correct; the description of it was more apologetic than the facts warrant, which makes a supported arrangement read like a workaround.

### What the specification actually says
`comment_type` accepts "comment", "trackback", "pingback", **or a custom type**. The `wps-login-attempt` type this plugin sends is therefore a documented pattern rather than a liberty taken with someone else's API.

`comment-check` requires exactly three fields: `api_key`, `blog` and `user_ip`. `comment_content` is not among them. Sending a check with no content is a supported call, not something being got away with.

The endpoint list is confirmed from the specification rather than inferred from the plugin source: verify-key, comment-check, submit-spam, submit-ham, key-sites and usage-limit. None concerns authentication, which is what made the local-decision architecture necessary in the first place. That conclusion is unchanged; it now rests on the published contract instead of on reading someone else's implementation.

### What changed
The 1.4.17 changelog no longer describes a login check as a reputation lookup "wearing a comment's clothes", which implied the call was off-label. It is not.

### Also considered and rejected
The specification documents a `usage-limit` endpoint returning monthly call count, plan limit, percentage used, and a `throttled` flag. It was assessed as a health panel for the settings screen and rejected: the figure it reports is dominated by ordinary comment checking, so it would say very little about this feature specifically, and the throttle flag only fires on plans consistently over their limit. The existing connection test already answers the question it would have answered. Recorded here so the same idea is not revisited from scratch.

### Meta
No code changes, no new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`.

## 1.4.18

### Why
The login guard was activated and gave no sign of life. That is a fair complaint, and it is two separate problems wearing one coat.

The first is by design and was correctly implemented: Akismet is consulted only when an address crosses the threshold, so on a site that has not been attacked since activation there is genuinely nothing to report. One call per block, not per attempt, is the whole reason the login page never waits on the network.

The second is a real gap. A working installation and a broken one looked identical, and the only way to tell them apart was to be attacked. Nobody should have to wait for an incident to find out whether their security software is running.

### What changed
Diagnostics now answers the question directly, with four rows: whether login protection is active, whether Akismet was detected and holds a key, how many failed sign-ins have been seen today and over seven days, and how many addresses were blocked over the same periods. Where Akismet has actually been used, a fifth row breaks the verdicts down into known-bad, clean, and no answer.

Counting failed attempts costs nothing extra and is bounded by the same rule that bounds everything else here: an address can only be counted until it is blocked, after which the gate rejects it before this code runs.

Blocks now record which logic chose their duration. Previously the block list showed a length with no explanation, so an Akismet-informed block was indistinguishable from the default. The reason now reads in plain words - address known for spam, address not known for spam with a shorter cool-off, or no usable answer and the default - and the verdict is stored as a field for anything that wants to filter on it.

And there is a "Test Akismet connection now" button in Settings. It calls Akismet's own key verification and reports back in one of four states: the key is valid and verdicts will be used, the key is not valid, Akismet could not be reached, or Akismet is not active. That gives a definite answer immediately rather than after the next attack.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all sixteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and the login-guard suite extended to 81 checks.

A fresh install is asserted to report zero rather than nothing. Attempts are asserted to be counted below the threshold, where no block and no Akismet call happen, which is exactly the state that previously looked like failure. Each of the three duration paths is asserted to name itself in the block reason and to record a matching field. On-demand verification is exercised across six states - Akismet unavailable, no key, valid key, invalid key, throwing, and returning something unrecognised - and asserted never to fatal. The handler is asserted to check both a nonce and a capability.

One inconsistency fixed on the way, found by the suite rather than by reading: the reason string said "clean" while the stored field said `akismet-ham`. Ham is Akismet's vocabulary and has no business in a block list, so both now say clean.

### Meta
No new files (51 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched, and no change to when Akismet is called or what decides a block.

## 1.4.17

### Why
Automated credential guessing against wp-login.php, and a question about whether Akismet could be hooked up to stop it.

Akismet turned out to be the wrong tool for the decision and a good tool for one part of it, and reading the plugin source settled it rather than my recollection. There are seven API endpoints - token, verify-key, deactivate, get-stats, comment-check, submit-spam, submit-ham - and not one concerns authentication. A login has no content to classify, so a check is largely a reputation lookup on the address and user agent.

The number that actually shaped this release is in Akismet's HTTP client: a fifteen-second timeout. Put that on the path of a login attempt and an attacker who can make Akismet slow can pin every PHP worker on the site just by hammering the login form, while an Akismet outage would mean no protection at all.

So the local counter decides whether to block, always, with no network in the path. Akismet decides only how long, after the decision is already made.

### What changed
A failed-login throttle. Five failures from one address within fifteen minutes blocks it, and the gate runs on `authenticate` at priority 1, so a blocked address is rejected before WordPress looks up a user or hashes a password.

Bot-favourite usernames - admin, administrator, root, test and a dozen more - are blocked on the first attempt rather than the fifth, but only when no such account exists on the site. A site that genuinely has a user called admin gets ordinary counting instead, which is what keeps this near-zero false positive.

An option to disable XML-RPC authentication and strip `system.multicall`, which is how one request carries hundreds of credential guesses. Off by default, because Jetpack and the mobile apps sign in that way and turning it on silently would break them.

Akismet enrichment, on automatically whenever the Akismet plugin is active and holds a key - there is nothing to configure and no key to enter twice, because `Akismet::get_api_key()` already has it. A known-bad address gets twenty-four hours, a clean-looking one gets fifteen minutes on the grounds that it is more likely a person who mistyped their password, and no usable answer gets the sixty-minute default. One call per blocked address, cached for a day.

### Not locking the operator out
This blocks addresses, which is the same failure class as the must-use guard withdrawn in 1.4.15, so the protections are in the design rather than a follow-up.

A logged-in administrator's address is never blockable. Addresses that have recently completed an administrator sign-in are remembered for thirty days and protected, which covers the operator who is logged out. There is an allowlist for shared office and VPN egress. Every block expires. And `define( 'WPS_DISABLE_LOGIN_GUARD', true );` in wp-config.php switches everything off with FTP alone - checked before the database setting, deliberately, because it exists for the case where wp-admin cannot be reached.

Counters are transients, so the store cannot outlive its window, and once an address is blocked the gate rejects it before the counter can fire again - so a blocked bot stops generating writes entirely. Both bounds are structural rather than a threshold hoped to hold.

### Verified
php -l across all twenty-seven includes and the bootstrap; node --check on admin.js; all sixteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 58-check suite.

The threshold is asserted to fire at five and not four. A logged-in administrator is asserted to survive fifty failures, and an address that completed an admin sign-in to survive twenty more while logged out. A bot username is asserted to block instantly when no such account exists and to fall back to ordinary counting when one does.

Akismet is exercised in five states - absent, present without a key, throwing, returning something malformed, and working - and every one is asserted to produce a working block, with the four broken states falling back to the default duration. It is asserted not to be called at all below the threshold, called exactly once per blocked address rather than per attempt, and to receive `user_ip` explicitly rather than inheriting it from the request, since that default is correct only while the call runs inline. The payload is asserted to carry no password field and no content.

One harness defect fixed, the fifth of its kind: the autoloader suite pinned the literal map size of 26, which failed the build when a class was legitimately added. It now derives the count from the classes on disk, which is the invariant that actually matters and was already asserted in both directions immediately below it.

### Meta
One new file, `includes/class-login-guard.php` (51 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched.

Two honest limits. This runs inside PHP, so WordPress still boots for every attempt - it reduces damage, noise and lockout risk, not server load, and a Cloudflare rule or fail2ban on the access log beats all of it because they reject before PHP starts. And it stops guessing, not a correct password from a stolen credential. That is two-factor authentication, and it is its own piece of work.

## 1.4.16

### Why
The events table was called ugly, which it was, but the useful part of that complaint is underneath the appearance: every row carried identical visual weight. A wp-config.php hash change - the most serious thing a site can report - sat in the same grey as an admin screen being viewed. A table where nothing stands out is a table nobody reads, and a security log nobody reads is decoration.

Three separate faults were behind it.

Event names were inconsistent. Types with a curated label read as English, and anything without one printed its raw identifier, so a single screen showed "Scan found issues" on one line and "admin_screen_visited" on the next.

Severity was not shown at all. The Events tab did keep two hand-written lists of "alert" and "ok" event types for row colour, but the overview had nothing, and those lists had already drifted from the codebase.

And the markup carried inline styles - column widths, padding, borders - which is exactly what the tokenisation work was meant to remove.

### What changed
Severity is now the first thing the eye lands on. A rail down the left of each row and a dot beside the label, driven by a shared classifier rather than by anything each screen keeps for itself. Two channels rather than colour alone, so the ranking survives a colourblind reader and a greyscale print, and the band is announced to screen readers.

Unmapped event types are humanised instead of printed raw, so the column reads as English whether or not anyone remembered to add a label. Curated labels still win where they exist.

The Events tab's private alert and ok lists are gone, along with the incidents table's inline column widths. All three tables - recent events, full events, incidents - now share one shell, one severity source, and one set of tokens, with dark scheme rules stated explicitly rather than derived, because the light tints are composited against white and go muddy over a dark panel.

### The bug this turned up
The first draft of the severity map keyed the wp-config change on `wp_config_hash_changed`. The event this plugin actually emits is `wp_config_modified`. The name was never emitted anywhere, so the most serious event a site can raise would have been classified as routine and rendered in the same grey it was already in - a redesign that changed the appearance and fixed nothing.

It was caught by checking the map against the real call sites instead of trusting it, and that check is now part of the suite: a severity key naming an event that is neither emitted nor known to the label map fails the build. The same check found `guard_events_overflow`, left behind when the tamper guard was withdrawn in 1.4.15, and removed it.

### Verified
php -l across all twenty-six includes and the bootstrap; node --check on admin.js; all fifteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 54-check suite.

Ninety-five emitted event types are read from the call sites and every one is asserted to resolve to a valid band. Ten types that must never look routine are asserted critical by name. Genuinely informational events - settings saved, diagnostics exported, baselines recorded - are asserted to stay quiet, and a clean scan is asserted green rather than grey, because a good result is worth seeing. Unknown, empty and differently-cased types are asserted to resolve safely rather than fatally. Both tables are asserted to carry the severity attribute, the second non-colour channel, and the screen-reader text, and to use the shared helpers rather than anything local.

One harness defect fixed, and it is the fourth of its kind: a test asserted the literal string `<th class="wps-strong wps-muted" style="width:110px">User</th>`, which broke when that inline width moved to CSS with no behaviour change. It now asserts that a User column exists. After the indicator version in 1.4.5, the require_once spelling in 1.4.8 and the version literal in 1.4.14, the pattern is well established and the rule is worth restating: assertions test intent, never a literal spelling of the implementation.

### Meta
No new files (50 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched. Inline style attributes in the overview drop from five to two.

## 1.4.15

### Why
Withdrawn at the operator's request, after two outages in a week traced to it.

The feature was tamper protection: a must-use plugin that loaded before ordinary plugins, checked this one was still active, and put it back if something had removed it. Useful against malware that disables the scanner before doing anything else. It is also the only component an operator cannot switch off from the dashboard, which is what made it work and what made a fault in it so costly.

Both faults are documented in 1.4.13 and 1.4.14. Neither is really the point. The point is that a component with no off switch has to be held to a standard the rest of the codebase is not, and this one was not - it shipped without a bound on a per-request write, without its own crash handler, and keyed on a dot-file that ordinary hosting tooling silently discards.

### What changed
The guard is gone, and removal is active rather than passive. Not installing it is not enough: a must-use plugin already on disk keeps loading for ever, so leaving it in place would have left the bug running on every site that ever installed it.

Upgrading deletes the three files it wrote and clears the five options it used. Only those exact filenames in that one directory are touched - nothing is globbed, walked, or pattern-matched, so no other plugin's must-use file is at risk. Where deletion fails, typically a read-only mu-plugins directory, the file is overwritten with an inert stub so the withdrawn code stops running anyway, and diagnostics reports the leftover with its path.

The class shrinks from 613 lines to 208, and what remains is the removal path plus no-op methods that return their old shapes, so a stale reference cannot fatal. The must-use file template, the signing apparatus and the event spool are gone outright. The bootstrap no longer calls into any of it, and the `pre_update_option_active_plugins` filter is removed.

It is written up as a parked feature at the head of doc/upgrading.md rather than deleted quietly, with four conditions that would have to hold before it returns. The idea was worth having, and someone will be tempted to build it again.

### What this costs
The plugin no longer notices being removed from the active plugin list, so malware that deactivates it will now succeed silently. That is a genuine reduction in capability and it should not be glossed over. The trade is that nothing this plugin installs loads before WordPress any more, and every part of it can be switched off from the Plugins screen.

### Verified
php -l across all twenty-six includes and the bootstrap; node --check on admin.js; the remaining fourteen harnesses re-run as regressions; render-smoke at 9/9 tabs; and a new 42-check suite.

The removal is tested from the state a 1.4.14 site is actually in: all three files present, all five options set. Files and options are confirmed gone, the withdrawal audited once, and the cleanup confirmed not to repeat on subsequent requests - it is a single option read after the first run. A downgrade followed by an upgrade is confirmed to clean up again. Every installation entry point is confirmed inert: install() refuses and writes nothing, ensure_key() writes no key, write_state() and import_events() do nothing.

Two cases matter more than the rest. Removal is confirmed to touch only its own three files, with another plugin's must-use file, an unrelated dot-file and an unrelated subdirectory all left alone. And the codebase is asserted to contain no remaining write into mu-plugins at all, with the file template and signing apparatus confirmed absent - so the feature cannot come back by accident.

Two harnesses retired with the feature: the guard-installation suite from 1.4.6 and the bounds suite from 1.4.14 both test code that no longer exists.

### Meta
No new files (50 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched.

## 1.4.14

### Why
Asked how anyone could be confident 1.4.13 would not white-screen a site again, I built the test that answers it rather than giving an assurance: run the guard in its worst state - signing key permanently absent, plugin never running to heal it - across 200,000 requests with the clock advancing, and measure the spool.

It grew to 52 MB. Worse than the version it was supposed to fix.

Two faults, both mine, both a day old.

The size cap read `filesize()` without clearing PHP's stat cache. In a process handling one request that is invisible, because the cache is cold every time - which is why it passed. Held open across many requests, every check after the first read a stale size and the ceiling never triggered.

And the throttle was in the wrong place. 1.4.13 throttled the signature-failure path, which was the one causing the reported outage, and left the other three writing on every request. One of those is the directory-missing path - which fires when the plugin folder is renamed, the exact recovery step recommended for an outage.

### What changed
The bound moved to the choke point. Every record now passes one throttle, keyed by event type, one per fifteen minutes, inside the recording function itself rather than at each caller. A safety bound that individual callers have to remember is not a safety bound, and this release is the evidence.

`clearstatcache()` runs before the size check, so the ceiling holds regardless of how the process is reused.

Re-measured under the same conditions: 262,160 bytes against a 256 KB cap, where 1.4.12 produced 34 MB. The ceiling holds, and the import side never parses an oversized spool anyway - it discards it with a single summary event, and caps any in-bounds run at 200 entries.

### Verified
php -l across all twenty-six includes and the bootstrap; node --check on admin.js; all fifteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; the scanner still does not flag its own guard; and the guard suite extended to 32 checks.

Two new cases, both testing the thing that failed rather than the thing that was fixed. Sixty requests with the plugin directory renamed are asserted to produce at most three events, with no event type appearing more than once inside the window - the case 1.4.13 missed entirely. And the generated must-use file is asserted to contain both the stat-cache clear and the choke-point throttle, so neither can be quietly dropped from the template.

The worst-case measurement is kept as a standing test rather than a one-off, because a bound that is not measured under load is a comment.

One further test defect fixed: the 1.4.12 suite pinned the literal version string `1.4.12`, which broke on the next release with the behaviour under test unchanged. It now reads the version from the source. That is the third time a pinned literal has broken a passing test - after the indicator version in 1.4.5 and the require_once spelling in 1.4.8 - and the rule is by now well earned: assertions test intent, never a literal spelling.

### Meta
No new files (50 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`. Must-use file version bumped, so every install regenerates on upgrade.

The honest summary of the last three releases: the plugin caused an outage, the first fix was incomplete, and it took a worst-case measurement to find that out. What is different now is not confidence, it is that the ceiling is measured under load and the measurement runs on every build.

## 1.4.13

### Why
The white screen was mine. The must-use guard shipped in 1.4.6 caused it, and this release fixes the fault rather than the symptom.

The guard signs its expected-state record with a key held in a dot-prefixed file beside it in mu-plugins. If that key is missing, the state can never verify - and the guard treated an unverifiable state as tampering and recorded it. Correctly, but on every single request, with no throttle, because the condition is permanent rather than momentary. Measured: fifty requests produced fifty records.

Dot-files are exactly what backup, migration and sync tools skip by default. So a restored or migrated site gets the guard without its key, and starts appending to a spool file on every page load.

The other end is what actually kills the site. The plugin imports that spool by reading the whole file into memory, splitting it into an array, and calling the tamper-evident audit log once per line - each call computing an HMAC chain link and doing a database insert. A hundred thousand requests produce roughly seventeen megabytes and a hundred thousand lines, and importing that exhausts memory or execution time. A blank page.

Neither half was a syntax error. It was an unbounded loop with a fuse, and the fuse was however long the site took to get traffic.

### What changed
Bounds at every point where there were none.

The guard throttles the unverifiable-state record to once every fifteen minutes, the same window already used for the not-loaded check, and refuses to append to the spool at all once it exceeds 256 KB. The import side refuses to parse an oversized spool, discarding it with a single summary event rather than importing it line by line, caps any run at 200 entries, and truncates unconditionally so nothing accumulates for next time.

And the root cause is healed rather than endured: when the plugin runs it now checks for the signing key, and regenerates it and re-signs the expected state if it is missing or malformed. That ends the condition instead of recording it for ever. It does not weaken the consent model - the only thing that reaches that code is this plugin, running, with write access to mu-plugins, which is precisely the access the 1.4.6 notes already concede cannot be defended against.

The must-use file version is bumped, so every existing install regenerates the fixed guard on upgrade.

### Verified
php -l across all twenty-six includes and the bootstrap; node --check on admin.js; all fifteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; the scanner still does not flag its own guard; and a new 28-check suite.

The failure is reproduced first and then re-run against the fix, with the guard executed in separate processes as before. Fifty requests with the key missing produced fifty records before and produce exactly one after. The throttle is confirmed to release after its window. An oversized spool is confirmed to receive no further writes, and on the import side to be discarded with one summary rather than four thousand individual audits - the specific behaviour that took the site down. The line cap is confirmed at 200 with unconditional truncation. Key healing is confirmed to regenerate, re-sign, audit once, no-op when the key is valid, treat a malformed key as missing, and - the point of the whole exercise - to stop the write loop at source, with forty subsequent requests recording nothing.

One test defect fixed: the suite read `filesize()` without clearing PHP's stat cache, so a later assertion saw an earlier test's file size and reported a file as oversized when it was not. Same defect as the stale stat in 1.4.2.

### Meta
No new files (50 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`.

Worth stating plainly, because it is the second time in three releases that this plugin has been the problem rather than the thing finding problems: the guard is the one component that cannot be deactivated from the dashboard, which makes it the worst possible place for a fault. 1.4.12's safe mode does not cover it either, since a must-use plugin loads before the plugin that would catch it. Bounds on anything that writes per-request belong in the design of that component, not in a later release.

If you removed the guard files by hand while recovering, upgrading restores them; no manual step is needed.

## 1.4.12

### Why
An operator reported a white screen. I could not reproduce it - the full bootstrap, a complete scan, the forensics run, every code path changed in 1.4.11 and all nine admin tabs execute cleanly, and there is no PHP 8-only syntax anywhere against the declared requirement of 7.4.

That did not matter, because the report exposed a worse problem than whatever caused it. A security plugin that can take a site down has already done more damage than most of what it defends against, and until this release nothing stopped that happening. A fatal anywhere in this plugin was a fatal for the whole site, with the message hidden behind a blank page, and the tamper guard shipped in 1.4.6 made it worse: deactivating through the database - the obvious remedy - would have been undone by the guard on the next request.

So rather than guess at a cause, this release makes the failure mode survivable and self-reporting.

### What changed
Three things, and they work together.

A shutdown handler records fatal errors that originate inside this plugin's own files, checked by path. Another plugin's crash is never claimed, which matters as much as catching our own: blaming a neighbour would send someone hunting in the wrong codebase.

Safe mode reads that record on the following request. If the previous run died inside this plugin, only the passive core loads - no scanning, no CSP headers, no drop-in guard, no admin screens, no remediation. In testing, a healthy boot registers fifty-nine hooks and a safe-mode boot registers three. The site comes back up, and the plugin says plainly that it is not protecting anything at the moment, which is the one thing a security plugin must never be quiet about.

Every bootstrap registration now runs inside a wrapper that catches a throw, records it with the name of the step that failed, and lets WordPress carry on. The autoloader also stops short of a fatal when a class file is missing or unreadable - an interrupted upload or a half-finished update is an ordinary way for that to happen, and a caller's class_exists() check copes with a false far better than a site copes with a blank page.

Recovery is a button. The admin notice carries the file, line, message, timestamp, and whether the crash happened on the front end or in wp-admin, with a nonce-protected action to clear the record and try again. Upgrading clears it automatically, since an upgrade is the usual fix.

### Verified
php -l across all twenty-six includes and the bootstrap; node --check on admin.js; all fourteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs; the scanner still does not flag its own guard; and a new 29-check suite.

That suite induces real fatals in separate processes, because a crash handler tested by simulation is not tested. A genuine undefined-function fatal inside the plugin is confirmed to be recorded with its file, line, message, version and request context; the next request is confirmed to enter safe mode, register far fewer hooks, and complete without error; the hourly scan and CSP headers are confirmed absent while unsafe, and the notice and clear action present. A crash induced in a different plugin's directory is confirmed neither recorded nor capable of triggering safe mode. Deleting a class file outright is confirmed not to fatal, with class_exists() returning false instead. A throw inside a boot step is confirmed not to escape and to be recorded with its step label. And clearing the record, or bumping the version, is confirmed to restore the full hook set.

One harness defect fixed. The 1.4.8 autoloader suite asserted the literal string `require_once WPS_DIR`, which broke when the autoloader began resolving its path into a variable first for the readability check - identical behaviour, different wording. Rewritten to assert the intent: exactly one require_once in the bootstrap, and it lives inside the autoloader closure. That is the same lesson as the pinned indicator version in 1.4.5, and it has now cost two releases.

### Meta
No new files (50 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`; no detection logic touched.

This does not identify the reported white screen. If it recurs on 1.4.12 the site will stay up and the notice will name the file and line, which is the information that was missing. If it does not recur, the cause was elsewhere - worth remembering that the same site has an unexplained wp-config.php modification and cron handlers with no file behind them, and that broken injected code produces a blank page exactly like a plugin fatal does.

## 1.4.11

### Why
An operator sent in seven scan findings, and reading them turned up two faults in this plugin rather than two faults on their site.

The first was dangerous advice. Two findings concerned cron callbacks, and both carried the instruction to remove the event with `wp cron event delete`. The hooks were `wp_version_check` and `wp_scheduled_delete` - WordPress core's own scheduled jobs. Following that advice would have stopped the site checking for security updates, and it would not have removed anything: deleting a schedule does not remove the code that registers a handler for it, so the callback returns on the next request and the core job does not.

The second was a misclassification hiding the most useful signal the check can produce. Both findings were rated MEDIUM with the verdict `missing_file`, which is reached when reflection returns a filename and `realpath()` then fails on it. For a closure declared inside `eval()`'d code, PHP reports the filename as `/real/file.php(123) : eval()'d code` - a string no `realpath()` will ever match. So a scheduled job whose handler exists only in evaluated code, with nothing on disk to inspect, was being filed next to ordinary resolution failures.

That is close to the definition of the persistence this plugin exists to find.

### What changed
`eval()'d code` is now its own verdict, rated high, checked before `realpath()` is attempted. It also catches the `runtime-created function` marker left by `create_function`. The finding preserves the part of the path before the parenthesis, because that names whatever performed the eval, and it includes a ready-to-run command that prints the declaring file of every closure on that hook - the fastest way to tell a legitimate plugin from an injected one.

Advice is now aware of the hook as well as the verdict. Sixteen WordPress core scheduled events are recognised, and for those the guidance is explicit that the event must not be deleted, that deleting it would not remove the handler, and that the thing to find is whatever registers the callback. It also says plainly that plenty of legitimate plugins extend core jobs, because they do. Non-core hooks still get the removal instruction.

The same conversation produced a third change. The operator's own plugin appeared in the report of plugins that cannot be checksum-verified, which is correct but useless - wordpress.org has no baseline to offer for code that was never published there. Settings now takes a list of plugins you wrote, and those drop out of that report.

Dropping them into silence would have been the wrong trade, because "my own plugin" is a comfortable place to add a file that nobody checks against anything. So a local baseline is kept instead: every PHP file is hashed, the set is reduced to one fingerprint, and it is stored against the plugin's version. A version change refreshes it silently, because that is an update. A fingerprint change with no version change is reported, because editing files in place is what both an undeclared hotfix and a planted file look like, and only the operator can tell those apart.

### Verified
php -l across all twenty-six includes and the bootstrap; node --check on admin.js; all thirteen prior harnesses re-run as regressions; render-smoke at 9/9 tabs with structural counts unchanged; the scanner still does not flag its own guard; and a new 47-check suite.

Both faults are tested at the point they failed. `eval()'d code` and the `create_function` marker are asserted to reach the new verdict, while a genuinely absent file still resolves to `missing_file` and an empty filename still to `unresolvable`, so the fix does not swallow the cases it was not meant to change. Core-hook advice is asserted to contain no delete instruction and to explain why deletion would not help, and a non-core hook is asserted to still receive one. The eval advice is asserted to name the origin file with the line-number suffix stripped and to carry the probe command parameterised to the actual hook.

The first-party feature is tested across its whole life: parsing accepts a bare slug and a slug/file.php pair and rejects malformed input; first sight baselines silently; an unchanged plugin stays silent; a version bump re-baselines silently; a file added with no version bump is reported once, at high severity, review-only, and does not nag afterwards; and a declared plugin that is not installed is not an error.

### Meta
No new files (50 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1`.

Both faults were in code that had shipped and passed its own tests. They were only visible in the output of a real scan on a real site, which is worth recording: the harness proves the check runs, and only an operator reading the result proves the check is right.

## 1.4.10

### Why
An operator reported new accounts appearing on a site where "Anyone can register" was switched off. Every detector shipped before this one looks at files. This attack leaves no file to look at, which is exactly why it kept working.

Three rows in wp_options turn a WordPress install into an account factory. `users_can_register` opens registration. `default_role` decides what a new account becomes - WordPress ships it as subscriber, and set to administrator it means anyone completing the registration form is an administrator, with no backdoor file needed at all. And `wp_user_roles`, the quietest of the three: leave the default role alone and instead grant subscribers `manage_options` and `activate_plugins`, and the Users screen shows a tidy list of subscribers who can all install plugins.

None of that touches disk. A file scanner can be working perfectly and see nothing.

### What changed
Detection at both ends, because they answer different questions.

At scan time, the three settings are checked directly. A default role of administrator is critical and says so plainly; editor or author is high, since that is occasionally deliberate. Registration being switched on is only reported when the plugin previously recorded it as off - and once reported, the baseline updates, so it says its piece once rather than nagging. Non-administrator roles are checked for capabilities they do not ship with, naming the exact ones granted.

At event time, the option changes are hooked as they happen. That is the half worth having: scan-time detection tells you the site is in a bad state, while the event tells you when it happened and who was signed in when it did. A default role raised to a privileged one scores 120 - the same weight as a new administrator account, because the outcome is the same - and registration opening scores 70. Both flow into the incident timeline, so registration being opened and the default role being raised in one sitting reads as a single high-risk incident rather than two unrelated log rows.

Everything here is review-only. Site configuration is not malware, and silently rewriting a membership site's registration settings would be a worse failure than the one being detected. The findings say which option to change and what to change it to, and the capability check acknowledges that membership and e-commerce plugins do legitimately extend roles.

### Verified
php -l across all twenty-six includes and the bootstrap; node --check on admin.js; all twelve prior harnesses re-run as regressions; render-smoke at 9/9 tabs with structural counts unchanged; the scanner still does not flag its own guard; and a new 37-check suite.

The reported scenario is tested first and by name: registration closed, default role administrator, detected as critical. Stock WordPress is confirmed clean - subscriber default, unset default role, and an untouched role table all produce nothing. Baseline behaviour is checked in both directions, including that a reopening is not re-reported once the baseline catches up. Capability tampering is asserted to name the granted capabilities and to leave administrators alone. The event hooks are fired rather than called, and asserted to capture the actor, to score a no-op change at nothing, and to record a role being lowered at low risk. Opening registration and escalating the default role in one window is confirmed to sum to 190 and band as high, with no rule written for that pair.

### Meta
No new files (50 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1` - no indicator lists moved.

## 1.4.9

### Why
The forward notes at the top of the upgrade guide had gone stale in a way that made them worse than useless. They described 1.3.98, 1.3.99, 1.4.0 and "1.4.1 onwards" as work still to come - all of which shipped several releases ago. Anyone reading the upgrade guide to find out what was ahead was being told about the past.

### What changed
The forward notes now cover what is genuinely ahead: the scanner restructuring, internationalisation, and EDR Phases 2 through 5, each written in terms of what an operator will notice at upgrade time rather than as a feature list.

Three things were added that were not there before. The open gating decisions are stated plainly - geolocation, session fingerprinting, and deception - along with what each would cost and why nothing happens until a decision is recorded, so the reason those fields sit empty is documented rather than mysterious. There is an honest note on sequencing: six consecutive releases between 1.4.1 and 1.4.6 came out of live samples and displaced the planned work each time, and the roadmap should be read as intent rather than a schedule. And there is a short list of what will not change - behavioural findings are never auto-remediated, nothing calls a third party without a recorded decision, and deactivating from the Plugins screen always works.

That last point is worth stating in the documentation rather than only in a changelog entry, because the tamper guard added in 1.4.6 is exactly the kind of feature people reasonably worry might fight them.

### Verified
Documentation only; no code changed. php -l across all twenty-six includes and the bootstrap, node --check on admin.js, all twelve harnesses re-run as regressions, render-smoke at 9/9 tabs with structural counts unchanged, and the scanner still does not flag its own guard - run in full because a release that claims to change nothing should be made to prove it.

The tree was rebuilt from the shipped 1.4.8 package before any edit, and every edit asserts its anchor appears exactly once, per the rule recorded in 1.4.8.

### Meta
No new files (50 entries). Version markers moved in all six places. `INDICATOR_VERSION` unchanged at `1.4.5-1`.

A documentation change earns a version bump here rather than a quiet republish, and the reason is mechanical: since 1.4.2 the plugin's own Markdown files are covered by the self-integrity baseline, which is keyed to the version. Republishing changed documentation under an unchanged version number would make every existing install report its own docs as modified.

## 1.4.8

### Why
An architecture review, and one finding large enough to act on immediately.

Every class was loaded on every request. Serving an anonymous visitor a single page made WordPress parse roughly 865 KB of this plugin - the admin screens, the remediation controller, forensics, the vendored Markdown parser, and the 320 KB scanner that only ever runs on cron or when an administrator asks for it. None of that is reachable on a front-end request. OPcache softens the parse cost but not the per-process memory or the class linking, and this plugin is built for exactly the shared hosting where OPcache is most often absent or starved.

### What changed
Classes are autoloaded from an explicit map. A typical front-end request now loads about 36 KB - the behavioural hooks, the drop-in guard, and the CSP header check - instead of 865 KB. That is 96 percent deferred, and nothing was moved, renamed or rewritten to achieve it.

An explicit map rather than a derived path, deliberately. Most class names do map cleanly onto their filenames, but three do not, and a security plugin quietly failing to load a class because of a clever naming rule is not a trade worth making. The map doubles as the class inventory, and a test asserts it stays complete in both directions.

Conditional requires were the obvious alternative and would have been the wrong answer. The review turned up two hazards that make the case: the blocker calls the scanner without a guard, and the drop-in guard - which runs on init on every request - probes for scanner methods with method_exists and falls back to different behaviour when it does not find them. Hand-guessing which context needs which class would have silently changed what the plugin does on ordinary page loads. Autoloading cannot, because a class is loaded exactly when something references it. Both hazards now have tests that assert why they are safe rather than merely that they exist.

The two admin registrars are additionally gated on is_admin(), since between them they register only admin_menu, admin_enqueue_scripts, admin_post_* and wp_ajax_* - and both admin-ajax.php and admin-post.php report is_admin() as true. That is another 93 KB front-end requests no longer touch.

Separately, the reference documentation has been brought up to date. Across 1.4.2 to 1.4.7 the version line in doc/readme.md was bumped every release while its content was not, so it still described a plugin that ended at the Content-Security-Policy and event-log era: no mention of tamper protection, behavioural monitoring, cloaked injectors, split-literal normalisation, file-operation shells or PHP configuration overrides, and an Admin Tabs list that omitted the Docs tab added in 1.4.2. readme.txt still framed the plugin as ClickFix-only. Both now describe what actually ships.

### Verified
php -l across all twenty-six includes and the bootstrap; node --check on admin.js; all eleven prior harnesses re-run as regressions; render-smoke at 9/9 tabs with structural counts unchanged; the scanner still does not flag its own guard; and a new 18-check suite.

The autoloader suite checks the things that would hurt if they were wrong. Every class declared on disk is asserted to be in the map, and every mapped path is asserted to exist and to declare the class it claims, so adding a class without registering it fails the build rather than failing in production. All twenty-six classes are then resolved by executing the real autoloader in a separate process, not by inspection. An unmapped foreign class name is confirmed to be passed over without error, which matters because the autoloader sees every class any other plugin asks for. The load footprint is measured rather than recalled.

One harness defect fixed: the render-smoke prelude did not stub is_admin(), which the bootstrap now calls. is_admin() is defined by WordPress core long before plugins load, so the call is correct and the harness was incomplete - the same shape of gap as the missing ARRAY_A in 1.4.7.

A process note, recorded because it changed how this release was built. Twice during it, the working tree held files that matched neither what shipped in 1.4.7 nor what this release's own edit scripts produced - first doc/readme.md, later the changelog and version markers. Rather than ship anything that could not be accounted for, every documentation file was reset to the shipped 1.4.7 baseline and all edits reapplied in a single deterministic pass. The code change was kept only because it is covered by a test suite that passes against it. Every line of this release has a known origin.

### Meta
No new files (50 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1` - no detection lists moved, and no detection logic was touched at all.

Two findings from the same review are deliberately not in this release, because each deserves its own. The scanner is 7,356 lines carrying 55 detection checks in one class, which wants splitting along the seam that already exists. And there is no internationalisation anywhere - no text domain, no load_plugin_textdomain(), no translation calls - a genuine repository-guidelines gap given readme.txt is written in wordpress.org format.

## 1.4.7

### Why
Every release up to now answered one question: is this file known-bad? That is scanning, and it only ever sees what an attacker left behind. This is the first release that answers a different one - what happened here?

The samples analysed across 1.4.1 to 1.4.5 kept arriving as finished artefacts. Something put them there, and the sequence that did so was invisible, because nothing was watching: an account signed in from an unfamiliar address, opened the plugin installer, uploaded a file, activated it. A scan finds the web shell afterwards. A timeline shows the account that uploaded it, and everything else that account did while it was there.

This is EDR Phase 1 from the roadmap adopted back at 1.3.97, and it has been displaced six times by live-sample work. That was the right call each time - a confirmed blind spot beats a planned feature - but the displacement had a cost, and this closes it.

### What changed
Three things, which are really one thing.

The plugin registers its first behavioural hooks: sign-in and sign-out, failed sign-ins, account creation, role elevation, password resets, plugin activation and installation, theme switches, media uploads, and admin screen views. Each records a scored event into the tamper-evident store built in 1.3.99, which has carried session, incident, and correlation fields since then waiting for exactly this.

Events that share an actor within a thirty-minute window are grouped into an incident. Grouping is deliberately simple - the same user, or failing that the same address - because incident grouping is what an operator reads when deciding whether they have been breached, and a clever correlator nobody can reason about is worse than an obvious one. Matching on address as well as user matters: a run of failed sign-ins carries no user id, and the successful sign-in that follows belongs to the same story.

Each event type carries a weight and an incident's risk is the sum of its events. That is the whole trick, and it is worth being clear about why it works. One sign-in scores 10 and means nothing. A sign-in, then the user list, then a new administrator account, inside one window, scores 138 and lands in the high band - without anyone having written a rule for that specific sequence. The two anchors are the roadmap's (a successful sign-in is 10, a new administrator account is 120) and the rest sit relative to those and to the audit weights already in use since 1.4.0, so one table governs both. It ships as a filter, because recalibrating once real timeline data exists is expected rather than hypothetical.

An Incidents card sits at the top of the Events tab showing each incident's actor, address, event count, cumulative risk, band, and the sequence of what happened, newest first.

Two restraints worth naming. Admin screen views are limited to a defined set - the user list, the user editor, the file editors, the plugin installer and list, general settings, the export tool - and repeat visits within one session are collapsed, because recording every admin page view would fill a store that caps at ten thousand rows with noise. And behavioural findings are observations only: a high-risk incident raises an alarm and never removes anything, which is the same discipline that governs file detections.

Per the roadmap's gating decisions, this ships without GeoIP (Decision 1), so country, city, asn, and impossible-travel scoring stay null and dormant; without client-side fingerprinting (Decision 2); and without deception (Decision 3). Nothing here makes a third-party network call.

### Verified
php -l across all twenty-six includes and the bootstrap; node --check on admin.js; all ten prior harnesses re-run as regressions; render-smoke at 9/9 tabs with inline-handler counts still at zero and structural counts unchanged; the scanner still does not flag its own guard; and a new 58-check suite.

The fixture harness gained WordPress hook stubs, as the roadmap required, so behaviour is tested by firing the real hooks rather than by calling methods directly. Every hook is asserted to register. The roadmap's two score anchors are asserted literally, all four bands are checked at their boundaries, and the score table is confirmed filterable. A sign-in is verified to carry its session token, an incident id, the client address, and null GeoIP fields. Incident grouping is tested in all three directions: a second event from the same user joins, a different user and address starts a new incident, and anonymous failed sign-ins group by address.

The sequence that matters gets its own test: sign-in, user list, new administrator account is asserted to be one incident of three events summing to 138 and banding as high, with the timeline reading oldest-first and the account creation marked critical. Role elevation is recorded only when it is genuinely an elevation - a sideways change is ignored, and so is a role set on someone who was already an administrator. Screen throttling is verified to collapse a repeat visit and to record again once the window expires, and logged-out views are not recorded at all.

Two harness defects were found and fixed rather than worked around. The suite did not define ARRAY_A, a WordPress core constant the codebase already relies on elsewhere. And the chain-integrity test was wiping table rows directly while the chain anchor persisted, which desynchronised the two and produced a failure that looked like a real one. Rebuilt on clean state, it now proves something stronger than originally written: the chain verifies across behavioural events, and altering a recorded risk score is detected.

### Meta
One new file, includes/class-edr.php (50 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1` - no detection lists moved. Decision 5 resolved by adopting the roadmap's score values as shipped defaults, filterable in one place. Phase 2 (behaviour baselines, trusted devices) is next.

## 1.4.6

### Why
Attackers were switching the plugin off on sites where it had been activated from the dashboard, and there was nothing to stop them or even to notice. The reason is structural rather than a bug: every defence this plugin has runs inside the plugin, so disabling it first defeats all of them at once.

Disabling is cheap. Any backdoor executing as PHP already holds the database credentials out of wp-config.php, so removing this plugin's entry from the active_plugins option is a single query - no files touched, no admin action, no warning anywhere. Deleting the plugin directory works just as well, because WordPress silently drops missing plugins from the active list on the next page load. A must-use plugin that unhooks it is worse still: the dashboard keeps showing the plugin as active while it does nothing. And simply unscheduling the hourly cron leaves everything looking healthy while scanning quietly stops.

There was also a loose end. The deactivation hook carried a comment reading "Intentionally keep MU file - it must survive plugin deactivation", but nothing in the codebase ever wrote such a file. The intent had been recorded years before the implementation existed.

### What changed
A must-use guard. Files in mu-plugins load before regular plugins, cannot be deactivated from the dashboard, and never appear in active_plugins at all, so the techniques used to disable a security plugin do not reach them. On each request the guard confirms the plugin is still in the active list, restores it when it is not, and records the fact. It also notices the two quieter failures: a plugin directory that has been deleted, which it reports rather than re-adding a broken entry that would only produce an error, and a plugin that is listed as active but never actually loaded, which is what unhooking or a swallowed fatal looks like from outside.

Consent was the hard part, and it is worth being explicit about. A guard that re-activated the plugin whenever it disappeared would fight the site owner turning it off deliberately, which is malware behaviour and would have been unacceptable to ship. So expected state is recorded explicitly: activation records that the plugin should be active, the deactivation hook records that it should not, and the guard only ever restores when the recorded expectation says active. Deactivating from the Plugins screen works exactly as it always did.

That expectation is signed with a key held in a file beside the guard, which matters because of who can write what. An attacker holding only database access - SQL injection, a stolen database user - can write "deactivated on purpose" into the option but cannot forge the signature, and an unsigned or altered expectation is treated as tampering rather than believed. Because the guard and its key live in mu-plugins rather than inside the plugin directory, deleting the plugin does not take its protection with it.

The guard cannot write to the chained event log, since the whole point is that it runs when the plugin does not. It appends to a small file instead, which the plugin imports into the tamper-evident store on the next request where it does run, so tampering ends up in the same signed chain as everything else. Separately, the running plugin now watches active_plugins directly and records any removal that has no genuine administrator request behind it - the value is passed through unchanged rather than blocked, because refusing the write could wedge a site in a redirect loop. Guard status is shown in Diagnostics, since a guard that failed to install because mu-plugins is not writable needs to be visible rather than assumed.

### Verified
php -l across all twenty-five includes and the bootstrap; node --check on admin.js; all nine prior harnesses re-run as regressions; render-smoke at 9/9 tabs with inline-handler counts still at zero and structural counts unchanged; and a new 40-check suite.

The guard was tested by running it, not by inspecting it: the generated file is executed in a separate process against a simulated WordPress, and asserted to restore the plugin when it is removed, to stand down when the owner deactivated it deliberately, to reject a forged consent record and restore anyway, to report a deleted plugin directory rather than re-adding a broken entry, and to do nothing whatsoever on a healthy site. The generated file is confirmed to pass php -l, to reference none of the plugin's classes, and to silence its filesystem calls so it fails open - a guard that white-screened a site would be worse than the problem it addresses. Signature handling is tested in both directions, event import into the chained log is verified to forward once and clear, and the active_plugins watcher is confirmed to record a silent removal while staying quiet for a genuine admin deactivation.

One check worth naming separately: the scanner is verified not to flag the guard it just installed. A security plugin that quarantines its own protection would be a poor joke.

### Meta
One new file, includes/class-guard.php (49 entries). `INDICATOR_VERSION` unchanged at `1.4.5-1` - no detection lists moved.

Stated plainly, because overselling this would be worse than not shipping it: an attacker with write access to mu-plugins can delete the guard, its key, and everything else. This is not invulnerability, and no defence that runs inside the site can be. What it buys is that switching the plugin off silently stops being possible - every attempt now has to defeat the guard as well, and anything short of that leaves a signed record. EDR Phase 1 moves to 1.4.7.

## 1.4.5

### Why
A sample calling itself Native Image Optimizer passed all sixteen detectors. What makes it worth a release is not that it was missed - it is why, because the reason invalidates an assumption the whole scanner rested on.

Its indicators were already catalogued - completely. Six Polygon RPC endpoints, eth_call, the entire EtherHiding set had been in the lists since 1.3.78, and the on-chain contract address the payload reads from was already recorded in the blocker and the scanner as a confirmed indicator from an earlier sample. This was not a new campaign and not an unknown one. Nothing matched anyway, for two independent reasons.

First, the payload never exists in readable form on disk. It sits in a binary resources file behind a custom header, and is reversed, XOR-decrypted against an embedded key, and inflated at runtime. Every catalogued indicator is inside that blob, encrypted.

Second, and more damaging, the loader splits every meaningful identifier across concatenated fragments. Not just suspicious names - all of them. Searching the plugin's source for wp_footer, googlebot, administrator or eth_call returns zero matches while the code uses all four. Content matching had simply been switched off, and nothing announced it.

What the payload does, once assembled: it fetches its next stage from a smart contract on the Polygon blockchain, so there is no domain to take down and the RPC endpoints it reads through are legitimate public infrastructure that cannot be blocklisted. The operator updates the payload by writing to the contract. The JavaScript it delivers uses the clipboard, which is the ClickFix pattern this plugin was originally written for - the same campaign, several evolutions on.

The cloaking is worth spelling out because it explains why site owners do not find these. The injector returns early for logged-in administrators, editors, and authors, so browsing your own site shows nothing wrong. It returns early again for eighteen crawler user agents - Googlebot, Bing, Yandex, Ahrefs, Semrush, Lighthouse, PageSpeed, the link previewers - so external scanners and search engines report the site as clean. It suppresses page caching so the payload is never cached and never leaves a trace in a cache file. Only ordinary logged-out visitors are served anything.

### What changed
Source is now normalised before it is matched. A read-side pass collapses concatenated string literals back into whole tokens, so wp_footer written as three glued fragments becomes wp_footer again. Nothing is written to disk. This matters beyond this sample: every existing indicator list keeps working against split-literal evasion instead of being silently defeated by it.

On top of that, a check that matches behaviour rather than tokens, because tokens can be hidden and behaviour cannot. It looks for three things co-occurring in one file: several crawler user agents being checked in order to avoid them, privileged logged-in users being skipped, and output being injected into the page. Each alone is ordinary - geo-plugins check user agents, membership plugins check roles, plenty of plugins inject footer markup. All three together describes content shown to visitors and deliberately concealed from both the administrator and everything that might report it, which has no honest reading. Where the file sits in its own plugin or theme folder, that whole folder is the malware and is removed; the containing-directory resolver refuses to nominate the plugins directory itself.

Identifier splitting is also flagged on its own, as review-only. The threshold is measured rather than guessed: across this plugin's own twenty-four files, some 315 KB of code, the highest count in any single file is three, while the sample carried seventy in under five kilobytes. Both an absolute floor and a per-kilobyte rate are required, so a large file that accumulates a few honestly is not flagged.

### Verified
php -l across all twenty-four includes and the bootstrap; node --check on admin.js; all eight prior harnesses re-run as regressions; render-smoke at 9/9 tabs with structural counts unchanged; and a new 36-check suite. Normalisation is tested on three-fragment and six-fragment chains, both quote styles, and confirmed to leave variable concatenation and ordinary literals alone and to skip oversized input. The live sample is detected with all six tells recorded, the whole fake plugin folder is nominated rather than the single file, removal works and lands in quarantine recoverable.

The false-positive controls are the part that matters, and all hold: an analytics plugin listing bots in order to exclude them from statistics is not flagged, because it neither skips administrators nor injects; a membership plugin that checks roles and injects footer markup is not flagged, because it does not cloak against crawlers; an SEO plugin naming crawlers in comments is not flagged, because it never inspects the request user agent. For the obfuscation check: 315 KB of this plugin's own code is not flagged, three splits in a small file are below the floor, and twelve splits diluted across a large file fail the rate gate while dense splitting in a small file is caught.

One regression surfaced and was fixed properly rather than patched over. The 1.4.1 harness asserted an exact INDICATOR_VERSION string, so this release's legitimate bump failed it. The assertion tested the wrong thing - it now asserts the value has moved off the pre-1.4.1 baseline and cannot regress to it, which is what it always meant.

Honest limits: the decoded JavaScript was read to identify its infrastructure and behaviour, not executed, and what the contract currently serves is whatever the operator last wrote to it. The blockchain stage is identified, not characterised.

### Meta
No new files (48 entries). `INDICATOR_VERSION` moves to `1.4.5-1` - two genuinely new indicator lists, the crawler-avoidance user agents and the cache-suppression constants. Version markers bumped in the other five locations. EDR Phase 1 moves to 1.4.6.

## 1.4.4

### Why
Four more live samples. Three of them - lobdgok, fxkohks, and cokefga - are the same campaign as the vrhpkgc sample behind 1.4.3: the same genuine "Protect Uploads" plugin used as camouflage, dropped into a folder with a random seven-character name, with the payload in the root index.php. Two of the three are byte-identical to each other. The fourth is the single-file Plugin-<hex> shape already in the catalogue, and it was caught twice over by existing checks with nothing new to learn.

Every sample was already detected before any code was written this release, which is the point of testing first. The problem was how two of them were caught. fxkohks and cokefga were flagged only by position - the index.php stub anomaly check from 1.4.3 - and not by technique, which means review-only rather than removal. Reading them explained why. Their payload is a 283-line file called DarkStealth v3 and it contains no eval, no assert, no system, no shell_exec, and no encoded blob. It does not execute anything. It browses directories, writes files, deletes them, creates folders, and accepts uploads, all driven straight from request parameters. An attacker uploads a PHP file through it and then requests that file; the web server does the executing. The generic web-shell check requires user input inside an execution construct and is structurally blind to this, and the file-manager check from 1.4.1 matches Tiny File Manager's constant cluster, which this is not.

lobdgok added a second thing entirely: a php.ini inside the plugin folder setting disable_functions to NONE, open_basedir off, and exec and shell_exec on. An attacker who cannot run exec because the host disabled it drops a configuration file next to the payload and tries again. Per-directory php.ini is honoured on CGI and FastCGI, .user.ini on PHP-FPM. There was no coverage for this at all.

### What changed
Two checks. The first detects file-operation web shells by capability cluster rather than by brand or by execution primitive: a single file that browses the filesystem, performs several distinct mutating operations, and accepts uploads, all driven by raw request superglobals rather than sanitised WordPress APIs. Keeping false positives down matters here because legitimate media and backup plugins do touch the filesystem, so the capabilities must co-occur in one file, the drivers must be raw superglobals, and remediation is gated on position - removed automatically only in the index.php stub position where no legitimate reading exists, reported for review anywhere else. The second reads php.ini and .user.ini files and flags directives that switch hardening back off: disable_functions cleared, open_basedir removed, shell execution re-enabled, auto_prepend_file or auto_append_file set, allow_url_include on. Inside wp-content that is critical, because nothing legitimate there has any reason to change PHP security settings. In the web root it is high rather than critical and always review-only, since a host may have placed that file deliberately and silently deleting configuration can take a working site down.

Both samples that were previously position-only are now caught by technique as well, which is what moves them from review to removal.

### Verified
php -l across all twenty-four includes and the bootstrap; node --check on admin.js; the 1.3.97, 1.3.98, 1.3.99, 1.4.0, 1.4.1, 1.4.2, and 1.4.3 harnesses re-run as regressions; render-smoke at 9/9 tabs with structural counts unchanged; and a new 30-check suite covering both directions. The shell fixture is confirmed to contain no execution primitive at all and is still caught, while the execution-focused check is confirmed to still miss it, which documents the gap rather than assuming it. False-positive controls hold: a plugin doing filesystem work through sanitised WordPress APIs is not flagged, a file with superglobals but only one mutating operation is not flagged, a file below the size floor is ignored, an ordinary host php.ini containing only memory and upload limits is not flagged, and a dangerous directive in a file that is not named php.ini or .user.ini is ignored. Case and spacing variants of the directives still match, and both checks dedupe correctly across the dual-root walk.

Samples were read statically and never executed, and all extracted copies were removed from the build environment afterwards. As always, there is no live WordPress here.

### Meta
No new files (48 entries). `INDICATOR_VERSION` unchanged at `1.4.1-1`: both additions are technique detectors living in the scanner, with no indicator lists moved - the same reasoning as the .htaccess work in 1.3.97. Version markers bumped in the other five locations. EDR Phase 1 moves to 1.4.5.

## 1.4.3

### Why
Two samples came in for analysis and one of them was a confirmed blind spot - every one of the eleven existing detectors returned zero. That is the most valuable thing a sample can be.

The clean one first, because it matters as a control: a theme built on the Omega framework, entirely legitimate, zero suspicious constructs. It is now part of the test suite as a false-positive control, since a detector that catches malware but also flags honest themes is not useful.

The other was a genuine plugin - Alexis Blondin's GPL "Protect Uploads" - sitting in a randomly named folder with a backdoor hidden in its root index.php. That file was 19 KB across two lines: control flow shredded into goto jumps, every function name rebuilt at runtime from single-character array offsets so no string matching can see it, and a 19,000-character compressed blob handed to a single eval. The plugin around it is real software, used as camouflage. Meanwhile the same plugin's admin, includes, and languages directories each held the normal 26-byte "Silence is golden" placeholder. That contrast is the whole story: index.php is one of the few files in a WordPress tree with a known-benign canonical form, and almost nobody ever reads it, which is exactly why it is a favoured hiding place.

### What changed
Two checks, deliberately independent, so that defeating one does not defeat both.

The first detects the packing technique rather than any particular payload, because there is no string to match: goto and label control-flow flattening, runtime string reconstruction from character arrays, kilobytes of code compressed onto a handful of lines, a large embedded encoded blob, and a dynamic execution primitive. Three independent tells are required, at least one of which must be an execution or payload tell rather than layout alone. Remediation is split by position: in an index.php, where the canonical content is a placeholder, a packed loader has no legitimate reading and is removed - into quarantine by default, so it stays recoverable; anywhere else it is reported for review, because a small number of commercial plugins genuinely ship through obfuscators and deleting a licensed plugin's main file would break a working site.

The second ignores technique entirely and looks at position: an index.php in a plugin, theme, or upload directory that is larger than a placeholder and carries executable logic. This still fires on a plain, unobfuscated backdoor that the packer check would miss, and it requires real executable content rather than mere size, so a long comment header does not trip it. Review-only, since a few plugins do use a functional root index.php.

### Verified
php -l across twenty-four includes and the bootstrap; node --check on admin.js; the 1.3.97, 1.3.98, 1.3.99, 1.4.0, 1.4.1, and 1.4.2 harnesses re-run as regressions; render-smoke at 9/9 tabs with exit code, FATAL absence, and tab count all asserted; and a new 20-check suite: the live backdoor is caught by both checks independently with three or more tells recorded and the sibling-stub corroboration surfaced in the finding text, the clean theme is flagged by neither, removal takes the backdoor and leaves the surrounding legitimate plugin intact, and it lands in quarantine recoverable. Five negative controls hold: an ordinary large plugin file, a long base64 asset string without eval or goto, a genuine "Silence is golden" stub, a file using goto with no payload, and a large comment-only index.php are all left alone. Two synthetic variants confirm the split works: a plain unobfuscated backdoor in stub position is caught by position alone, and a packer outside stub position is detected but correctly not auto-deleted.

Two defects were caught by the harness and fixed. The sibling-stub corroboration globbed the wrong directory level - neighbouring plugins rather than subdirectories of the same plugin - so the strongest piece of evidence never reached the finding text. And a 1 KB size floor silently skipped a complete packer that fitted in 976 bytes; the floor is now 600 bytes, with the tell count rather than file size deciding.

Honest note on scope: the payload itself is a third encrypted layer requiring a runtime key, so what it ultimately does is not established here. Detection does not need it - the technique fingerprint is what identifies the file - but nobody should read this changelog as a claim about the payload's behaviour.

### Meta
No new files (48 entries). `INDICATOR_VERSION` unchanged at `1.4.1-1`: both checks are technique detectors carrying their own patterns, and no indicator list moved - consistent with how the .htaccess redirect rules were handled in 1.3.97. Version markers bumped in the other five locations. EDR Phase 1 moves to 1.4.4.

## 1.4.2

### Why
The documentation shipped inside every release but could only be read by opening files over FTP or digging through the plugin folder - which is exactly when you least want to, since the moment you need the upgrade notes or the changelog is usually the moment something is wrong. This release makes the bundled docs readable from a Docs tab in the admin.

### What changed
Parsedown 1.8.0 (MIT, single file) is vendored to render markdown, and the plugin now carries a Docs tab presenting the readme, upgrade notes, changelog, and reference document, each with a one-line description of what it is for. Everything is served from the files already inside the release, so it works with no internet connection.

Three decisions in this are security decisions rather than convenience ones. The library is vendored as WPS_Parsedown rather than Parsedown, because Parsedown is one of the most commonly bundled PHP libraries and a second global declaration of that class fatals the entire site - a failure this plugin would be causing rather than preventing. That rename is the only change from upstream; every other reference inside the file uses self:: or static::. The document to display is chosen from a fixed whitelist keyed by slug, so no path from the request ever reaches the filesystem and there is nothing to traverse regardless of what is submitted. And because this plugin's threat model explicitly assumes an attacker who already has file access, a tampered markdown file has to be treated as an attempt at admin XSS: the parser runs in safe mode so raw HTML is escaped and javascript: URLs are neutralised, the result is then passed through wp_kses_post() as a second independent layer, and doc files have joined the plugin's self-integrity baseline so tampering is reported by the scanner as well as contained by the viewer.

Rendering is cached against a fingerprint of each file's size and modification time, which matters because the changelog and upgrade notes are around 300 KB each; they are parsed once and re-rendered immediately whenever they change. Where the mbstring extension is missing, or the parser is unavailable or errors, the tab falls back to showing the escaped raw source rather than failing.

### Verified
php -l across all twenty-four includes and the bootstrap; node --check on admin.js; the 1.3.97, 1.3.98, 1.3.99, 1.4.0, and 1.4.1 harnesses re-run as regressions; render-smoke extended to nine tabs, all rendering with zero notices and inline-handler counts still at zero; and a new 31-check suite for the viewer: markdown features render, all four whitelisted documents open, six traversal payloads including encoded and mixed forms leak nothing and fall back to the readme, a doc tampered with a script tag, an onerror handler, a javascript: link, and an iframe emits none of them while still rendering the legitimate markdown around them, the cache populates and is genuinely reused, a modified file invalidates it, a missing file reports honestly instead of fatalling, the global Parsedown class is confirmed absent, and the MIT attribution and licence file are present.

Two real defects surfaced during verification and are fixed. PHP caches stat results per request, so the cache fingerprint could be computed from stale size and mtime values; clearstatcache() now runs before fingerprinting. And a class constant initialised from DAY_IN_SECONDS fatally errored when the class loaded without WordPress core constants present - replaced with a literal, because a documentation viewer must never be able to take down the admin. The mbstring fallback path was verified for real rather than simulated: the build container had no mbstring extension, so the degradation ran genuinely before the extension was installed to test the formatted path.

Worth recording plainly: the first run of the release gate reported green while the docs tab was fatalling, because the gate piped the smoke harness to tail instead of checking its exit code. The gate was corrected to honour exit codes, FATAL strings, and the expected tab count before this release was packaged. A verification gate that can pass while a tab dies is worse than no gate at all.

### Meta
Three new files: includes/vendor/class-wps-parsedown.php, includes/vendor/parsedown-LICENSE.txt, and includes/class-admin-docs.php (package grows to 48 entries: three files plus the new vendor directory entry). `INDICATOR_VERSION` unchanged at `1.4.1-1` - no detection lists moved. Version markers bumped in the other five locations. EDR Phase 1 moves to 1.4.3.

## 1.4.1

### Why
A live doorway-kit sample came in for analysis. The good news first: the existing detector from 1.3.83 caught it immediately, at maximum cue score, with all four structural tells firing and auto-removal armed. It is the same annealing/resweep family, not a new one. The bad news came from testing what happens when the sample is altered the way an operator would alter it. Renaming one directory - the kit's `core/` folder - dropped detection to nothing, because the detector required a directory with that literal name before it would score anything at all. A 226 KiB browser file manager bundled inside the kit was invisible to the web-shell check, since it contains no eval, no encoded payload, and no obfuscation; it is simply a complete filesystem-control application, which is exactly what makes it a capable shell. And the kit's cloaking configuration - the file that decides who sees spam and who sees a clean page, carrying 111,088 blocked IPs, 569 blocked user-agents, and 87 blocked orgs - was never read by anything.

### What changed
Kit detection no longer depends on a folder name the operator controls. Any directory is now a candidate and the structural cue score decides, so the misspelled backdor file, the hex-suffixed panel and file-manager components, and the ipManager/linkManager/settingsManager module triplet identify the kit wherever it sits and whatever it is called; a directory actually named `core` still counts as a corroborating tell rather than a precondition. A new cloaking-config check finds the kit by its configuration instead of its layout, which is the half that survives renaming: a JSON file carrying several of the catalogued cloak keys together, gated on a blocklist large enough to be an evasion list rather than a site setting - a handful of blocked IPs is ordinary configuration, tens of thousands is a kit hiding from crawlers and hosting providers. It reports the kit's own version string and blocklist sizes, and stays review-only, because deleting a configuration file alone leaves the kit running. A new file-manager check catches browser-based file managers by a cluster of their defining constants, never by one, with severity driven by location: inside uploads or cache, or sitting beside kit components, it is treated as a web shell; elsewhere it is a review item, since operators do legitimately install these. It is never auto-deleted - that judgement belongs to the owner.

### Verified
php -l across all twenty-two includes and the bootstrap; node --check on admin.js; the 1.3.97 (28/28), 1.3.98 (20/20), 1.3.99 (35/35), and 1.4.0 (24/24) harnesses re-run as regressions; render-smoke at 8/8 tabs with structural counts identical to the 1.3.96 baseline; and a new 20-check suite driven against the actual sample rather than a mock: the unrenamed kit is still caught (no regression), the kit with its `core/` folder renamed is now caught where it was missed before, the real settings.json is flagged by configuration fingerprint alone with its 111,088-entry blocklist and self-reported version surfaced, the 226 KiB file manager is detected and marked critical for sitting beside kit components, and the negative cases hold - a site's own small blocklist, ordinary JSON, a large ordinary plugin file, and a file carrying only two of the file-manager constants are all left alone. The harness caught one real bug during development: because wp-content normally lives inside the web root, walking both roots recursively reported the same file twice, fixed with a realpath dedupe guard. Standing caveat unchanged: no live WordPress here, and the sample was read statically and never executed.

### Meta
No new files (44 entries). `INDICATOR_VERSION` moves for the first time since 1.3.81, to `1.4.1-1`: this release adds two genuinely new indicator lists - the file-manager constant cluster and the doorway cloak-config keys. Version markers bumped in the other five locations.

## 1.4.0

### Why
This release closes out the security audit's high-priority list and marks the platform foundation as complete - hence the version number. Four gaps remained after 1.3.99. Destructive endpoints could be hammered as fast as a script could post to them. The plugin's actions were logged but thinly: an event said something happened without carrying what the original value was, what it became, or why. The plugin verified other plugins against wordpress.org but never verified itself - and a custom build is exactly the one plugin wordpress.org cannot vouch for. And a diagnostics export could be altered after the fact with nothing to prove it.

### What changed
Twenty-two destructive handlers now run through a per-user cooldown after their existing nonce and capability guard: five heavyweight irreversibles (salt regeneration, user deletion, plugin-folder deletion, quarantine empty, bulk base64-option deletion) at thirty seconds, seventeen per-item actions at ten - enough to blunt scripted rapid-fire without making legitimate bulk cleanup miserable, and every refusal is itself recorded as a rate_limited event. A new WPS_Event_Log::audit() helper generalises the quarantine manifest's stored_by/reason pattern to any action: who initiated it, what it acted on, the original value or a pointer to preserved evidence, the new value, the reason, and a risk weight - wired into salt regeneration, user deletion, plugin-folder deletion, the four wp_options deletion paths (which now capture their quarantine snapshot id and record it as the recoverable original), and the export itself, all flowing into the chained store with a file-log copy kept for the no-database fallback. The plugin now baselines its own php, js, and css files at install or upgrade - trust-on-first-use: the release you upload is the trusted state - and every scan diffs the live tree first, before anything else runs, reporting modified, missing, or unexpected files as review-only criticals; the runtime logs directory is excluded because it is mutable by design and the HMAC chain covers it. And diagnostics exports are signed: a sha256 of the exact bundle plus an HMAC under the per-install chain key, so a doctored support bundle fails verification.

### Verified
php -l across all twenty-two includes and the bootstrap; node --check on admin.js; the 1.3.97 (28/28), 1.3.98 (20/20), and 1.3.99 (35/35) harnesses re-run as regressions; the render-smoke harness at 8/8 tabs with structural counts identical to the 1.3.96 baseline; and a new 24-check fixture suite: the first cooldown call passes and the second is refused with the wait time and a recorded rate_limited event while a different action's bucket is unaffected, the audit helper maps action, object, risk, and original/new onto the schema with the initiating user auto-filled and the chain still closing, the export signature verifies under the chain key and a one-byte payload change fails it, and the self-baseline establishes on first run, verifies a clean tree, flags a modified file, a deleted file, and a dropped file as three review-only criticals with the failure audited, then silently re-baselines on a version change because an upgrade is a new trusted state. One incident worth recording: an environment reset mid-release wiped the test harnesses, and restoring them by re-running a historical command also re-ran an embedded CSS edit against the working tree - caught by diffing against the shipped 1.3.99 and restored byte-identical before anything was packaged, with the structural render counts confirming parity. The process rule that follows is in the SSOT.

### Meta
No new files (44 entries). `INDICATOR_VERSION` unchanged at `1.3.81-1`. Version markers bumped in the other five locations. This completes the hardening audit's high-priority list; the deferred low-leverage items (AuthorizationManager formalisation, Request/Validator split, REST hardening) remain recorded as deferred with reasons in the SSOT.

## 1.3.99

### Why
The event log was the weakest piece of forensic evidence the plugin kept: four fields, two hundred entries, one JSON file that anyone with file access could rewrite without a trace. Under the threat model this plugin already assumes - an attacker who reaches admin - the record of what happened was editable by the person it records. The hardening audit called for an immutable log; the EDR roadmap called for an enriched, correlatable one. Per the one-schema rule in the SSOT, they are the same subsystem, and this release builds it once as the foundation everything from 1.4.0 onwards writes into.

### What changed
A new WPS_Event_Log class stores events in a dedicated table carrying the full unified 24-field schema - user, role, session, incident and correlation ids, IP, geo fields, request context, object, severity, risk score - with fields the plugin cannot populate yet stored null so the record shape never changes underneath later phases. Every record is chained: prev_hash links it to its predecessor, curr_hash covers a canonical serialisation of its content, and an HMAC signature under a per-install key seals it. Editing a row breaks its own hash; deleting one breaks its successor's link; and the chain head is anchored in two places outside the table (an option and a PHP-guarded, randomised-name mirror file in the hardened log directory), so truncating or rebuilding the table leaves the anchors describing rows that no longer exist. The HMAC key is mirrored the same way and either copy restores the other. Rotation keeps the newest ten thousand rows and re-anchors the genesis hash so the surviving window still verifies; rotation is the only deletion path - the store has no clear button by design, and clearing the old file log now records the clearance as an event. The existing log_event() API is untouched: it now forwards every call into the store as a schema-shaped record while keeping the file copy as belt-and-braces and as the fallback when the database is unavailable, so all existing call sites gained chained records without moving. The old 200-entry file log is imported once as pre-chain rows - preserved evidence, counted separately, never claimed as verified. The Events tab reads from the store, gains a User column and a verification banner: green with the verified count when the chain closes, and an unmissable failure line naming the first bad record - or the anchor mismatch - when it does not. Storage engine per roadmap Decision 4, resolved this release: a table over a file, because phase 1's incident grouping is query-shaped work and a table survives the filesystem resets this project has already lived through.

### Verified
php -l across all twenty-two includes and the bootstrap; node --check on admin.js; the 1.3.97 (28/28) and 1.3.98 (20/20) fixture harnesses re-run as regressions; the render-smoke harness at 8/8 tabs, which now also proves the no-database fallback since it runs without a wpdb; and a new 35-check fixture suite driving the store through an in-memory wpdb: table creation and one-time legacy import as pre-chain, five signed records verifying with both anchors matching, an edited middle row flagged at the exact record id, a deleted tail row flagged as suspected truncation, pruning that re-anchors genesis with the surviving window still verifying, the log_event shim double-writing store and file, clear() recording its own clearance, key and anchor mirrors on disk with PHP guards and the key restored from its mirror after option loss with the chain continuous across the restore, and the renderer showing the verification banner, the User column, the tamper line with record id, and the clean file-log fallback. Honest limits, stated in the class header and here: this is tamper-evident, not tamper-proof - an attacker holding database write access AND the HMAC key AND both anchors can rebuild the chain; what the design guarantees is that the common case, a direct UPDATE or DELETE against the table, is detected. And as always: no live WordPress or MySQL here - the wpdb in the harness is an in-memory stand-in speaking the exact SQL shapes the class uses.

### Meta
One new file: includes/class-event-log.php (package grows to 44 entries). `INDICATOR_VERSION` unchanged at `1.3.81-1` - no detection lists moved. Version markers bumped in the other five locations. Roadmap Decision 4 recorded as resolved in the SSOT.

## 1.3.98

### Why
Four gaps carried over from the Tier-2 backlog. A removal that returns success was trusted at its word, so a permissions race or an instant re-drop could masquerade as a clean remediation. Every family detector matched its own structural shape, so a rotated loader with a brand-new shape but a known C2 domain sailed through until someone wrote a detector for it. Redirect injections in theme functions.php - the classic traffic-theft persistence - had no dedicated check. And on constrained hosts a full scan could outlast max_execution_time and die mid-pass, caching nothing and reporting nothing.

### What changed
Removal is now verify-then-report: after any remediation claims success, the scanner re-checks the filesystem, and a target that still exists is reported as unverified with re-dropper hunt guidance instead of as a clean removal - and it never joins the parent-handled skip list, so children aren't silently passed over. A new unified C2 sweep reads every PHP-executable file under wp-content plus the web root's top level against the merged catalogue from the new WPS_Indicators::all_c2_domains() aggregator (cookie-exfil, TDS, and ClickFix download hosts in one list; the victim-site list is deliberately excluded). It's review-only, because security tooling legitimately ships blocklists containing exactly these domains. A new functions.php check walks every theme, dormant ones included, and flags a redirect primitive - header/wp_redirect to an external host, echoed window.location, meta refresh, or a runtime-decoded target - only when paired with a cloaking or obfuscation tell (encoding functions, hex escapes, referer/UA gating, visitor-only gating, eval); a redirect alone is never enough, which is what keeps legitimate themes out of the report. And the scan now runs on a 45-second wall-clock budget: checks that haven't started when it's exhausted are skipped and named in a scan_budget_exhausted finding, the last-scan record is marked partial, and a running check is never interrupted - honest degradation instead of a silent death.

### Verified
php -l across all twenty-one includes and the bootstrap; node --check on admin.js; the render-smoke harness at 8/8 tabs with zero notices; the full 1.3.97 fixture harness re-run as a regression (28/28); and a new 20-check fixture harness for this release: the merged C2 catalogue carries all three family lists, a .phtml implant and a web-root implant are both flagged while a clean file and a plain-text mention are not, the infected and hidden-target functions.php fixtures are caught while a tell-free external redirect and a same-host redirect are left alone, the budget skips remaining checks once exhausted, a genuine removal verifies clean, and a refused removal is reported as failed with the target confirmed persisting. One honest limit: the success-then-persists race itself needs a live re-dropper to reproduce, so that branch is asserted structurally (present, and ordered before the parent-handled list) rather than provoked. The harness also exposed a latent undefined-key notice on the failure path's action text, fixed with null-coalescing.

### Meta
No new files. `INDICATOR_VERSION` stays `1.3.81-1`: all_c2_domains() is an aggregator over the existing family lists and carries no entries of its own, and both new checks are technique detectors. Version markers bumped in the other five locations.

## 1.3.97

### Why
WP Perf Shield reads PHP well. Six gaps in this release were about the artefacts and paths it wasn't reading. A referer- or user-agent-cloaked redirect lives entirely in .htaccess rewrite rules, and nothing looked there, so a doorway could quietly send search-engine traffic to a pharma domain while the owner saw a clean site. Sixteen content walkers tested for a literal '.php' extension, so a payload dropped as shell.phtml or shell.phar walked straight past them. Signature scanning covered plugins but never themes, so a shell parked in an inactive theme sat in a dead zone. delete_option() on a malicious row destroyed the evidence along with it. Pre-clean backups were copied next to the file being cleaned, which left an infected copy in the webroot under a guessable name, still executable through a second extension. And the re-drop tripwire only watched wp-content, while the kit's confirmed favourite spot is the web root itself.

### What changed
One executable-extension test now backs every walker. is_php_executable() checks the same PHP_INVENTORY_EXTS set the inventory uses - php, phtml, php3 through php7, phps, pht, phar - and all sixteen walkers, the re-drop pre-filter, and the external-payload-loader classifier run through it; the ZIP check and the two existing inventory sites were left alone. A new check_htaccess_redirects() reads .htaccess at the web root, wp-content, and uploads, parses each RewriteCond/RewriteRule group, and flags a rule that redirects to an external host only when it's gated on HTTP_REFERER or HTTP_USER_AGENT, calling out search-engine-referer and crawler-UA conditions as the doorway signature. It's review-only - hotlink-protection rules share the same grammar - so it reports the offending rule and never touches .htaccess. Signature scanning now walks every theme, active or dormant, with the delete target scoped to the specific theme folder. Before any malicious wp_options row is deleted, quarantine_option() snapshots it - name, serialised value, autoload flag - into the store as a recoverable entry that restores through update_option, with object instantiation blocked on the way back; all six deletion paths, auto and manual, snapshot first. Pre-clean backups now copy into the quarantine store through a new copy mode rather than landing beside the file, so the pre-clean bytes end up neutralised and non-executable in the protected store while the live file stays put to take its cleaned content; the wordfence-waf.php and .user.ini inline backups were folded onto the same path. The re-drop tripwire adds a shallow pass over the web root's top level, so a root-dropped kit trips the RE-DROPPED counter it used to slip past. Three fields joined the quarantine manifest while that code was open: a sha256 of the stored file, the login of whoever triggered the action, and the detection reason.

### Verified
php -l across all twenty-one includes and the bootstrap; node --check on admin.js; the render-smoke harness across all eight tabs with zero notices and the structural assertions from 1.3.95/1.3.96 intact. A new fixture harness plants live artefacts against a sandboxed install and drives the new code directly: a .phtml/.phar/.php7 file reads as executable while .txt/.js/.zip don't; a google-referer external redirect is flagged while a same-host hotlink rule and an unconditional canonical redirect are not; a signature in an inactive theme is caught with the theme folder as the delete target while a clean theme is left alone; a known-hash file planted at the web root is detected as a re-drop; a malicious option round-trips through quarantine_option and restore with its value intact; and a pre-clean backup lands in the store as a copy with the original left in place and no .wps-backup file beside it. Twenty-eight checks, all passing. Same standing caveat: there's no browser here, so no screenshots, and the fixtures exercise the detection logic rather than a live WordPress request.

### Meta
No new files - every change edits an existing class. `INDICATOR_VERSION` stays `1.3.81-1`: the extension set is infrastructure, the .htaccess rules are technique regexes, and every new finding reuses an existing fingerprint, so the indicator list itself didn't change. Version markers bumped in the other five locations.

## 1.3.96

### Why
1.3.95's tokenisation changed colour values it was only supposed to route. The sweep normalised where the brief was preservation: #c00 rendered as a muted rose, the gold and orange severity pills went brown-amber, two distinct greens collapsed into one, the warm-yellow forensics callouts were reinvented as generic warn tints, and the legacy retokenise pass flattened the findings-panel pastels and decorative gradients into four severity tokens. Compounding it, Appearance defaulted to Auto, so anyone whose operating system runs dark got an invented dark palette by surprise. The result on screen was not the plugin the user approved.

### What changed
The legacy stylesheet region is restored byte-for-byte from 1.3.94 - the findings panel, source cards, pills, gradients, and hero render exactly as before. The component layer was rewritten value-exact: one token per distinct original colour, every light value taken from the 1.3.94 PHP inline styles rather than from a normalised palette. Where 1.3.94 used different shades for the same role on different surfaces, the classes now honour that instead of unifying it - the system-check labels keep their #16815d/#bf2f45 pair while status text elsewhere keeps #1a7f37/#a32d2d, the overview scan-result KPI keeps its #c00, the non-critical forensics callouts return to warm yellow #fff9de with the #d4af00 rule and #7a5e00 labels, the hardening rebaseline note returns to amber #faeeda/#ef9f27, the remediation warning boxes return to their border-only #e4b9b9 style, the events table gets its #fafafa zebra alternation back, and the logs error box keeps its #7a2a2a text. Appearance now defaults to Light: the original appearance is the default experience and dark is strictly opt-in (Auto remains available for those who want OS-following behaviour).

### Verified
A pin-table check resolves every colour declaration in the component layer through the token map and asserts byte-equality against the 1.3.94 originals - 56 of 56 exact. The legacy region is asserted byte-identical to the 1.3.94 file. The render-smoke harness still passes all eight tabs with zero notices, the structural assertions from 1.3.95 hold (no inline onclick, no inline scripts, delegated data attributes intact), and the settings default renders scheme=light with the Light option selected. Same caveat as always: no browser here, so no screenshots - but byte-identical CSS in the legacy region plus a value-equality proof for the component layer is a stronger parity claim than 1.3.95 could make.

### Meta
`INDICATOR_VERSION` unchanged at `1.3.81-1`. Version markers bumped in the six locations. Process rule adopted into the SSOT: tokenisation must be value-preserving; palette changes ship only with explicit approval.

## 1.3.95

### Why
Three standing workspace preferences were being contradicted by the plugin's own admin markup, and the 1.3.94 design review measured the gap precisely. 511 inline style attributes sat across the nine renderer files, carrying 68 hardcoded colours that bypassed the eight-token layer admin.css already declared. The Settings tab ran every option through one continuous form under a heading that only described its first two fields. Six inline onclick handlers and an inline script block in the self-block notice shipped from a plugin that carries its own CSP hardening class. And there was no colour-scheme support at all, which is exactly what the half-built token layer existed to enable.

### What changed
The token layer is now complete: roughly thirty custom properties on `.wps-app` covering surfaces, hairlines, three text tiers, severity background/line pairs, the mono stack, the brand accent, and a scheme-aware gradient endpoint. A component layer sits on top of it - cards (with flush, padded, and alert variants), tables whose th/td styling comes from descendant rules, notes, badges, dots, the KPI set, status boxes, and a small set of spacing and text utilities.

The inline-style sweep took the renderers from 511 attributes to 24 in source, which is 22 at render time across all eight tabs. The survivor policy is explicit: column widths, dynamic bar widths, JS-toggled `display:none`, and table min-widths stay inline because they are sizing and state; colour and typography never do. Every dynamic colour ternary became a class ternary - PHP now chooses the class and CSS owns the colour, from the overview KPI cards through the diagnostics status rows to the forensics verdict labels.

A dark scheme rides on the tokens. The new Appearance setting (Auto / Light / Dark) writes `data-wps-scheme` onto the plugin wrapper; Auto follows `prefers-color-scheme`. The legacy stylesheet was retokenised property-aware so the findings panel, source cards, and pills follow the scheme too. Three things stay constant by intent: the hero heading gradient approved in 1.3.63, the brand pill, and `color:#fff` on coloured surfaces.

Settings is now four sectioned cards inside the tabbed admin - Detection rules, Remediation, Blocking & uploads, Appearance - each with a heading that actually describes its scope, all saved by the one form. Event handling reached zero inline onclick and zero inline scripts: `forensic_action_button()` emits `data-wps-action` / `data-wps-data` / `data-wps-confirm` consumed by a delegated listener in admin.js, copy buttons use `data-wps-copy`, and the self-block notice behaviour moved into admin.js, which the blocker now enqueues wherever the notice renders. The 31 emoji entities in card titles and buttons became semantic Dashicons with `aria-hidden` and inherited colour; buttons and tabs gained focus-visible outlines; the remediation status region carries `role="status" aria-live="polite"`.

### Verified
`php -l` passes across all includes and `node --check` across admin.js. A render-smoke harness (WordPress stubbed, the real `WPS_Admin::render_page()`) renders all eight tabs with zero notices and asserts the structural claims directly: 0 onclick, 0 inline scripts, the scheme attribute on every tab, delegated data attributes present, 22 residual style attributes at render time. The harness caught one real defect before release: the appearance option read its raw key inside a ternary's true branch, so a fresh install without the key raised an undefined-index notice on every tab - both the read and save paths now hoist the guarded value. Not verified: pixel-level parity. There is no browser in this environment, so no screenshots; visual fidelity rests on the class mappings being faithful to the styles they replaced, plus the deliberate normalisations named in Upgrading.

### Meta
`INDICATOR_VERSION` unchanged at `1.3.81-1` - no detection lists were touched. Version markers bumped in the six locations.

## 1.3.94

### Why

Every removal path in the plugin was destructive: `auto_remediate()` and the manual delete buttons ended in `@unlink` / `delete_directory()`. That carried two costs. A false positive was unrecoverable, and the forensic evidence this plugin exists to gather was destroyed at the exact moment it mattered most. Reviewing the delete path also surfaced a real bug: `delete_directory()` refuses any path outside `WP_CONTENT_DIR`, so a doorway kit planted at the site root - the exact shape of all four confirmed re-drops - was flagged `auto_delete` on every scan yet never actually removed. Detection said "handled"; the kit stayed live.

### What

Quarantine-first remediation. Confirmed threats are moved into a hardened store instead of being destroyed, every file is neutralised so nothing can execute or match a detector, and each entry is restorable for 30 days before automatic purge. Hard delete remains available as a setting and as the fallback when quarantine refuses or fails, so a threat is never left live.

### Changes

- New `includes/class-quarantine.php` (`WPS_Quarantine`). Store at `wp-content/wps-quarantine/` hardened with a deny-all `.htaccess` (`Require all denied` + `php_flag engine off`) and an index stub. `quarantine()` moves a file or directory under `store/<id>/payload/`, appends `.wpsq` to every file (non-executable, invisible to the content scanners), and writes a `manifest.json` (original path, kind, file list, timestamps, finding type/severity). `restore()` reverses the neutralisation and moves the payload back, refusing if the original path is occupied again. `list_entries()`, `purge()`, `purge_all()`, and `purge_expired()` (30-day retention) complete the lifecycle. Cross-device moves fall back to copy-and-delete.
- Guard rails: a target is quarantinable only if it resolves inside `ABSPATH`, is not the store itself, and is neither a protected path (`ABSPATH`, `wp-content`, plugin dirs, `wp-admin`, `wp-includes`, the theme root, this plugin) nor an ancestor of one. Refusals are logged and fall through to the existing delete path with its own guards.
- `auto_remediate()` is quarantine-first: when the new `quarantine_enabled` setting is on (default), the threat is quarantined and the finding is marked `quarantined` with the store id; the log event is `auto_quarantined`. When off, refused, or failed, the previous hard-delete behaviour applies unchanged.
- Root-kit removal fixed as a consequence: `WPS_Quarantine` carries its own path guards rather than inheriting `delete_directory()`'s `WP_CONTENT_DIR` restriction, so a kit at the ABSPATH root is now genuinely neutralised. Verified in the harness with a root-level kit directory that the old path refused.
- Store exclusion: the broad tree walkers that already skip the plugin's own directory (`check_php_signatures` shares the line with `check_redrop` and `check_dropper_cache`) and the doorway-kit walker now also skip the quarantine store, so neutralised evidence is never re-flagged; `check_redrop` was the critical one since it hashes regardless of extension.
- Retention: `WPS_Quarantine::purge_expired()` runs at the end of every hourly scan.
- Forensics tab: an always-visible Quarantine card (independent of running a report) lists entries newest-first - quarantined time (UTC), finding type, original path relative to ABSPATH - with per-entry Restore and Delete buttons and an Empty quarantine action. Restore warns it is for false positives; both destructive actions confirm first.
- AJAX: `wps_quarantine_restore`, `wps_quarantine_purge`, `wps_quarantine_empty` handlers in the remediation controller (`manage_options` guard, id validated against the strict store-id pattern before any filesystem work). `admin.js` reloads after quarantine actions so the card reflects the store.
- Settings: new "Quarantine removed threats instead of deleting them" toggle (default on) beside the auto-remediation toggle; `quarantine_enabled` persisted through the existing save handler.
- `tools/verify-package.ps1`: required-file manifest synced to the bootstrap require list - it had drifted by four files (`class-dropin-guard.php`, `class-log-reader.php`, `class-csp.php`, `class-admin-logs.php`) and now also covers `class-quarantine.php`.

### Verified

- `php -l` clean on every PHP file; `node --check` clean on `assets/js/admin.js`.
- Quarantine class harness: directory and single-file round-trips restore byte-identical content (SHA-256 tree compare); payload carries only `.wpsq` files; store hardening files present; all six guard refusals hold (ABSPATH, wp-admin, wp-content root, plugin dir, theme root, outside-install) with live paths intact; restore refuses when the original path is re-occupied; purge and `purge_all` empty the store; `is_quarantine_path()` recognises store children.
- Integration harness through `auto_remediate()` (reflection, WordPress stubbed): a root-level kit directory - previously flagged but never removed - and an uploads webshell are both moved off the live path, findings marked `remediated` with `quarantined` ids and the quarantine action text, entries restorable. With `quarantine_enabled` off, the same finding takes the hard-delete path, no store entry is created, and the action text reads auto-deleted, confirming the fallback.
- Not exercised here: a full `WPS_Scanner::run()` under real WordPress and real cross-device filesystems; the copy-and-delete fallback is code-reviewed but not device-tested.

### Meta

- `INDICATOR_VERSION` unchanged at `1.3.81-1` - no indicator lists changed.

## 1.3.93

Re-dropper hunt for the recurring doorway kit.

### Why

Two more drops arrived (trioxide_c0b61d, moulted_fdd902): the same doorway/backdoor
kit as pacifiers/donation, byte-identical core.php (fingerprint 219cc579), re-dropped
under new random folder names. The 1.3.91 fingerprinting correctly counts them as the
third and fourth re-drops and escalates to "RE-DROPPED Nx  active re-dropper present",
so detection and recurrence-awareness work. The problem is that the re-dropper is still
live. The kit's own code only writes its internal state and fetches doorway content over
curl, so it does not re-plant itself  something outside it does, and the likely vectors
(a system crontab, a dropper outside the WordPress install) are exactly the ones PHP
cannot read: no shell, and open_basedir confinement. The scanner already covers the
WordPress-level vectors (wp-cron, mu-plugins, wp-config, auto_prepend, drop-ins,
dropper-cache); it had nothing for the off-WordPress ones.

### What

A new Forensics card, "Re-dropper hunt", with read-only SSH commands to find what
re-plants a recurring kit: list the user and system crontab, isolate cron entries that
run PHP/curl/wget, search the whole account (not just the webroot) for the kit and its
reused stub files, find any directory shaped like the kit, grep for PHP that embeds the
kit markers (the re-dropper itself), and list PHP modified in the last two days
account-wide. The kit reuses the stub names canaryspillsdinky.php and
unmadesuerscorker.php across every drop, so those are the precise search target.

### Verified

- `php -l` clean on both changed files.
- Both new samples are confirmed the same kit as 1.3.91 (identical core.php
  fingerprint); the 1.3.91 escalation counts them as re-drops 3 and 4 with the
  hunt-the-dropper guidance.
- The hunt card generates its six commands carrying the stub-name IOCs, the system-cron
  paths, the kit-shape search and the recent-mtime account search.

### Meta

- Version markers to 1.3.93; `INDICATOR_VERSION` unchanged at `1.3.81-1` (forensic
  guidance, no detection-list edits).

## 1.3.92

Move the log-forensics panel toward in-plugin where it never needed SSH.

### Why

The Forensics panel labelled a block of commands "SSH required: the web server
process cannot read its own access logs." That overstates it. The plugin already
greps every log it can read in the Logs tab  WPS_Log_Reader discovers the readable
access/error logs and matches the campaign indicators in PHP, no shell  and one of
the "SSH required" commands, the attack-window file find, touches no logs at all. It
only walks the filesystem by mtime, which PHP does natively.

### What

- New in-plugin card, "Recently-modified executable files (attack-window
  correlation)": lists PHP under plugins, mu-plugins and uploads newest-first so a
  drop cluster (several files sharing a timestamp) is visible in the dashboard.
  Replaces the SSH `find`, which is removed from the command list. Read-only and
  bounded, no shell.
- The fallback commands' wp_<hex>_cfg pattern is now sourced from
  WPS_Indicators::malware_option_keys() instead of a hardcoded list that had drifted
  six variants behind the catalogue.
- The panel is retitled and reworded: it points at the Logs tab first and frames the
  SSH commands as the fallback for logs PHP genuinely cannot read on a given host
  (root-owned /var/log, open_basedir confinement, disabled shell functions), rather
  than a blanket requirement.

### What still needs SSH, honestly

Where PHP cannot read the access or auth logs  root-owned files outside open_basedir,
or hosts that disable the shell  the copy-paste commands remain the only route, and
that is a host limitation rather than something the plugin can engineer around. The
plugin never shells out; it reads and matches logs in PHP, only where the host allows.

### Verified

- `php -l` clean on both changed files.
- Harness: the in-plugin scan lists executables newest-first and excludes non-PHP;
  build_ssh_commands now emits the catalogue's current cfg keys (including the
  1.3.68 and 1.3.79 variants the hardcoded list lacked) and no longer contains the
  filesystem find.

### Meta

- Version markers to 1.3.92; `INDICATOR_VERSION` unchanged at `1.3.81-1` (reads the
  indicator catalogue, no list edits).

## 1.3.91

Doorway-kit re-drop awareness: name the recurrence, point at the dropper.

### Why

Two fresh samples (pacifiers_e83dd2, donation_c9385e) arrived from the webroot with
the note that the kit "keeps appearing in root." They are the same annealing/resweep
doorway + backdoor kit as 1.3.83, re-dropped under different random folder names with
re-randomised hex-suffixed filenames. check_doorway_backdoor_kit() already detects and
auto-deletes them at ABSPATH root  verified against the live detector  so the kit is
not evading the scanner. It keeps reappearing because a re-dropper outside the kit
folder re-plants it after each removal, and the scan was removing it silently, with
nothing to say "this is the same kit again, go find what is re-planting it."

### What

The kit's core.php is byte-identical across re-drops  only the folder name and the
hex-suffixed filenames randomise, and core.php embeds neither  so its hash is a stable
fingerprint. check_doorway_backdoor_kit() now records that fingerprint and the set of
distinct folder names the kit has appeared under. When the same kit returns under a new
name, the finding escalates from a plain detection to "RE-DROPPED Nx  active re-dropper
present", and the guidance switches from "delete this directory" to "find the dropper":
wp-cron and system cron, mu-plugins, wp-config.php / auto_prepend_file injection, and
any co-resident web shell. The kit is still auto-deleted as before; the overlay only
adds the recurrence signal.

Counting is by distinct random name, not per scan, so a single instance left in place
(auto-delete off) does not inflate the count  only a genuine re-plant under a fresh
name does.

### Verified

- `php -l` clean.
- Harness across three scans against a root-staged kit: first sighting is a normal
  detection; re-scanning the same instance does not inflate the count; the kit renamed
  to a new folder (a re-drop) escalates to "RE-DROPPED 2x" with the hunt-the-dropper
  guidance. Both uploaded samples are confirmed the same kit  core.php and the module
  set are byte-identical, only the wrapper name and hex suffixes differ. Detection and
  auto-delete at ABSPATH root were re-confirmed against the live detector.

### Not addressed here

This surfaces the recurrence and directs the hunt; it does not find the re-dropper
itself, which lives outside the kit and is not present in these samples. The general
redrop detector (check_redrop) still scans wp-content only, not ABSPATH root  a
separate gap worth closing if root re-drops of other families turn up.

### Meta

- Version markers to 1.3.91; `INDICATOR_VERSION` unchanged at `1.3.81-1` (scanner logic
  plus one new option, no indicator-list edits).

## 1.3.90

Supply-chain blind-spot awareness, plus a checksum-cache fix.

### Why

The June 2026 ShapedPlugin compromise (reported by Wordfence) backdoored Pro plugins
through the vendor's own update channel; the free wordpress.org builds were clean.
Checksum integrity  1.3.89 for plugins, 1.3.47/48 for core  verifies against the
.org distribution, so it is structurally blind to a premium plugin with no public
baseline, which is exactly where that attack lived. This release does not pretend to
detect the backdoor. It makes the blind spot visible so the risk is not silent.

### What

- check_plugin_integrity() now records the installed plugins it cannot verify (the
  ones .org returns 404 for  premium or custom) and emits one low-severity
  awareness line listing them, noting that a vendor-channel supply-chain compromise
  of one would not be caught by integrity checking. Low severity by design: the scan
  only emails on critical findings, so this never adds inbox noise.

- Fixed a latent caching bug in the checksum fetch. A transient failure (network
  error, or 403/429/5xx) was being negative-cached for a week, which both suppressed
  verification after a brief outage and could mislabel a verifiable plugin as
  premium. Now only a definitive 404/410 is cached as "not in the repo"; transient
  failures return without caching and are retried on the next scan.

### Not in scope

The ShapedPlugin loader and its install-persistent.php exfil stage are not detected
here  building those from a news write-up would invite false positives, and the
real sample is needed to do it properly. The persistence half of that chain (a
dropped web shell, a planted second-stage plugin on disk, unauthorised admin
accounts) is already covered by existing checks, because file-level scanning is not
fooled by the loader hiding itself from the admin plugin list.

### Verified

- `php -l` clean.
- Stubbed-network harness: a clean repo plugin verifies and is not listed; a premium
  plugin (404) is listed once at low severity and negative-cached; a plugin whose
  fetch fails transiently is not listed and is left retryable, with no negative
  cache. The modified and planted-PHP critical paths are unchanged from 1.3.89.

### Meta

- Version markers to 1.3.90; `INDICATOR_VERSION` unchanged at `1.3.81-1` (detection
  logic only, no indicator-list edits).

## 1.3.89

Anticipatory detection, part two: plugin file integrity against wordpress.org.

### Why

The 1.3.87 tripwire catches NEW PHP in uploads and mu-plugins, but a file modified
in place inside a legitimate repository plugin is not "new", and detecting it needs
no baseline  only the official distribution to compare against. This is the second
of the two anticipatory measures: it catches injection into real plugins and files
planted inside them, and it works on the first scan with no clean baseline.

### What

check_plugin_integrity() (new, registered in run()) verifies each installed
wordpress.org-repository plugin against the official plugin-checksums API
(downloads.wordpress.org/plugin-checksums/<slug>/<version>.json). For each plugin it
reads the declared version, fetches the checksums (cached a week; fetches capped per
scan), and flags a PHP file whose hash matches none of the official values as
MODIFIED (critical  a real plugin file altered is injection; restore by
reinstalling, not deleting), and a PHP file absent from the official distribution as
EXTRA (critical  a file planted inside a legitimate plugin folder).

Each file's official hash may be a single value or a whitelist of several (ZIPs
rebuilt at different revisions), and the check passes if any one matches; sha256 is
used, md5 is the fallback. Only executable files are verified, so the "soft changes"
to readme/text that wp-cli itself ignores by default do not raise noise. Premium and
custom plugins (no .org checksums) are skipped. Findings are review-only, never
auto-deleted.

### Scope and verification limits

This completes the two-measure plan. Themes are deliberately out of scope: .org does
not checksum themes the way it does plugins, so theme integrity needs a
zip-download-and-hash approach and will be its own pass if wanted. The network fetch
and per-scan orchestration could not be exercised in the build harness (no outbound
.org access there); they are verified by inspection, and the live fetch should be
confirmed on a real install.

### Verified

- `php -l` clean.
- The parse and compare logic  the security-critical core  is unit-tested: parsing
  handles single-string hashes, whitelist arrays, md5-only fallback and malformed
  entries; comparison passes a clean plugin, flags a tampered PHP file as MODIFIED
  and a planted PHP file as EXTRA, treats a hash whitelist as match-any, and ignores
  non-PHP soft changes (a wrong readme.txt hash is not flagged) and non-PHP extras (a
  .log file is ignored). Version parsing reads the header correctly.

### Meta

- Version markers to 1.3.89; `INDICATOR_VERSION` unchanged at `1.3.81-1` (new
  detection logic, no indicator-list edits).

## 1.3.88

New forensic sample validated (caught, no change required); placeholder-URI
backstop extended.

### Sample: ultra-layout-scanner-15c8 (externalized-payload variant)

A new fake plugin from a compromised site: the externalized-payload shape again
with cosmetic renaming. A 567-byte main stub with a split-string require
(`__DIR__.'/app/c'.'lass-init'.'.php'`), a sibling loader at `app/class-init.php`
that reads `storage/config.bin`, runs a `chr(ord(...))` substitution loop and
gzinflates it, and the opaque blob itself. The header author is "Net IO" (the same
shell author as the catalogued wp_3093c104e2_cfg Pro Cache Scanner variant) and the
Plugin URI is the `developer.wordpress.org/plugins` placeholder.

check_external_payload_loader() (1.3.83) catches it critical / auto-delete on all
three cues with no change required: the shape detector generalised to the renamed
variant exactly as intended. This is the value of detecting the technique rather
than the instance.

### Placeholder-URI backstop extended

The same sample re-confirmed the gap noted in 1.3.83: check_plugin_metadata_camouflage
matched only the example.* reserved domains, not the developer.wordpress.org/plugins
boilerplate these variants use. Extended it to flag that placeholder too, so a
future variant that drops one of the three externalized-payload cues still trips a
backstop. The pattern requires the "developer." host, so a legitimate
wordpress.org/plugins/<slug>/ directory link is never matched.

### Verified

- `php -l` clean.
- The sample is flagged by check_external_payload_loader (critical / auto-delete)
  and now also by check_plugin_metadata_camouflage (high) - defence in depth.
- False-positive check: a plugin with a real Plugin URI, and one linking to its
  wordpress.org/plugins/<slug>/ directory page, are both left unflagged.

### Meta

- Version markers to 1.3.88; `INDICATOR_VERSION` unchanged at `1.3.81-1`. The sample
  is a file-based JS injector with a per-instance hex slug and no wp_options
  persistence, so there is nothing to add to the indicator catalogue; generic shape
  and placeholder detection cover it.

## 1.3.87

Anticipatory detection: a PHP-inventory drift tripwire that catches new strains by
deviation rather than signature.

### Why

The recent surprises (the page-image-scanner externalized-payload variant and the
annealing/resweep doorway kit) slipped past because detection was keyed to known
shapes and known families, always one strain behind. This adds the first family-
and payload-agnostic detector: it flags a PHP file by the fact that it appeared or
changed where it should not, no matter what the file contains.

### What

check_php_inventory_drift() (new, registered in run()) records the PHP files in
uploads and mu-plugins  the two directories that should never legitimately gain
new code and that have content detection but no temporal baseline  as a
realpath => sha256 map (autoload off, walk bounded). On every scan it flags a NEW
PHP file (present now, absent from the baseline) as critical, and a CHANGED PHP
file (hash differs) as high.

On a fresh install with no baseline yet it establishes the baseline and flags
nothing, since it cannot know which existing files are clean: the content detectors
cover pre-existing malware, this covers what arrives afterwards. A novel loader
dropped into uploads, or a re-dropper written to mu-plugins, trips here on first
appearance, before it is catalogued.

These are anomalies, so they are surfaced for review and never auto-deleted,
consistent with the line drawn for the other heuristic buckets. A manual "Reset
PHP-inventory baseline" button on the Hardening tab re-captures the clean set after
a confirmed cleanup (mirrors the drop-in baseline reset; modifies no file).

### Scope

This is the first of the two anticipatory measures discussed. It watches uploads
and mu-plugins specifically because they are high-signal and low-churn; it
deliberately does not watch the plugins and themes trees, where legitimate updates
churn. That is the job of the plugin/theme checksum-integrity check  the second
measure  which is a larger, network-dependent build and will land as its own pass.

### Verified

- `php -l` clean on the three changed PHP files; `assets/js/admin.js` parses.
- Reflection lifecycle simulation: the first run establishes a two-file baseline
  and flags nothing; after a dropped uploads/evil.php and a modified
  mu-plugins/loader.php, the next run flags the first NEW/critical and the second
  CHANGED/high while leaving the untouched file silent; re-baselining clears it;
  non-PHP files are never tracked.

### Meta

- Version markers to 1.3.87; `INDICATOR_VERSION` unchanged at `1.3.81-1` (new
  detection logic, no indicator-list edits).

## 1.3.86

Known-bad DB options and malicious cron hooks now auto-clean through the same
toggle as everything else, and detection and deletion share one list.

### Background

Auditing the manual remediation buttons surfaced two gaps. The known-bad wp_options
keys  the highest-confidence DB malware in the plugin, an explicit catalogue  were
detect-only: auto_remediate deletes files and directories but not option rows, so
the only thing that removed them was the manual "Delete malicious DB options"
button. The lower-confidence heuristic base64 options had already been wired to
auto-clean in 1.3.85, so the high-confidence category was the one still requiring a
manual click.

The audit also found detection and deletion had drifted apart:
check_malicious_db_options carried its own hardcoded copy of the bad-option list,
and that copy was missing several catalogued _cfg variants that the manual button
(which reads WPS_Indicators::malware_option_keys()) would have removed.

### Changes

- One source of truth. check_malicious_db_options now reads
  WPS_Indicators::malware_option_keys() instead of a private duplicate, so
  detection, auto-clean and the manual button can never drift. This alone restores
  detection of the variants the stale inline list was missing.
- Options auto-clean, gated by the toggle. When auto-remediation is enabled
  (default), confirmed known-bad options are deleted in the scan pass and shown as
  auto-deleted; when off, they are flagged with the manual-button action text.
- Cron hooks auto-purge, gated by the same toggle. The scan now sweeps the cron
  array for the campaign's malicious hook substrings (the same list the manual
  handler uses), unschedules matches when auto-clean is on, and flags them for the
  manual button when it is off, so a malicious hook is visible in the scan either
  way.

The manual "Delete malicious DB options" button is unchanged and remains the
off-toggle path. The four repair buttons (wp-config, wp-login, functions, wp-cron)
are untouched: they clean or replace essential and core files that auto-delete
deliberately refuses, and stay manual by design.

### Safety

Consistent with the rest of the plugin, auto-cleaning is gated behind the existing
auto-remediation toggle rather than firing unconditionally, so no site's risk
posture changes without that setting already enabled. Core option names are never
in the catalogue, and the cron sweep matches only the campaign's known hook
substrings, leaving legitimate WordPress cron events alone.

### Verified

- `php -l` clean.
- Reflection-driven simulation, toggle ON: three known-bad options (including the
  mu-plugin backup and a variant the old inline list missed) deleted and marked
  remediated, the malicious cron hook unscheduled, a legitimate core cron hook and
  `siteurl` left untouched.
- Toggle OFF: the same four findings reported detect-only, nothing deleted, nothing
  unscheduled, each pointing at the manual button.

### Meta

- Version markers to 1.3.86; `INDICATOR_VERSION` unchanged at `1.3.81-1`. The
  indicator lists in class-wps-indicators.php were not edited; the scanner stopped
  using a stale private copy of one of them.

## 1.3.85

Confirmed base64 payload options are now treated as first-class confirmed malware:
toggle-gated auto-clean, a bulk "Delete all" action, and one consistent delete
path.

### Background

The `unknown_base64_option` findings (wp_options rows whose value decodes to PHP
source or to the ClickFix outer-JS loader) were the only confirmed-malware class
the plugin would not auto-clean, and could be removed only one option at a time.
On a heavily seeded site that meant dozens of identical "Delete now" clicks, while
the scan-results view listed them as criticals whose only action was to go to the
Forensics tab and delete them there  a non-actionable dead end and a redundant
second surface. The "unknown" label only ever meant the option key was not
pre-catalogued; the decoded content is structurally confirmed by the classifier (a
PHP opener plus an executor call, or the IIFE + String.fromCharCode + new Function
shape).

### Changes

- Auto-clean, gated by the existing setting. When auto-remediation is enabled (the
  same `auto_delete_enabled` toggle that governs every other confirmed artefact,
  default on), the scan now deletes confirmed base64 payload options in the same
  pass as file malware. It is not unconditional: each live option is re-validated
  with `WPS_Forensics::confirm_base64_option_verdict()` immediately before
  deletion, so a stale cached report can never drive a delete, and the core-safe
  skiplist still applies.
- "Delete all" bulk action. For manual mode (toggle off), the Forensics base64 card
  now leads with a single "Delete all N flagged options" button. The new
  `delete_all_unknown_b64_options` handler loops the cached report, deletes each
  option behind the same two gates as the single-option handler (report membership
  and core-option refusal), and splices the report to the surviving entries (the
  1.3.84 contract), so the count and card stay consistent.
- One delete path, no redundant surface. The scan-results action text now reflects
  reality instead of pointing at the Forensics tab: confirmed options show as
  auto-deleted when the toggle is on, or are routed to the single bulk action when
  it is off. Deletion logic lives in one place (the remediation controller); the
  scanner auto-clean and both buttons funnel through it.

### Safety

Auto-deletion is deliberately gated behind the existing auto-remediation toggle
rather than firing unconditionally on every scan, so the change does not alter the
risk posture of any site that does not already have that setting enabled. The
automatic path re-validates live content; the manual paths require the option to be
in the cached report and refuse core option names even if one were injected into
the report.

### Verified

- `php -l` clean across the four changed PHP files; `assets/js/admin.js` parses.
- `confirm_base64_option_verdict` returns the right verdict for a clickfix_js
  option and a php_payload option, and empty for a benign long-base64 option, a
  core-safe-prefixed option even with malicious content, a sub-threshold option,
  and a missing option.
- The bulk handler drove a four-entry report (two clickfix_js, one php_payload, one
  injected `siteurl`) to three deletions with `siteurl` skipped and its value
  intact, the auto_prepend and cron findings preserved, and the report spliced to
  the surviving entry. An empty report returns the "run forensics again" error.

### Meta

- Version markers to 1.3.85; `INDICATOR_VERSION` unchanged at `1.3.81-1` (no
  indicator-list edits).

## 1.3.84

Bugfix: sequential deletion of suspicious base64-encoded options on the Forensics
tab.

### Symptom

Deleting more than one "Suspicious base64-encoded option value" in a row failed.
The first "Delete now" succeeded, but every later one on the same page returned
`Option "<name>" is not in the current forensics report. Run forensics again, then
retry.`, even though the option was plainly listed in the report on screen.

### Cause

The delete handler (`delete_unknown_b64_option`) gates deletion on the option
being present in the cached `wps_forensics_report`, then, on a successful delete,
discarded the entire cached report with `delete_option( 'wps_forensics_report' )`.
The rendered page is a snapshot of one forensics run and offers many options for
deletion, so the first successful delete wiped the validation basis for every
sibling finding still shown, and the next click was validated against an empty
report. First delete worked, all subsequent ones failed until Forensics was re-run.

### Fix

On a successful delete the handler now removes only the deleted option from
`unknown_base64_options` and writes the report back with `update_option()`,
instead of discarding the whole report. Sibling base64 findings stay valid for
sequential deletion, and the `auto_prepend` and cron findings in the same report
are left intact. The change is server-side only; the page already replaces each
deleted row with its own success indicator.

### Verified

Drove the real handler through a three-option report: deletions #1, #2 and #3 all
succeed in sequence (previously only #1 did), the cached report persists and
shrinks by exactly the deleted entry each time, sibling findings are preserved,
and both safety gates still hold  an option absent from the report is refused,
and a core option name is refused even if injected into the report.

### Meta

- Bumped plugin header, `WPS_VERSION`, readme stable tag, and `doc/readme.md` to
  `1.3.84`.
- `INDICATOR_VERSION` unchanged at `1.3.81-1` (bugfix, no detection or indicator
  changes).

## 1.3.83

Two-threat detection release. Adds a structural detector for a new ClickFix
delivery shape and, by request, brings a co-residing non-ClickFix backdoor family
into scope with removal.

### page-image-scanner family (externalized-payload fake plugin)

A new ClickFix delivery shape evaded 1.3.82: a sub-1 KB main loader
(`<slug>/<slug>.php`) with a split-string `require`, a sibling
`core/class-handler.php` that reads a bundled blob, runs a `chr(ord(...))`
substitution loop and `gzinflate`s it, and the actual payload externalized into a
non-PHP file (`storage/state.pkg`). The shape heuristic scores only the tiny main
file, the signature scan never sees the compressed blob, and the metadata
camouflage check is tuned for `example.com` rather than the
`developer.wordpress.org` placeholder this loader uses, so nothing fired.

`check_external_payload_loader()` (new, registered in `run()`) flags a plugin
that combines three cues: a PHP file that reads and decodes a file
(`file_get_contents`/`fread` with `gzinflate`/`gzuncompress`/`base64_decode`/
`str_rot13` or a `chr(ord(...))` decode loop), an opaque bundled payload blob (a
non-PHP file with a non-standard extension over 512 bytes), and an obfuscation
tell (a split-string `include`/`require` path or a `chr(ord($table[ord(...)]))`
substitution loop). Critical, auto-delete of the plugin folder.

### annealing / resweep family (doorway-spam + backdoor panel kit) — new scope

This is not the ClickFix campaign. It is a self-contained PHP kit dropped into the
webroot: a file-manager web shell, an admin panel, login/logs/settings, an
`ipManager`/`linkManager`/`settingsManager` module set, a bundled IPv4 subnet
calculator used for visitor/bot cloaking, doorway templates and spam wordlists,
and a second renamed copy of itself bundled alongside (self-replication). It is
the first non-ClickFix family this plugin handles, added by explicit request.

`check_doorway_backdoor_kit()` and `doorway_kit_cue_score()` (new, registered in
`run()`) scan a bounded set of roots (`plugins`, `mu-plugins`, `themes`,
`uploads`, `wp-content`, ABSPATH; depth-limited and file-count-capped) for a
`core/` directory carrying the kit's structural tells: a misspelled `backdor*`
backdoor file (near-unique to this family, counted double), hex-suffixed
`panel_<hex>.php` / `filemanager_<hex>.php` files, and the
`ipManager`/`linkManager`/`settingsManager` module set. At three or more cue
points the kit root is flagged critical and auto-deleted, subject to a
protected-path guard.

### Removal safety

The doorway-kit removal targets a whole directory tree, so a protected-path guard
resolves the kit root and refuses auto-deletion (downgrading to critical
review-only) if it equals or contains ABSPATH, `wp-content`, the plugins,
mu-plugins, themes, or uploads roots, or the plugin's own directory. The
external-payload detector deletes a single plugin folder via the existing
auto-remediation path, which already carries the 1.3.80 boundary-safe containment
and active-theme protections.

### False-positive guards

The external-payload detector requires all three cues; a plugin that merely ships
a compressed data file and `gzinflate`s it (no obfuscation tell) is not flagged.
The doorway detector requires the misspelled `backdor` tell plus a second tell, or
the full panel/filemanager/module trio; a legitimate plugin or theme with a
`core/` or `core/modules/` directory scores zero.

### Verified

- `php -l` clean; both detectors are additive and registered once in `run()`.
- Malware simulation: `page-image-scanner-23ed` and the `annealing_1af540` kit
  (including its bundled `resweep` copy) are each flagged critical/auto-delete.
- False-positive simulation: a caching plugin with a `core/` subdirectory, a
  GeoIP plugin that `gzinflate`s a bundled `.dat` blob (the case the obfuscation
  cue is designed to spare), and a framework plugin with a `core/modules/`
  directory were all left untouched by both new detectors.

### Meta

- Bumped plugin header, `WPS_VERSION`, readme stable tag, and `doc/readme.md` to
  `1.3.83`.
- `INDICATOR_VERSION` stays `1.3.81-1`: detection logic was added in the scanner,
  the indicator lists in `class-wps-indicators.php` were not modified.
- Scope note: `annealing`/`resweep` is a distinct malware family from the
  `wp-perf-analytics` ClickFix campaign. It co-resided with a ClickFix variant in
  the sample dump, which is suggestive but not proof of a shared operator; the two
  codebases share no structure or infrastructure.

## 1.3.82

Persistence-layer detection release. Closes a renamed-copy gap on the
access/persistence side of the campaign, the same class of evasion the ClickFix
detection already defeated with structural scoring.

### The gap

A live sample (`rest-api-compat`) arrived as a three-file persistence kit: a
heavily obfuscated ~66 KB MU plugin (`mu-plugins/rest-api-compat.php`,
masquerading as "Transient Cleanup Manager"), plus two wp-content drop-in
re-droppers (`db.php` and `advanced-cache.php`) that decode and rewrite the MU
plugin on every page load. It is the same persistence concept as the catalogued
`session-manager.php` / `_sm_ac_v5` RAT family, with every identifier renamed
(marker `_ac_63b990b9`, a different target filename, a different DB option).

Against 1.3.81 the kit was almost invisible: `check_mu_plugins()` is bound to the
filename `session-manager.php` and its signature fallback misses obfuscated
content; `check_wp_content_dropins()` needs three session-manager-specific
markers or the literal `_sm_ac_v5`, and the renamed re-droppers hit only two. The
only thing that fired was the generic 1.3.54 drop-in publisher audit, at
medium/review-only, which does not break the reinfection loop (`db.php` loads
before plugins and restores the payload after a manual delete).

### Added

- `check_wp_content_dropins()` gains a structural re-dropper branch, independent
  of the session-manager identifiers. Any audited drop-in
  (`advanced-cache.php`, `object-cache.php`, `db.php`, `sunrise.php`) that
  combines a decode call (`base64_decode` / `gzinflate` / `gzuncompress` /
  `str_rot13` / `convert_uudecode`), a payload write (`file_put_contents` /
  `fwrite` / `fputs`), and a write target under `mu-plugins/` (or
  `WPMU_PLUGIN_DIR`) is flagged critical/auto-delete as a re-dropper, regardless
  of option name, marker, or target filename. Runs only when the
  session-manager markers did not already match, so confirmed-family findings are
  not double-counted.
- `check_mu_plugins()` gains a structural obfuscation branch for renamed MU-plugin
  RATs that evade both the known-filename match and the cleartext-signature scan.
  It scores the rolling-XOR deobfuscation guard
  (`chr($arr[$i] ^ ord($key[...]))`), `eval(`, `base64_decode`, high `chr()`
  density, and `register_shutdown_function`, and flags critical/auto-delete only
  when the near-unique rolling-XOR guard is present alongside a high overall cue
  count. Runs only when the filename and signature checks did not already match.

### False-positive guards

Auto-deletion on the re-dropper branch requires the `mu-plugins` write target,
which legitimate cache/database drop-ins do not have; auto-deletion on the MU
branch requires the rolling-XOR guard idiom, which is effectively unique to this
payload and absent from legitimate (rarely obfuscated) MU plugins.

### Verified

- `php -l` clean on the changed scanner; both edits are additive branches inside
  methods already registered in `run()`.
- Malware simulation: the full `rest-api-compat` kit now raises three
  critical/auto-delete findings — the MU plugin via the obfuscation branch and
  both drop-ins via the re-dropper branch.
- False-positive simulation: representative legitimate drop-ins (WP Super Cache
  `advanced-cache.php`, Redis `object-cache.php`, Query Monitor `db.php`) and MU
  plugins, plus two deliberately tricky fixtures (a `sunrise.php` that decodes and
  writes but not into `mu-plugins`, and an MU plugin with 120 `chr()` calls but no
  rolling-XOR guard), were not flagged by either new branch. The pre-existing
  1.3.54 review-level publisher nudge on unknown drop-ins is unchanged.

### Meta

- Bumped plugin header, `WPS_VERSION`, readme stable tag, and `doc/readme.md` to
  `1.3.82`.
- `INDICATOR_VERSION` stays `1.3.81-1`: the indicator lists in
  `class-wps-indicators.php` were not modified, only scanner detection logic was
  added (consistent with the rule that `INDICATOR_VERSION` tracks the indicator
  lists, and with the 1.3.80 precedent).
- The new MU obfuscation branch does not hardcode the `rest-api-compat` slug; the
  slug/pattern blocklist is intentionally not extended, since structural
  detection covers renamed variants without per-slug maintenance.

## 1.3.81

Branch-reconciliation release. Two packages were built from the same `1.3.79`
base on parallel branches; both claimed the `1.3.79` version for different
detection work, and one branch then added a `1.3.80` safety release on top of
its own `1.3.79`. The result was a version collision: two different `1.3.79`
definitions and a `1.3.80` that carried only one of the two detection lineages.
This release merges both lineages onto the `1.3.80` safety base and advances the
version once so the collision cannot recur.

### What the two branches each held

- Cookie-stealer / theme-loader lineage `1.3.79`: structural admin-session-cookie
  stealer detection and a theme-modifying loader-plugin detection, driven by a
  forensic dump from a compromised live site. Never shipped in the lineage that
  produced `1.3.80`.
- JS-injector / safety lineage `1.3.79` + `1.3.80`: the RC4-obfuscated JS-injector
  / theme-`css.js` dropper detection, followed by the `1.3.80` safety-stabilization
  fixes. This is the base for `1.3.81`.

### Merged in (onto the 1.3.80 base)

- `WPS_Scanner::check_admin_cookie_stealer()` plus its registration in `run()`.
  Matches admin-session-cookie stealers by code shape (a shutdown hook, an
  administrator-role check, an outbound HTTP call, and a `wordpress_*` cookie
  reference must all co-occur), closing the renamed-copy gap on the
  `.wp-config-cache.php` payload. Auto-deletes only when the destination host is
  on `WPS_Indicators::cookie_exfil_c2_domains()`; external-but-unknown host is
  critical with a delete button; unextractable host drops to high for review.
  Wires up the previously-unused `cookie_exfil_c2_domains()` accessor.
- `WPS_Scanner::check_theme_loader_plugin()` plus its registration in `run()`.
  Catches the `Plugin-<6-10 hex>` theme-modifying loader family by structural
  cues (slug shape, function-name family, `get_template_directory_uri() .
  '/css.js'` injection, hex-array obfuscator density). Two cues flag for review,
  three auto-delete the fake plugin folder. The delete target is the malicious
  plugin folder under `WP_PLUGIN_DIR`, never a theme file, so it is consistent
  with the `1.3.80` rule of never deleting active-theme files automatically.
- Catalogue: `wp_1f20bc3f7f_cfg` and `wp_8447aa87d2_cfg` added to
  `malware_option_keys()`; `Cache Solutions` and `WP Solutions` added to
  `clickfix_known_shell_authors()`.

### Preserved from the 1.3.80 base

All `1.3.80` safety work is kept unchanged: removal of the broad `addons`/`scr`
plugin-folder substring deletion, the two-tier uploads-PHP policy, active-theme
critical-file protection in manual and auto-remediation paths, boundary-safe
self-directory and parent-path containment checks, the css.js sub-critical
no-auto-delete handling, version-and-locale-scoped core-checksum cache keys, the
restricted log reader, the tightened `PHP_SAPI` CLI guard, and the pre-write
backups before `clean_login()`, `clean_functions()`, and `clean_cron()`. The
branch code that `1.3.80` had deliberately changed (the broad slug list, the
unscoped checksum cache, the pre-backup cleaners) was not reintroduced.

### Notes

- `check_theme_loader_plugin()` (loader-folder shape) and
  `check_obfuscated_js_injector()` (RC4 payload shape) can both fire on the same
  `Plugin-<hex>` sample. This is intended defence in depth; the two match
  different artefacts of one family and either alone is sufficient.
- `WPS_Indicators::INDICATOR_VERSION` advanced to `1.3.81-1` because the indicator
  catalogue changed (two option keys, two shell authors).

### Meta

- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project
  docs to `1.3.81`.
- Verified: `php -l` clean on all changed PHP files; brace-balanced at depth 0;
  both merged methods declared once and registered once in `run()`; the
  pre-existing `check_obfuscated_js_injector()` registration retained.
- Real-sample simulation: the four structural detection methods were invoked
  (via reflection, with WordPress stubbed) against the confirmed forensic
  samples. The three single-file ClickFix variants (`auto-asset-helper-2763`,
  `site-security-toolkit-1f30`, `total-database-optimizer-9a95`) each matched
  `check_clickfix_shape_heuristic()` at 6/6 traits (auto-delete);
  `Plugin-7e4eb3ff` matched both `check_theme_loader_plugin()` at 3/4 cues and
  `check_obfuscated_js_injector()` at 10/11 signals (both critical, auto-delete),
  confirming the intended dual-detection overlap; and `.wp-config-cache.php`
  matched `check_admin_cookie_stealer()` (critical, auto-delete) with the C2 host
  `webanalytics-cdn.sbs` extracted and matched against `cookie_exfil_c2_domains()`.
  The legitimate Malay `.l10n.php` translation files and the `advanced-cache.php`
  / `object-cache.php` drop-ins in the same dump were not flagged. The harness
  exercises the detection methods directly, not the full `run()` pipeline.
- Second sample batch validated the same way: `pro-cache-scanner-6d52`,
  `site-speed-insights-d6e7`, and `total-database-optimizer-9a95` each matched
  `check_clickfix_shape_heuristic()` at 6/6 traits (auto-delete), and the two
  original injector-family captures `Plugin-b45b652c` and `Plugin-45e0930c`
  (the pair `check_obfuscated_js_injector()` was built from) were each caught by
  both `check_theme_loader_plugin()` (3/4 cues) and `check_obfuscated_js_injector()`
  (10/11 signals) at critical/auto-delete. This is cross-coverage evidence for the
  merge: the branch-A theme-loader check generalises onto branch-B's source
  samples and vice versa, so every member of the `Plugin-<hex>` family raises two
  independent critical findings.
- Third sample batch revalidated the broader ClickFix prefix family against the
  shape heuristic: `advanced-asset-insights-ec06`, `auto-content-profiler-0b8d`,
  `site-speed-insights-d6e7`, `starter-image-guard-e9a2`, and
  `total-render-toolkit-adae` (five distinct slug prefixes) each matched
  `check_clickfix_shape_heuristic()` at 6/6 traits (auto-delete), and the
  loader/cookie-stealer methods correctly returned nothing for this prefix-only
  set. Confirms the heuristic scores structure rather than the slug, so prefix
  rotation does not evade detection (`auto-content-profiler-0b8d`, the original
  variable-concatenation evasion sample, still scores 6/6).
- Final sample batch, including the progenitor `wp-perf-analytics` family, was
  checked across three layers. `pro-font-optimizer-c88b`,
  `total-render-profiler-3753`, and `native-render-toolkit-9401` matched the
  shape heuristic at 6/6 (auto-delete). The two original `wp-perf-analytics`
  captures (`wp-perf-analytics`, `wp-perf-analytics-d2e9`) scored only 3/6 on the
  shape heuristic (medium, review-only) because the heuristic is tuned for the
  later canonical renamed shape, not the ~6 KB progenitor; this is the intended
  backstop behaviour, not a gap. All five were blocked by `WPS_Blocker::is_blocked()`
  (slug/pattern layer; `wp-perf-analytics` is a built-in blocked slug and the
  `-d2e9` rename matches the `wp-perf-analytics-<hex>` pattern) and all five
  matched `check_php_signatures()` at critical/auto-delete (campaign signature
  layer), confirming the progenitor family is caught at critical confidence by
  the slug and signature layers regardless of the heuristic score.
- Package the release ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.80

Safety stabilization release. This rationalises the plugin version after the
1.3.79 detection release and closes the high-risk false-positive deletion
paths identified in code review.

### Fixed

- Removed broad substring-based plugin-folder detection for `addons` and `scr`.
  The direct critical folder list now keeps only distinctive malware-family
  names (`antymalwary`, `wpconsole`, `wp-performance-booster`). The generic
  `addons` and `scr` terms are no longer allowed to drive automatic plugin
  folder deletion.
- Changed uploads PHP handling from "delete every PHP file" to a two-tier
  policy: harmless small `index.php` silence stubs are ignored, uploads PHP
  with known malware signatures remains critical and auto-deletable, and other
  uploads PHP is high severity for manual review.
- Added active-theme critical-file protection to both generic manual deletion
  and scanner auto-remediation. `functions.php`, `style.css`, common template
  entry files, and other active/parent theme critical files now require
  surgical cleaning or restore-from-backup rather than generic deletion.
- Replaced scanner self-directory prefix checks with boundary-safe containment
  checks so a sibling folder such as `wp-perf-shield-malware` cannot be skipped.
- Replaced auto-remediation parent-path prefix checks with a boundary-safe
  string path helper so `/plugins/foo2` is not treated as already covered by
  `/plugins/foo`.
- Fixed planted `css.js` payload severity handling. Scores below the critical
  threshold now report as `high`, do not set `auto_delete`, and do not provide
  an automatic delete path.
- Versioned core-checksum cache keys by WordPress version and locale in scanner
  and forensics paths to avoid stale checksum manifests after core updates.
- Restricted the admin log reader to log-like filenames and standard log
  directories, while denying sensitive non-log extensions such as `.env`,
  `.sql`, backups, JSON/config files, archives, and PHP-like files.
- Added timestamped, non-overwriting backups before `clean_login()`,
  `clean_functions()`, and `clean_cron()` write replacements.
- Tightened the internal indicator-update tool's CLI guard to `PHP_SAPI !==
  'cli'` and removed the closing PHP tag.

### Meta

- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project
  docs to `1.3.80`.
- `WPS_Indicators::INDICATOR_VERSION` remains `1.3.79-1`; this release changes
  deletion policy, safety guards, cache scoping, and backups, not the indicator
  catalogue.
- Rebuild as `wp-perf-shield-1.3.80.zip` with `wp-perf-shield/` as the package
  root before publishing.

== 1.3.79 ==
* New family: Obfuscated JS injector / theme-css.js dropper.
  Two confirmed samples analysed (Plugin-b45b652c, Plugin-45e0930c).
  Each is a lone PHP plugin file disguised as "simple js plugin" that
  embeds ~130 KB of RC4-obfuscated JavaScript in a PHP heredoc (ENDPLUGINJS),
  writes it to the active theme directory as css.js, and injects a
  <script src="...css.js"> tag into every front-end pageview. Human visitors
  receive a remote JSON-RPC payload from a C2 server; bots and WordPress
  admin/cron/asset requests are filtered out for stealth. Structurally distinct
  from the XOR+base64 ClickFix loader family — uses a different obfuscator
  (RC4 string-array rotation with while(!![]){try{) and a different delivery
  mechanism (theme-directory file write rather than wp_footer hook).
* class-scanner.php: five new literal signatures added to SIGNATURES_PERF
  (get_template_directory_uri() . '/css.js', _get_css_js_content,
  _header_has_css_js_script, _find_closing_tag_position, ENDPLUGINJS).
  These fire via the existing check_php_signatures() path for all plugin
  PHP files.
* class-scanner.php: new check_obfuscated_js_injector() method. Scores up
  to 11 co-occurring structural signals in plugin PHP files; 3+ signals
  = high severity, 6+ = critical + auto-delete. Separately checks the
  active and parent theme directories for a planted css.js payload (up to
  6 JS structural signals; 4+ = auto-delete).
* class-wps-indicators.php: two new public methods —
  obfuscated_js_injector_php_signatures() and
  obfuscated_js_injector_payload_markers() — for external integrators
  and support bundles.
* INDICATOR_VERSION bumped to 1.3.79-1.

## 1.3.78

Detection release, driven by a live sample from an infected site (rembat.my, a Malaysian football-news site). The captured injection is the same ClickFix family this plugin targets, but evolved in two ways that defeated the existing signatures. Decoded and verified independently before building.

### What the sample was

A `<script>` appended before `</body>` on every page, obfuscated as base64 + single-byte XOR (key 179) wrapping a `new Function(new TextDecoder().decode(...))`. De-obfuscated, it is the desktop-only ClickFix lure: it skips mobile/tablet and iOS/Android, runs an anti-debugger timing check, sets and checks dismissal cookies named `_cf_verified` and (with grim irony) `_wp_perf_ok`, and fetches its next-stage URL from a **Polygon** smart contract (`0x08207B087F61d7e95E441E15fd6d40BEfd6eD308`, selector `0x38bcdc1c`) via `eth_call` across six public Polygon RPC nodes, an EtherHiding move from the earlier Binance Smart Chain variant. It then paints a full-screen iframe overlay with `allow="clipboard-write"` (the clipboard-poisoning step) and waits for a `cf-captcha-verified` postMessage.

### Why 1.3.77 would have missed it

Two structural reasons, both verified:

1. The two wrapper signatures (`s.charCodeAt(i)^k`, `new TextDecoder().decode(r)`) are literal and assume one sample's variable names. This variant randomised them (`_daa77`, `_6a70`, `_0695`, `_db937`), so the literal `strpos` did not match.
2. The cleartext indicators already in the signature list (`_wp_perf_ok`, `eth_call`, the contract, `cf-captcha-verified`) live *inside* the base64 blob in the file, so a raw substring scan of the file never sees them.

### Fixes

- **Polygon EtherHiding hosts** added to `WPS_Indicators::etherhiding_indicators()` (the six Polygon RPC nodes), and the `eth_call` primitive is now matched as a bare substring so it catches both quote styles. Indicator version moves to `1.3.78-1`.
- **New `check_obfuscated_loader()`**, registered in the scan pipeline. It detects the loader by *structure* rather than variable names: a file must carry an atob/base64_decode blob, a `charCodeAt(...)^key` XOR loop, a TextDecoder/fromCharCode pass, and a `new Function()`/`eval()` sink. On a structural match it base64-decodes the blob and brute-forces the single-byte XOR, recovering the payload, the key, the contract address, and the chain RPC hosts; a campaign indicator in the recovered decode is treated as proof (critical), while structure-without-recovery is reported high for manual review. This survives variable-name randomisation and XOR-key rotation (keys 84, 113, 114, 179 seen to date). The cheap regex gate runs per file; the costly brute runs only on files that already match the full structure.
- The finding does not auto-delete. If the loader is a standalone dropper it should be deleted; if it was appended to a legitimate file (e.g. a theme functions.php) only the injected block should be removed, so the plugin flags it with the recovered details and leaves the decision to the operator.

### Verification

- `check_obfuscated_loader()` brace-walks cleanly and is registered in the pipeline.
- Simulated against a synthetic dropper carrying the real rembat.my blob with randomised variable names: the structural gate fired, the brute recovered XOR key 179, all cleartext indicators, the contract address, and all six Polygon hosts; a benign file using only `base64_decode()` did not trip the gate.
- `php -l` was NOT run (no PHP CLI in the build environment). Run it on `class-scanner.php` and `class-wps-indicators.php` before publishing.

### Compatibility

- Built on the 1.3.77 base (all 1.3.75 / 1.3.76 / 1.3.77 work retained). No new options, no new AJAX, no schema change. One new read-only scan check and an extended indicator list.
- The structural gate requires four independent patterns to co-occur, so false positives on legitimate code are very unlikely; recovery (and the critical verdict) requires a decoded campaign indicator.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.78`. Rebuild as `wp-perf-shield-1.3.78.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.77

Bug-fix release.

### Fixed

- `sanitize_key()` in the `wpconfig_constant` AJAX handler was lowercasing constant names before the allowlist check, causing all three wp-config.php hardening toggles (`DISALLOW_FILE_MODS`, `DISALLOW_FILE_EDIT`, `FORCE_SSL_ADMIN`) to always return "Constant not in the allowed list." and silently do nothing. Fixed by wrapping the sanitised value in `strtoupper()` so it matches the uppercase entries in `ALLOWED_CONSTANTS`.

### Meta

- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.77`. Rebuild as `wp-perf-shield-1.3.77.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.76

Hardening release. Adds an opt-in Content-Security-Policy, the one item from the broader hardening landscape that directly counters this campaign's visitor-facing stage, built report-only-first so it cannot silently break a site.

### Why CSP, and why carefully

The injected ClickFix script runs in the visitor's browser, paints the fake CAPTCHA, and reaches out to a C2 or a Binance Smart Chain node. A CSP `connect-src` can stop that outbound call even on an already-infected page, and `object-src` / `base-uri` / `frame-ancestors` add low-risk hardening. CSP is also the easiest way to break a WordPress site, so this is engineered to be safe before strict.

### New class: `WPS_Csp`

- **Off by default.** Nothing is emitted unless the operator opts in on the Hardening tab.
- **Three modes:** Off, Report-only (recommended front door), Enforce. In report-only the browser blocks nothing and only posts violation reports, so the operator sees what would break, and spots the malware's outbound calls, before enforcing. Enforce is gated behind a JavaScript confirmation warning.
- **Default policy is permissive where WordPress breaks and strict only where safe and useful:** it keeps `'unsafe-inline'`/`'unsafe-eval'` for script and style, and sets `connect-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'self'`. `connect-src 'self'` is the directive that surfaces (and later blocks) the C2/BSC callback; the UI tells the operator to widen it to their legitimate third parties from the reports before switching to Enforce. The policy is editable, with a one-click restore-default.
- **Front-end only.** The header is never emitted in wp-admin, AJAX, REST, cron, XML-RPC, or feeds, where inline scripts are unavoidable.
- The plugin appends its own `report-uri` automatically.

### Hardened public report endpoint

CSP reports are posted by browsers without authentication, so the REST collector (`wp-perf-shield/v1/csp-report`, public by necessity) is locked down: it stores nothing when CSP is off, ignores bodies over 8 KB, rejects anything that is not a CSP-report payload, throttles writes to roughly one every two seconds, truncates every stored field to 300 characters, and keeps only the 50 most recent reports in a ring buffer. The Hardening tab shows those reports (time, directive, blocked URI, source), so a blocked-uri pointing at an unfamiliar host is the malware's callback, and a familiar host is something to add to `connect-src` before enforcing.

### Verification

- `WPS_Csp` brace-walks cleanly (13 methods); the `wps_csp` handler closes cleanly; admin.js and the Hardening tab balance.
- Endpoint hardening simulated: a real connect-src violation to comicstar.lat is stored, while off-mode, throttled, oversized, and non-report payloads are all dropped, and the buffer caps at 50.
- Save normalization simulated: an invalid mode falls back to off, line breaks are stripped from the policy, and an empty policy restores the default.
- `php -l` was NOT run (no PHP CLI in the build environment). Run it on `class-csp.php`, `class-remediation-controller.php`, and `class-admin-hardening.php` before publishing.

### Compatibility

- Off by default, so existing installs are unaffected until the operator enables it. One new `manage_options`-gated AJAX handler (`wps_csp`) and one public REST report endpoint (hardened as above). New option `wps_csp_reports` is removed on uninstall; CSP mode/policy live in the existing settings option.
- If another plugin already sets a CSP header, browsers combine them restrictively; operators running a second CSP source should pick one.
- No detection-logic or indicator changes, so `WPS_Indicators::INDICATOR_VERSION` stays `1.3.75-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.76`. Rebuild as `wp-perf-shield-1.3.76.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.75

Intelligence release. Three additions drawn from public reporting on this campaign's lineage, chiefly GoDaddy's (Denis Sinegubko) tracking of the fake-plugin ClickFix/ClearFake operation and Silent Push's infrastructure feeds.

### 1. EtherHiding (Binance Smart Chain) detection

GoDaddy documented the 2024 wave fetching its next-stage ClickFix JavaScript from a Binance Smart Chain smart contract rather than a plain C2, a technique called EtherHiding: the loader issues an `eth_call` JSON-RPC request to a public BSC node and reads attacker-controlled bytecode out of a contract, which resists takedown because the payload lives on-chain. The captured variant uses a plain C2 (biletors.cfd / comicstar.lat), but the same operator lineage has used EtherHiding, so a new `WPS_Indicators::etherhiding_indicators()` lists the public BSC RPC hosts and the `eth_call` / `eth_getStorageAt` read primitives, and `check_clickfix_c2_in_options()` now flags any decoded `wp_<10hex>_cfg` payload that contains one. The match is scoped to that malware option shape, so a legitimate web3 plugin referencing BSC is not in scope. A pure EtherHiding hit is reported with its own finding type and an explanation that the on-chain stage cannot be taken down.

### 2. example.com placeholder-URI camouflage check

GoDaddy named a defining tell of the fake plugins: they copy a real plugin's header metadata into a lone bootstrap file but leave an `example.com` Plugin URI or Author URI in place. A new `check_plugin_metadata_camouflage()` walks the plugin folders, reads each plugin header, and flags any whose Plugin URI or Author URI carries a reserved RFC 2606 placeholder domain (example.com/.org/.net/.edu). Legitimate plugins never ship a placeholder URI, so false positives are near zero; it is reported high with a delete button rather than auto-deleted, since an abandoned developer scaffold could in principle trip it. The fake-plugin shape heuristic was also extended to consider a lone `index.php` as the main file, not only `<slug>.php`, because the GoDaddy variant ships its payload as `index.php` and would otherwise be skipped entirely.

### 3. Automated-login signature in the Logs tab

GoDaddy observed from access logs that the operators log in with stolen credentials by POSTing straight to wp-login.php without ever loading the login page, because it is a script replaying credentials, not a browser. A human login always GETs the page before POSTing it. The Logs tab gains a "Find automated-login attempts" button backed by `WPS_Log_Reader::scan_login_posts()`, which parses Common/Combined log lines, groups by client IP, and reports IPs that POSTed to wp-login.php with zero preceding GETs, plus any xmlrpc.php auth hits. This is the access-log query that points at the credential-stuffing entry point, the initial-access half of the picture the file checks cannot show. Simulated: a script POSTing without a GET is flagged, a human GET-then-POST is not, and xmlrpc hits are flagged.

### Verification

- All new and edited methods brace-walk cleanly; both new checks are registered in the scan pipeline; admin.js and the log reader balance.
- Each detection was simulated: a BSC payload in a malware option is flagged while a clean cache config is not; a fake plugin with an example.com URI is flagged while WP Rocket's real URIs are not; the login parser flags the scripted IP and the xmlrpc IP and leaves the human login alone.
- `php -l` was NOT run (no PHP CLI in the build environment). Run it on `class-scanner.php`, `class-wps-indicators.php`, `class-log-reader.php`, and `class-remediation-controller.php` before publishing.

### Compatibility

- The only new AJAX surface is one extra mode (`loginscanall`) on the existing `manage_options`-gated `wps_log_inspect` handler. No new persistent options. The metadata-camouflage finding is review-with-button, not auto-delete; no auto-delete boundary changed.
- EtherHiding adds indicator data, so `WPS_Indicators::INDICATOR_VERSION` moves to `1.3.75-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.75`. Rebuild as `wp-perf-shield-1.3.75.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.74

Detection release. Closes a class of predicted leak surfaced by the ddbricks.com report: writable WordPress-managed directories that should never hold standalone PHP but had no location-based check.

### The prediction

The report showed the dropper staging camouflaged PHP in writable directories WordPress manages: dozens of webshells in `uploads/` (including `wpallimport` temp dirs) and a batch of plugin-mimicking backdoors in `languages/`. The detection pattern that catches those is location-based: any standalone PHP in such a directory is wrong, regardless of its contents.

Auditing where that location-based logic existed showed it covered `uploads/`, `languages/`, and `cache/` only. `check_dropper_cache()` walks all of wp-content but matches just known ZIP patterns and known backdoor filenames, so an unknown-named PHP shell dropped elsewhere under wp-content would slip past it. That leaves equivalent writable directories uncovered, and the natural next staging spots:

- **`wp-content/fonts/`** — the Font Library directory (WordPress 6.5+). It holds uploaded font files only and never legitimately contains PHP. The infected site runs WordPress 7.0, so this directory exists and is writable. Highest-confidence gap.
- **`wp-content/upgrade/`** and **`wp-content/upgrade-temp-backup/`** — update staging. They hold extracted update packages and rollback copies only transiently while an update runs; PHP at rest here is suspect.

### What it adds

A new `check_writable_dirs_for_php()`, registered in the scan pipeline beside the uploads/languages/cache checks. It walks those three directories for `.php` files (skipping the blank `index.php` silence stub):

- A file whose contents match a known malware signature is reported critical and auto-deleted, the same handling as the uploads and languages backdoor tiers (malware signatures do not occur in legitimate font or update files).
- Any other PHP file gets a review-and-delete finding with a "Delete this path" button. `fonts/` is high severity with no caveat. The two update directories are medium and never auto-deleted, with finding text noting that a live update legitimately places plugin and theme PHP there, so the operator confirms no update is running before deleting. This avoids destroying a genuine mid-update rollback.

Detection tiers were simulated: a signature shell in `fonts/` auto-deletes; a camouflaged no-signature PHP in `fonts/` is high with a button; PHP in the update dirs is medium with a button and caveat; a blank `index.php` and non-PHP font files are ignored.

### Residual predicted leak (not closed here, stated honestly)

The hardest remaining staging spot this attacker's camouflage habit points to is PHP injected **inside a legitimate plugin or theme folder** (a stray file added to, say, `plugins/woocommerce/`, named to blend in). Location-based logic cannot help there, because those folders are supposed to contain PHP. Catching it cleanly needs a per-plugin/theme file manifest to diff against, the way `check_core_checksums()` does for WordPress core, and doing that without high false-positive rates is a larger piece of work. It is deliberately left open rather than closed with a heuristic that would flag legitimate plugin files. Signature scanning (`check_php_signatures`, `check_generic_webshell_patterns`) still covers the subset of in-folder shells whose contents match a known pattern.

### Verification

- `check_writable_dirs_for_php()` brace-walks cleanly; registered in the pipeline; `auto_delete` set only on the signature-match tier; delete button on both tiers.
- Tier logic simulated against six cases with correct results.
- `php -l` was NOT run (no PHP CLI in the build environment). Run it on `class-scanner.php` before publishing.

### Compatibility

- No new AJAX handlers, capabilities, or UI. No new persistent options. The only auto-delete path added is signature-matched PHP in font/update directories; the update directories never auto-delete on the non-signature tier.
- No indicator-catalogue changes; this is detection logic, so `WPS_Indicators::INDICATOR_VERSION` stays `1.3.72-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.74`. Rebuild as `wp-perf-shield-1.3.74.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.73

Reporting release. Adds a read-only Logs tab that surfaces the server access/error logs and the WordPress debug log inside the admin, with a one-click campaign-IOC scan, closing the reporting gap where nothing tied a finding's timestamp to the request that produced it.

### Why

Every forensic answer in this campaign ends with "take the timestamp to your access logs." Until now that meant leaving WordPress, finding the log on disk, and grepping by hand. The drop-in guard (1.3.71) logs the moment a drop-in changes, and the C2-in-options check (1.3.69) recovers a download URL, but the operator still had to correlate those against raw server logs elsewhere. This brings the log into the plugin.

### New: Logs tab

A new top-level Logs tab (in the observability band beside Events). It discovers the readable logs at conventional locations, lists them with size, and offers:

- **Scan all logs for campaign indicators** (one click). Greps every readable log for this family's C2 hosts (`biletors.cfd`, `comicstar.lat`), the static campaign token, and a fixed set of delivery fingerprints (`a=dl&token=`, `mode=cloudflare`, `FromBase64String`, `powershell`, the wp-file-manager RCE endpoint, and others), and shows the matching lines grouped by log with the matched term highlighted. This is the line that names the request that planted or served the malware.
- **Tail** and **IOC scan** per individual log for manual correlation against a specific finding's timestamp.

### New class: `WPS_Log_Reader`

Discovery, tailing, and IOC scanning, built read-only and defensively:

- Candidate log paths are code-defined (WordPress `debug.log`, PHP `error_log`, and globbed cPanel-style `access-logs/`, `logs/`, `ssl/logs/` directories derived from ABSPATH). User input never becomes a path that is opened.
- `is_safe_log()` is the security boundary and is re-applied inside the AJAX handler on every request: the resolved real path must be a readable regular file under an allow-listed root (the account home, the WP tree, or a standard web-log root such as `/usr/local/apache/domlogs`), and any path whose basename ends in `.php` is refused, so the reader never discloses source code. Verified against `/etc/passwd`, `wp-config.php`, and out-of-root paths (all rejected) and against the cPanel access log, debug.log, and a domlogs symlink target (all allowed).
- Only the tail is read (256 KB / 800 lines cap); IOC hits are capped at 300. Nothing is written.
- Log lines are returned raw and rendered in the browser via jQuery `.text()`, never as HTML, because access logs carry attacker-controlled user-agent and URL strings. Treating a line as markup would make the viewer a stored-XSS sink; this avoids that.

### New AJAX handler

One handler, `wps_log_inspect` (`manage_options`-gated), with modes `scanall`, `tail`, and `iocscan`. It re-validates any supplied path through `is_safe_log()` before opening it.

### Honest limitation

PHP can only read logs the web-server user has access to. On many hosts the raw access log is owned by the system and will not appear; the WordPress debug log almost always does. The tab states this in-line and points the operator at their hosting panel's log viewer for the same timestamp when a needed access log is not PHP-readable.

### Also: actionable wp-content/languages findings

Prompted by a 33-page WP Perf Shield report from an infected site (ddbricks.com, 160 issues) where the malware staged backdoors in two places. The webshells in uploads (dozens of 64-hex-named `.php` files and `wpallimport` temp-dir `index.php` drops) were auto-deleted correctly. But the second batch, PHP files in `wp-content/languages/` camouflaged with the filenames of installed plugins (`wordpress-seo.php`, `sitepress-multilingual-cms.php`, `all-in-one-seo-pack.php`, `cookie-law-info.php`, and a generated `bricks-components-<random>.php` series), landed in the check's second tier: flagged HIGH but with no delete control, because their content matched no known signature. That left the operator dozens of dead-end "review and delete" items with no in-plugin action.

That tier now carries a "Delete this path" button (the file-deletion path hardened in 1.3.70 handles these safely), and its guidance now states plainly that a filename matching an installed plugin is camouflage, not evidence of legitimacy. The auto-delete tier (signature or known-RAT-filename match) and the `.l10n.php` / blank-`index.php` exclusions are unchanged, so legitimate WordPress translation PHP is still never offered for deletion.

### Verification

- Both new classes and the new handler brace-walk cleanly; `class-admin.php` and `admin.js` balance.
- The `is_safe_log()` boundary was simulated against allowed and disallowed paths with correct results, and the `.php` rejection is in place.
- `php -l` was NOT run (no PHP CLI in the build environment). Run it on `class-log-reader.php`, `class-admin-logs.php`, `class-admin.php`, and `class-remediation-controller.php` before publishing.

### Compatibility

- One new top-level tab, one new `manage_options`-gated AJAX handler, two new classes. No write paths, no new persistent options (nothing to remove on uninstall). No change to auto-delete boundaries.
- No indicator-catalogue changes; the log scanner reuses the existing C2/token lists, so `WPS_Indicators::INDICATOR_VERSION` stays `1.3.72-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.73`. Rebuild as `wp-perf-shield-1.3.73.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.72

Indicator release. A second captured sample of the ClickFix clipboard-PowerShell stage, this one tied to ddbricks.com, was decrypted and verified. It yields a new C2 download host and, more usefully, confirms a static campaign token shared across victims.

### What the second sample showed

The earlier sample (1.3.69) pointed at `biletors.cfd` with `src=themuslimapologist.online`. This one points at `comicstar.lat` with `src=ddbricks.com`. Independently decrypting the AES-256-CBC loader (32-byte key, 16-byte IV, 1,136-byte ciphertext) confirms the YAML analysis: the decrypted stage downloads a Windows `.exe` from comicstar.lat and runs it through a WMI then WScript.Shell then ProcessStartInfo fallback chain.

The decisive detail: both samples carry the identical 64-hex `token` value, `8caaf953…`, across two different victim sites and two different C2 hosts. That makes the token a static campaign build constant, not a per-victim value. It is the most durable fingerprint the campaign has exposed, because it survives both C2-host rotation and victim change.

### What it adds

- `comicstar.lat` added to `WPS_Indicators::clickfix_download_c2_domains()` alongside `biletors.cfd`.
- New `WPS_Indicators::clickfix_campaign_tokens()`, seeded with the shared `8caaf953…` token.
- `WPS_Scanner::check_clickfix_c2_in_options()` gained a third match path. It already matched the download-URL shape (structural regex) and known C2 hosts; it now also flags any decoded `wp_<10hex>_cfg` payload that contains a known campaign token. The token path is the catch when a future build rotates the C2 host again or restructures the URL so the `a=dl` action no longer matches the structural regex. Verified: the new sample trips all three paths, a simulated rotated-host payload with no `a=dl` is caught by the token alone, and a clean WP-Optimize cache config trips none.

### Note on ddbricks.com

The `src=` parameter shows this stage was served from ddbricks.com, a different site than the earlier themuslimapologist.online. So the campaign is hitting multiple WordPress installs with a shared token. The detection added here applies to any infected site regardless of which host or victim a given build names. The server-side remediation for an affected site is unchanged from the steps already outlined: identify and remove the injection source, rotate all credentials, block the C2 host at the edge, and verify no further callbacks. The plugin blocks and detects the symptom; it does not replace that cleanup.

### Verification

- Sample decrypted independently in analysis; C2 host, token, and `src` confirmed against the supplied YAML rather than trusted from it.
- `check_clickfix_c2_in_options()` brace-walk closes cleanly at depth 0 (21/21).
- Three-path detection simulated against the new sample, a rotated-host token-only payload, and a clean cache config.
- `php -l` was NOT run (no PHP CLI in the build environment). Run it on `class-scanner.php` and `class-wps-indicators.php` before publishing, per the standing checklist.

### Compatibility

- No new AJAX handlers, capabilities, nonces, or UI changes. No change to auto-delete safety boundaries.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.69-1` to `1.3.72-1` (new C2 host and campaign token).
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.72`. Rebuild as `wp-perf-shield-1.3.72.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.71

Detection release. Adds a temporal drop-in integrity guard so creation, modification, or removal of a WordPress drop-in is caught and timestamped, instead of only being recognised by publisher signature at scan time.

### Why

The 1.3.54 check (`check_drop_ins`) recognises drop-ins by publisher signature and flags any at a canonical wp-content path that match no known publisher. That is point-in-time only. It cannot tell you a drop-in is new, that one changed, or that one was present and has since vanished. A self-healing backdoor that writes `db.php`, lets it run once to re-plant deleted malware, then removes it, leaves no steady-state trace for a publisher check to catch, and produces exactly the "the scanner saw db.php, now it's gone" pattern.

### New class: `WPS_Dropin_Guard`

It baselines the canonical wp-content drop-ins (`db.php`, `object-cache.php`, `advanced-cache.php`, `sunrise.php`, `maintenance.php`, `db-error.php`, `fatal-error-handler.php`, `install.php`, `php-error.php`), storing a SHA-256, mtime, size, and recognised publisher for each, then reports deviations against that baseline.

Two detection paths:

- `check()` runs inside the hourly scan (registered in `WPS_Scanner::run()`). On first run it establishes the baseline and defers; thereafter it emits findings for any drop-in that appeared, changed, or disappeared since the baseline. Severity is driven by publisher recognition: an unknown-publisher appearance or modification is high and carries a "Delete this path" button; a recognised-publisher change (a cache plugin rewriting its own drop-in on reconfiguration) is medium and benign. A removal is medium and the finding text names the self-healing-backdoor pattern explicitly.
- `watch()` runs on `init`, throttled to once per 60 seconds via a transient. On a normal request the cost is a single transient read. When the window has elapsed it stats the canonical paths, compares against a stored mtime/size fingerprint (no hashing), and logs the precise UTC moment any drop-in appears, changes, or vanishes (`dropin_watch_appeared` / `_changed` / `_removed`). That timestamp is the thread to pull in web-server access logs and SFTP login logs to find how the file was written.

It reuses the scanner's drop-in name list and publisher recognition through two new public accessors (`WPS_Scanner::drop_in_canonical_names()`, `WPS_Scanner::match_drop_in_publisher()`), so there is one source of truth.

### Re-baseline control

A "Reset drop-in baseline" button was added to the Hardening tab beside the existing wp-config baseline reset, wired to a new `wps_rebaseline_dropins` AJAX action (`update_core` capability, mirroring `rebaseline_wpconfig`). After an intentional change (enabling a cache plugin, switching object cache), the operator resets the baseline so the new state becomes the clean reference. The action never modifies a drop-in file; it only re-stores the integrity reference and resyncs the watch fingerprint.

### Honest limitation

A `db.php` loads during `wp-settings.php` before any plugin, so a drop-in that writes and self-deletes inside a single request cannot be observed by an in-PHP hook. The guard catches drop-ins that persist into a later request, plus any change or removal detected between checks. For sub-request transients, the recovered mtime in the log line remains the correlation key.

### Verification

- New class brace-walk closes cleanly at depth 0; `rebaseline_dropins()` and `match_drop_in_publisher()` close cleanly; admin.js braces and parens balance.
- The appear/modify/remove classification was simulated: an unknown new `db.php` is high with a delete button, a WP-Optimize advanced-cache.php rewrite is medium, a removed drop-in is medium.
- `php -l` was NOT run (no PHP CLI in the build environment). Run it on `class-dropin-guard.php`, `class-scanner.php`, and `class-remediation-controller.php` before publishing, per the standing checklist.

### Compatibility

- One new AJAX handler (`wps_rebaseline_dropins`), `update_core`-gated, configuration-only. One new init hook (the throttled watch). No change to auto-delete safety boundaries; drop-in findings are review-and-remediate.
- No indicator-catalogue changes, so `WPS_Indicators::INDICATOR_VERSION` stays `1.3.69-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.71`. New options `wps_dropin_baseline` and `wps_dropin_watch_fp` are removed on uninstall. Rebuild as `wp-perf-shield-1.3.71.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.70

Remediation release. The "Delete this path" button now works on directory findings, not only single files.

### What changed

The Overview-tab "Delete this path" button (added 1.3.61) calls the `wps_delete_file` AJAX handler. That handler refused any path that was not a regular file, returning "Path is a directory  use the plugin folder delete action instead." So findings whose `delete_path` pointed at a directory rendered a button that always errored. The two finding types affected are both produced by the hidden-directory check:

- `Hidden development directory under wp-content/` (medium): leading-dot dev directories such as `.vscode`, `.idea`, `.git`, `.svn`, `.cache` inside a plugin folder.
- `Hidden directory under wp-content/ (no benign explanation)` (high): any other leading-dot directory inside a plugin folder.

The scanner already sets `delete_path` for these only when the directory is contained inside `WP_PLUGIN_DIR`, so the button is exposed for plugin-contained directories only.

`delete_file()` now deletes a directory recursively when the target is a directory, reusing the proven `CHILD_FIRST` iterator pattern from `delete_plugin_folder()`. The file path (single `unlink()`) is unchanged.

### Safety boundary on directory deletion

The handler is gated on `manage_options` and is reachable directly, so the directory branch applies defence-in-depth independent of the scanner's button gating:

- The directory must resolve inside `wp-content/` (tighter than the ABSPATH boundary the file branch uses).
- It must not be a structural root: `wp-content/` itself, or the `plugins/`, `themes/`, `mu-plugins/`, `uploads/`, or `languages/` roots. Each is resolved with `realpath()` and compared against the resolved target.
- It must not be WP Perf Shield's own directory, nor any ancestor of it (so a path that contains the plugin is refused).
- Symlink escape is contained: the target is `realpath()`-resolved before the boundary checks, and `RecursiveDirectoryIterator` does not descend into symlinked directories.

A successful directory deletion logs a `directory_deleted` event with the path and item count, clears the cached scan results, and reports the count back to the operator. Partial failures report how many items were removed and how many failed.

### What this release does NOT change

- No new AJAX handlers, capabilities, nonces, or UI markup. The button, its label, and its confirm dialog are unchanged; only the handler's directory behaviour changed.
- No indicator-catalogue changes, so `WPS_Indicators::INDICATOR_VERSION` stays `1.3.69-1`.
- No change to the file-deletion path, the protected-basename list, or the `delete_plugin_folder` / `delete_theme_file` handlers.

### Verification

- `delete_file()` brace-walk closes cleanly at depth 0 (19/19).
- Directory branch confirmed present with recursive `CHILD_FIRST` deletion, structural-root refusal, self-directory refusal, and the file `unlink()` path retained with a `return` separating the two so there is no fallthrough.
- `php -l` was NOT run (no PHP CLI in the build environment). Run it on `class-remediation-controller.php` before publishing, per the standing checklist.

### Compatibility

- No public API changes. No breaking changes for site operators or external integrators.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.70`. Rebuild as `wp-perf-shield-1.3.70.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.69

Detection release built directly on 1.3.68 (Pro Cache Scanner). It adds a tenth ClickFix family entry, closes a structural-heuristic evasion gap that the sample exposed, and turns a decrypted second-stage PowerShell C2 into a server-side detection signal. All 1.3.68 Pro Cache Scanner coverage is retained unchanged.

### New family entry: Total Database Optimizer

Confirmed sample `total-database-optimizer-9a95.php` (9,808 bytes). MD5 `80322b56aaec6af92d392f8daa36aee7`, SHA-256 `1e5992209203641e6b12b309596c1eb87a46c985eded099214ea036eb316adb3`. Plugin Name "Total Database Optimizer", Author "Cache Software", Description "Advanced performance profiling and latency reduction", `Plugin URI: https://developer.wordpress.org/plugins/`. Handler class `WP_Manager_abc5` reads the base64 payload from option `wp_d4b340aceb_cfg` (self-seeding on first run), registers `add_action('wp_footer', array($this,'render'), 90809)`, and gates injection on the canonical six-condition cloak (`is_admin`/`wp_doing_ajax`/`wp_doing_cron`, REST, role-bearing users, the bot UA regex, and the `_cf_verified` / `_wp_perf_ok` dismiss cookies). The payload is XOR-obfuscated JS run via `new Function()`.

Covered at every layer, matching the Pro Cache Scanner treatment:
- `WPS_Blocker::get_blocked_slugs()` and the `get_patterns()` suffix-rotation regexes (`total-database-optimizer-*`).
- `WPS_Blocker::get_blocked_hashes()` (MD5 + SHA-256).
- `WPS_Blocker::zip_content_signature()` (option key `wp_d4b340aceb_cfg`, class `WP_Manager_abc5`, Plugin Name, slug) so renamed-ZIP uploads are caught by content inspection.
- `WPS_Indicators::malware_option_keys()` and the scanner DB-option remediation list (`wp_d4b340aceb_cfg`), so the persistence option is detected and removable.
- `WPS_Scanner` content-signature list, description map, `clickfix_known_shell_authors()` (`Cache Software`), and the `check_htaccess_false_security()` local substring list.

### Heuristic fix: array-callback evasion in Trait 6

The fake-plugin-shape heuristic's late-priority `add_action` trait used `add_action\s*\([^)]+,\s*[0-9]{5,}\s*[,)]`. The `[^)]+` arg span stops at the first `)`, which in an `array($this,'render')` callback is the array's own closing paren, before the priority argument. The Total Database Optimizer sample used exactly that array-callback form and scored 5/6 instead of 6/6. The span is now `[^;]*?` (statement-bounded, non-greedy), so a parenthesised callback no longer drops the trait. Validated: the sample now scores 6/6; four legitimate `add_action` forms (string callback, array callback, 4-argument, low priority) produce no match; three high-priority evasion forms match.

### ClickFix second-stage C2 recovered and made detectable

A captured ClickFix clipboard PowerShell (AES-256-CBC loader; key/IV/ciphertext as three base64 blobs, executed via `[scriptblock]::Create()`) was decrypted. Its next stage downloads from:

```
https://biletors.cfd/api/index.php?a=dl&token=<64-hex>&src=<victim-domain>&mode=cloudflare
```

`biletors.cfd` is the distribution source; the `src=` parameter names the compromised site that served the lure (captured: themuslimapologist.online). Added:
- `WPS_Indicators::clickfix_download_c2_domains()`, a new download-source C2 list seeded with `biletors.cfd`, kept separate from `tds_c2_domains()` and `cookie_exfil_c2_domains()`. Informational, for egress-blocking guidance and forensic annotation.
- `WPS_Scanner::check_clickfix_c2_in_options()`, a new hourly-scan check (registered in `run()`). It reads every `wp_<10hex>_cfg` option (`LIKE` prefilter then strict shape match, so uncatalogued variant keys are still inspected), base64-decodes the value, and flags an embedded C2 callback by structural regex (download-action + long-hex token, host-agnostic) or by known-host match. The finding extracts the stamped `src=` site. This is the first check that can name an infected site by the C2 URL baked into its own injected payload. It fires only when the callback is in cleartext after the decode; deeper-obfuscated builds remain covered by the file/slug/option-key/hash/shape-heuristic layers. The `src=` value is used for annotation only, never for blocking.

### Verification

- Trait-6 regex validated against the live merged file: sample scores 6/6; three high-priority forms match; four legitimate calls do not.
- C2 check validated end-to-end against the live merged regex: infected option (known key and unknown-key variant) detected with URL and `src=` extracted; a WP-Optimize-style base64 cache config and a non-family option name correctly ignored.
- Pro Cache Scanner and all other 1.3.68 indicators confirmed still present.
- Brace-walk over the new method closes cleanly at depth 0 (18/18). The decrypted PowerShell payload is not reproduced in the codebase; only the recovered host and URL shape are encoded.
- `php -l` was NOT run (no PHP CLI in the build environment). Run it on `class-scanner.php`, `class-blocker.php`, and `class-wps-indicators.php` before publishing, per the standing checklist.

### Compatibility

- No new AJAX handlers, capabilities, nonces, or UI changes. No change to auto-delete safety boundaries; the new C2 finding is review-and-remediate, not auto-delete.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.68-1` to `1.3.69-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.69`. Rebuild as `wp-perf-shield-1.3.69.zip` with `wp-perf-shield/` as the package root before publishing. The dev-only `.claude/` directory is not part of the distributable package.

## 1.3.68

IoC catalogue release. Closes detection and removal coverage for the full 2026-05 ClickFix sample batch, including one previously-unknown family member and two pre-existing signature-layer gaps. No new features, no UI changes, no AJAX surface, no capability changes. The 1.3.67 surgical-edit Clean buttons and the 1.3.66 tab regrouping are unaffected.

### Sample batch surveyed

Ten ClickFix-family ZIPs were inventoried from a captured malware sample folder. Nine were already covered at every layer of the plugin; one (`pro-cache-scanner-6d52.zip`) was previously unknown to the plugin. Two pre-existing samples had partial coverage gaps:

- `advanced-asset-insights-ec06.zip`  fully covered.
- `auto-content-profiler-0b8d.zip`  covered at the slug/pattern/hash/option-key layer, but the Plugin Name string, slug, persistence option key, and handler class name were missing from `WPS_Blocker::zip_content_signature`. Renamed-ZIP uploads carrying this content by a different filename would not have been caught by content inspection. Closed in 1.3.68.
- `native-render-toolkit-9401.zip`  fully covered.
- `pro-cache-scanner-6d52.zip`  **new family entry**, no prior coverage at any layer. See below.
- `pro-font-optimizer-c88b.zip`  fully covered.
- `site-speed-insights-d6e7.zip`  fully covered.
- `starter-image-guard-e9a2.zip`  covered at the central slug list, but the slug was missing from the local `$malware_patterns` array in `check_htaccess_false_security` (the ".htaccess Deny does not stop PHP execution" warning). Same gap for `advanced-asset-insights`, `page-seo-toolkit`, and `auto-content-profiler`. Closed in 1.3.68.
- `total-render-profiler-3753.zip`  fully covered.
- `total-render-toolkit-adae.zip`  fully covered.
- `wp-perf-analytics*.zip` (5 sibling samples)  fully covered.

### New family entry: Pro Cache Scanner

Confirmed sample: `pro-cache-scanner-6d52.zip`. Container holds a single PHP file (`pro-cache-scanner-6d52/pro-cache-scanner-6d52.php`, 9,561 bytes). MD5 `15e17041c615dc272d5cd5ac3bcd5d6f`, SHA-256 `894108561a3b5be93a76ce2bda74602ed5b5305649aae65b43460565ca220201`.

Plugin header:

- Plugin Name: `Pro Cache Scanner`
- Plugin URI: `https://developer.wordpress.org/plugins/` (the developer-docs root URI, the same copy-paste tell the existing structural heuristic scores as a trait)
- Description: `Optimized resource loading to improve Core Web Vitals`
- Version: `3.4.13`
- Author: `Net IO`
- Text Domain: `pro-cache-scanner-6d52`

Behaviour. Identical cloaked-injection pattern as every other ClickFix sibling. Handler class `Health_Proc_1e3d` is instantiated at file load. Constructor reads `get_option('wp_3093c104e2_cfg', '')`, base64-decodes the value, and if shorter than 100 bytes (i.e. on first run) re-seeds it from a hardcoded base64 blob and writes it back via `update_option('wp_3093c104e2_cfg', ..., 'no')`. Constructor then registers `add_action('wp_footer', [$this, 'render'], 91490)`. The `render` method gates injection on the canonical six-condition cloak:

1. Skip when `is_admin()`, `wp_doing_ajax()`, or `wp_doing_cron()` is true. Function names are built via `chr()` concatenation to evade literal-substring scanners (`chr(105).chr(115).chr(95).chr(97).chr(100).chr(109).chr(105).chr(110)` for `is_admin`).
2. Skip when `defined('REST_REQUEST') && REST_REQUEST` (literal split into `'REST_'.'REQUEST'` fragments).
3. Skip when the current user has role administrator, editor, or author. Concatenated as `'admi'.'nistra'.'to'.'r'` etc.
4. Skip when the User-Agent matches the bot regex `bot|crawl|spider|lighthouse|pagespeed|semrush|ahrefs|mj12|dotbot|bingpreview|slurp|yandex|duckduck|facebookexternalhit|twitterbot|whatsapp|telegram|googlebot`.
5. Skip when cookie `_cf_verified` or cookie `_wp_perf_ok` is set. Both cookie names are family-specific opt-out markers; neither is a real Cloudflare cookie. The cookie literals are concatenation-split.
6. If all gates pass, output `'<script>' . $payload . '</script>'` with the base64-decoded payload as a contained string. The payload itself is a double-wrapped JS blob (base64  XOR/permutation lookup against a 256-byte key array  `new Function(decoded)()`) that runs in anonymous-visitor browsers only.

Why the persistence option is the critical removal target. Even after the dropper PHP file is deleted, the `wp_3093c104e2_cfg` option row in `wp_options` survives. The next variant of the dropper that gets uploaded (under any slug) reads from this same option key and self-heals the payload without contacting a remote source. Deleting the file alone is pointless. The 1.3.68 cleanup allow-list update lets the existing per-row delete handler (`wps_delete_single_option`) and bulk delete handler (`wps_delete_db_options`) clear this option safely.

### Where the coverage was added

- **`WPS_Blocker::get_blocked_slugs()`** added `pro-cache-scanner`. This is the literal-substring activation block consumed by `is_blocked()`, `filter_active_plugins()`, `scrub_active_list()`, and the upload-filename guard. Real-time activation of any folder whose name contains `pro-cache-scanner` is now refused; any such folder in the active-plugins list at boot is now force-deactivated.
- **`WPS_Blocker::get_patterns()`** added the two suffix-rotation regexes for `pro-cache-scanner-*`. These catch repackagings where the original `-6d52` 4-hex suffix has been rotated to `-a83f`, `-19be`, etc. The regex bound is `[-_][a-z0-9]{3,8}` to match the family naming convention.
- **`WPS_Blocker::get_blocked_hashes()`** added MD5 `15e17041c615dc272d5cd5ac3bcd5d6f` and SHA-256 `894108561a3b5be93a76ce2bda74602ed5b5305649aae65b43460565ca220201`. File-identity match works regardless of slug rename.
- **`WPS_Blocker::zip_content_signature()`** added: the persistence option key `wp_3093c104e2_cfg`, the handler class name `Health_Proc_1e3d`, the Plugin Name string `Pro Cache Scanner`, and the slug `pro-cache-scanner`. ZIP uploads carrying the payload under any filename are caught by content inspection. Closing the auto-content-profiler signature-layer gap at the same time added `wp_e07ded4e61_cfg`, `DB_Worker_1c49`, `Auto Content Profiler`, and `auto-content-profiler` to the same list.
- **`WPS_Indicators::malware_option_keys()`** added `wp_3093c104e2_cfg`. This is the cleanup allow-list consumed by both the Remediation-tab bulk delete action and the per-row delete action (`class-remediation-controller.php` lines 482 and 550). The option row is the persistence anchor; deleting the dropper PHP file without deleting this option is pointless because the next dropper variant self-heals from it.
- **`class-scanner.php` `check_htaccess_false_security()` local `$malware_patterns`** synced to match the central Blocker slug list. Five previously-missing entries added: `advanced-asset-insights`, `page-seo-toolkit`, `starter-image-guard`, `auto-content-profiler`, `pro-cache-scanner`. The local list is a defensive secondary substring check used by the warning that fires when an operator drops a `Deny from all` rule into the malware plugin's `.htaccess` and believes the threat is neutralised (it is not; `.htaccess` governs HTTP routing only, while WordPress loads plugins via `require_once()` which Apache never sees).
- **`class-scanner.php` `clickfix_known_shell_authors()`** added six Author strings from the captured corpus: `Developer Tools Team` (wp-perf-analytics gen-1), `Smart Software` (native-render-toolkit-9401), `Auto Labs` (pro-font-optimizer-c88b), `Auto Studio` (site-speed-insights-d6e7), `Pro Works` (total-render-profiler-3753), `Net IO` (pro-cache-scanner-6d52). This array provides the bonus trait in the six-trait structural heuristic (not a primary scoring trait, but recorded in the finding context to help operators triage).

### What this release does NOT change

- No new AJAX handlers, no capability changes, no nonce model changes. The 1.3.57 audit's residual-risk acceptances stand.
- No effect on the 1.3.67 surgical-edit Clean buttons, the 1.3.66 tab regrouping, the 1.3.65 onclick fix, or any other prior remediation flow.
- No effect on the structural-trait heuristic logic itself; only the shell-author bonus list and the local fallback substring array were touched.
- No new finding types. The existing scanner finding types (`Plugin folder slug matches known malware family`, `ClickFix-shaped fake plugin folder (heuristic score X/6)`, `.htaccess does not stop malware execution  folder must be deleted`) all pick up the new family automatically through the data changes above.

### Verification

PHP parser fallback (`tools/verify-package.ps1`) passes on all 20 PHP files: braces, parens, and brackets balance after PHP/HTML mode-aware string and comment stripping. Version-marker consistency check passes across the four declared release files (`wp-perf-shield.php` header, `WPS_VERSION` constant, `readme.txt` Stable tag, `doc/readme.md` Current plugin version). Directory layout check passes.

### Compatibility

- No public API changes. No breaking changes for site operators or external integrators.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.67-1` to `1.3.68-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.68`. Rebuild as `wp-perf-shield-1.3.68.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.67

Feature release. Implements the surgical-edit "Clean injection" buttons that have been deferred since 1.3.61, covering two specific finding types in the auto_prepend_file hijack chain. This is the largest functional change since 1.3.61's inline-delete-button addition.

### What it does

Two new finding-card buttons let an operator one-click-remediate two specific malware patterns:

1. **Wordfence WAF wrapper hijack.** Scanner finding type: `wordfence-waf.php auto_prepend hijack: non-canonical include`. The genuine wordfence-waf.php at ABSPATH is a thin wrapper that includes a single canonical Wordfence bootstrap path (`wp-content/plugins/wordfence/waf/bootstrap.php` or the wordfence-protect equivalent). Malware adds a second include line above that points at attacker-controlled payload storage. The Clean injection button removes the specific malicious include line by line-anchored regex match against the offending include target captured by the scanner.

2. **.user.ini auto_prepend_file directive.** Scanner finding type: `.user.ini sets auto_prepend_file to a non-canonical path`. The .user.ini file is plain-text PHP-config (key=value pairs). Malware adds an `auto_prepend_file = "<path>"` line pointing at a malicious PHP script. The Clean injection button removes that specific line, preserving all other directives.

`.htaccess`-based findings of the same shape are deliberately NOT given a Clean button. Operator-edited .htaccess files contain heterogeneous rewrite rules whose interaction with surgical line-removal is unpredictable. Those findings remain instruction-only.

### Recognised cleanable patterns (wordfence-waf.php)

Two regex patterns are tried in sequence per line. The line must match one of them AND contain the offending include target captured by the scanner.

- **Bare include:** `[@]?include[_once]?|require[_once]?\s*\(?\s*['"]<offending>['"]\s*\)?\s*;?` on its own line. Examples: `include('/p.php');`, `@include_once "/p.php"`, `REQUIRE('/p.php')`.
- **file_exists wrapper:** `if\s*\(\s*file_exists\s*\(\s*['"]<offending>['"]\s*\)\s*\)\s*\{?\s*[@]?include[_once]?|require[_once]?\s*\(?\s*['"]<offending>['"]\s*\)?\s*;?\s*\}?` on its own line. The wrapper form is the dominant in-the-wild pattern: `if (file_exists('/p.php')) include('/p.php');` and the brace-wrapped variant `if (file_exists('/p.php')) { include('/p.php'); }`. Both halves of the line MUST reference the SAME offending path  this is what distinguishes the malware idiom from legitimate code that might happen to file_exists-and-include something with a different path in each half.

### Refused (non-cleanable) patterns

If the offending include is on a line that contains other PHP statements and does not match a recognised wrapper form, the handler returns `mixed_line` status and the button reports an error pointing the operator at manual edit. Two examples:

- `<?php @include('/p.php'); @include_once(ABSPATH . 'wp-content/plugins/wordfence/waf/bootstrap.php'); ?>`  the offending include sits on the same line as the canonical include. Removing the line would also remove the canonical include. Refused.
- `if (file_exists('/legit.php')) include('/payload.php');`  the file_exists check and the include reference different paths. This is unusual and may indicate either an unfamiliar code pattern or a hand-crafted malware variant that requires operator review. Refused.

Both refusals produce a clean error message with explicit "edit manually" guidance. The handler never silently fails or partially writes.

### Safety mechanisms (every Clean operation)

- **Hard-coded path.** Each handler operates on exactly one specific file. `clean_wfwaf_include()` operates on `ABSPATH . 'wordfence-waf.php'` and accepts no path parameter from the client. `clean_user_ini_prepend()` operates on `ABSPATH . '.user.ini'` and accepts no path parameter from the client. This is materially narrower than the 1.3.57 residual-risk WPSEC-001 boundary on `wps_delete_file` (which accepts arbitrary paths inside ABSPATH under `manage_options` trust). Each Clean handler can ONLY ever touch its one specific file.
- **Backup-on-edit.** The original file content is copied to `<file>.wps-backup-<unix-timestamp>` before any modification. Timestamp collisions are handled by appending a numeric suffix. The backup is plain file content, recoverable by `mv` from the operator's shell. The backup is NOT auto-deleted; the operator decides when to clean it up.
- **Atomic write.** Cleaned content is written to `<file>.wps_tmp` and `rename()`d into the original path. If `file_put_contents()` returns false or `rename()` fails, the original file is untouched and the temp file is unlinked. Matches the pattern used by `clean_login()`, `clean_functions()`, and `clean_cron()` since 1.3.x.
- **Pre-check.** The offending content must actually be present in the file. If the scanner finding is stale (operator already cleaned manually before clicking), the handler returns success with `already clean` and does not rewrite the file. No backup is created in this case (nothing to back up).
- **Mid-line guard.** Conservative-by-default. If the offending content is on a line that contains other code and does not match a recognised wrapper form, refuse with a clear error pointing at manual edit.
- **Post-write verification.** After the `rename()` succeeds, `clearstatcache()` is called and the file is re-read. The same regex used to detect the offending content originally is run against the re-read content. If the offending content is still present, the handler logs a `wfwaf_clean_failed_post_verify` or `user_ini_clean_failed_post_verify` event, returns a critical error to the operator, and points at the backup file path.
- **Logged.** Every successful clean writes a `wfwaf_cleaned` or `user_ini_cleaned` event to the security event log including the offending value and the backup filename.

### Verification

The cleaning logic was extracted into pure functions (`clean_wfwaf_compute()` and `clean_user_ini_compute()`) so it can be tested in isolation without WordPress bootstrap. 27 input cases were tested:

- **wordfence-waf.php:** typical wrapped form, bare include, idempotent (re-run on cleaned content), brace-wrapped form, mismatched-paths refusal, freeform mid-line refusal, multi-include sequence, CRLF line endings, uppercase keywords, regex-metachar paths, already-clean file. 20 sub-assertions, 20/20 passed.
- **.user.ini:** standard quoted form, bare unquoted form, idempotent, uppercase directive, empty file. 7 sub-assertions, 7/7 passed.

The button rendering was tested against 8 input cases including paths with apostrophes, ampersands, and hidden-dot directories. The static-render-then-parse pipeline produces a complete `wpsForensicAct(this, "<action>", {"match": "<value>"}, "<confirm>")` JS expression after browser HTML-attribute extraction. All 8 cases plus 3 suppression cases (`remediated=true`, unknown strategy, missing strategy) passed.

### Code changes

- `includes/class-scanner.php`: added `clean_strategy => 'wfwaf_hijack'` to wordfence-waf.php non-canonical-include findings (line ~1298). Added `clean_strategy => 'user_ini_prepend'` to .user.ini auto_prepend_file findings, but ONLY when `cfg_name === '.user.ini'` (line ~1351-1357)  the same loop processes both .user.ini and .htaccess findings, but only .user.ini gets the strategy. Both findings get a slightly updated `action` text mentioning the Clean button.
- `includes/class-remediation-controller.php`: registered `wps_clean_wfwaf_include` and `wps_clean_user_ini_prepend` in the `$ajax_actions` array. Added five new methods: `clean_wfwaf_include()` (~80 lines), `clean_wfwaf_compute()` (~50 lines, pure function), `contains_include_target()` (helper), `clean_user_ini_prepend()` (~70 lines), `clean_user_ini_compute()` (~30 lines, pure function), `user_ini_contains_prepend()` (helper).
- `includes/class-admin-overview.php`: added Clean injection button rendering when `clean_strategy` is set on a finding. Uses the 1.3.65 `esc_attr()` pattern for the onclick attribute. The map of strategy-to-AJAX-action is hardcoded in the rendering block.
- `assets/css/admin.css`: added `.wps-finding-clean-btn` rule set with amber colouring (`#b45f06`) to visually distinguish surgical edit (modify file in place, backup created, reversible) from delete (destructive, irreversible at `#a00`).

### What 1.3.67 does NOT change

- No new capabilities. Both new handlers run under `manage_options` trust, the same as `wps_delete_file`.
- No new nonces. Both new handlers use the existing `wps_action` nonce.
- No effect on the IoC catalogue. No detection changes.
- No effect on the 1.3.61 inline-delete-button, 1.3.65 onclick fix, 1.3.66 tab regrouping, or any prior remediation behaviour. The new buttons sit alongside the existing Delete this path button in finding cards where applicable.
- The Forensics-tab buttons are independent and unaffected.

### Compatibility

- No public API changes. No breaking changes for site operators or external integrators.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.66-1` to `1.3.67-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.67`. Rebuild as `wp-perf-shield-1.3.67.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.66

UX release. Three operator-driven changes shipped together because they were raised in a single feedback round and touch overlapping surfaces (the admin tab navigation and the Diagnostics-tab content).

### What changed

- **DOC-20260508-009** Tab order reorganised. Pre-1.3.66 order: Overview, Forensics, Diagnostics, Remediation, Hardening, Events, Settings. The interleaving had no functional logic  Diagnostics sat between two action tabs, Events sat between Hardening and Settings. New order groups tabs by purpose:
  - **Action band:** Overview, Forensics, Remediation, Hardening
  - **Observability band:** Diagnostics, Events
  - **Configuration band:** Settings
- A new `$tab_group_starts` array in `class-admin.php` lists the slugs of tabs that begin a new functional band after the leading band (currently `[ 'diagnostics', 'settings' ]`). The renderer adds a `wps-tab-group-start` CSS class to those tabs. `admin.css` turns that class into a 14px left margin and a 1px inset left edge using `--wps-line` (matching the rest of the panel borders for visual consistency). The result is a subtle visible boundary between bands without consuming additional vertical space or requiring a row break.
- **DOC-20260508-010** Hover state added to non-active tabs. The pre-1.3.66 styling left tabs as flat text on a white container with no hover affordance, so operators could not visually distinguish them from labels. The fix uses a `:not(.nav-tab-active)` guard so the hover treatment applies only to non-active tabs and does not compete with the active state's gradient. Hover/focus-visible properties: `background: rgba(20, 32, 45, .055)` (subtle gray tint), `color: var(--wps-ink)` (text colour shifts from muted gray to primary ink), `transition: background-color .15s ease, color .15s ease, box-shadow .18s ease` (smooth state transitions). `cursor: pointer` is now explicit on the base tab rule.
- **DOC-20260508-011** Active tab gets a 2px teal inset bottom accent. The active state previously relied entirely on a slightly-different background gradient and an outer shadow, which was readable on light backgrounds but not strongly distinguished from a hovered tab. The new active state keeps the existing background gradient and outer shadow and adds `inset 0 -2px 0 #14565d` to the box-shadow stack. The teal `#14565d` matches the version pill text colour from `assets/css/admin.css:67` and is the brand teal used elsewhere. Inset shadows do not clip with the rounded outer container the way border-bottom would.
- A combined `.nav-tab-active.wps-tab-group-start` selector handles the case where the active tab is also the first tab of a band (Diagnostics-as-active or Settings-as-active). Without this combined rule, the `.nav-tab-active` rule's box-shadow would override the `.wps-tab-group-start` rule's box-shadow because they target the same property. The combined selector layers all three shadow components: outer drop shadow, inset bottom accent, inset left separator.
- **HARDEN-20260508-012** "Latest signals" sub-section removed from the Diagnostics tab. The card previously rendered four event-derived metrics in a 2-column grid alongside "Security posture": last attack signal, last clearance, unique attacker IPs, current blocked IP attempts. Three of those four metrics duplicated information already shown by other Diagnostics sections (the cards row at the top of the tab, the "Active hostile IP blocks" section, the "Recent activity by day" section, the "Top attacking IPs" section). The fourth (last clearance) was the only genuinely-new datum and was low-value. The operator reported the card visually echoed the Events tab, which is the dedicated raw-event-log surface. The card is removed and the parent grid simplifies from `1fr 1fr` to a single full-width container so "Security posture" spans the whole row. `$analytics` is still computed because other sections consume its sub-keys (`daily`, `top_attackers`, `top_subjects`, `event_mix`).

### Code changes
- `includes/class-admin.php`: tab order regrouped in the `$tabs` array (lines ~245-253). New `$tab_group_starts` array added (line ~265). Tab-rendering loop (lines ~175-197) updated to read `$tab_group_starts` from the context and add the `wps-tab-group-start` class to qualifying tabs. The context array passed to tab renderers gains a `tab_group_starts` key.
- `includes/class-admin-diagnostics.php`: 2-column grid wrapper (was line 123) replaced with a single-width container. "Latest signals" card markup (was lines 136-144) removed. A 1.3.66 explanatory comment block records the removal decision and the rationale for future maintainers.
- `assets/css/admin.css`: four new/updated rules covering `.nav-tab` (cursor + transition added), `.nav-tab:not(.nav-tab-active):hover` and `:focus-visible` (new hover state), `.nav-tab.wps-tab-group-start` (new group-separator), `.nav-tab-active` (added inset bottom accent to existing box-shadow), and `.nav-tab-active.wps-tab-group-start` (combined-state shadow stack).

### What 1.3.66 does NOT change
- No scanner changes. No new finding types. No IoC catalogue updates.
- No new AJAX handlers. No capability changes. No nonce model changes. The 1.3.57 audit's residual-risk acceptances stand.
- No effect on the Forensics-tab buttons or the 1.3.65 Overview-tab inline-delete fix, which use independent rendering paths.
- No effect on the 1.3.63/1.3.64 header pill design or the 1.3.64 tagline.
- The `$analytics` data structure passed into Diagnostics is unchanged. Other consumers of `$analytics['last_attack']`, `$analytics['last_clearance']`, `$analytics['unique_ip_count']`, and `$analytics['blocked_ip_attempts']` (if any exist outside the removed card) continue to work.

### Tests
- PHP parser fallback (`php -l`): clean across all 20 PHP files.
- JS syntax (`node --check`): clean.
- Static-render verification of the new tab nav: 6/6 assertions pass.
  1. Tab order matches expected sequence (Overview, Forensics, Remediation, Hardening, Diagnostics, Events, Settings).
  2. Diagnostics tab carries the `wps-tab-group-start` class.
  3. Settings tab carries the `wps-tab-group-start` class.
  4. Events tab does NOT carry the `wps-tab-group-start` class (it's mid-band, not band-start).
  5. Overview tab does NOT carry the `wps-tab-group-start` class (it's the leading tab).
  6. When `active_tab=diagnostics`, the rendered tag carries both `nav-tab-active` and `wps-tab-group-start` classes.
- CSS cascade walked by inspection. Each new selector's specificity calculated and confirmed against the existing rules. The `:not(.nav-tab-active)` guard prevents the hover state from applying to the active tab. The combined `.nav-tab-active.wps-tab-group-start` selector beats both individual rules by class count.
- "Latest signals" string presence in `class-admin-diagnostics.php`: 0 in rendered markup; 2 occurrences remaining are inside the historical-context comment that records the removal decision (intended).

### Compatibility
- No public API changes. No breaking changes for site operators or external integrators.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.65-1` to `1.3.66-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.66`. Rebuild as `wp-perf-shield-1.3.66.zip` with `wp-perf-shield/` as the package root before publishing.

### Verification step taken
The 1.3.65 changelog committed to a new release-checklist step for admin-UI changes: "render the affected component to a static HTML string in a PHP test harness; extract the rendered attribute or text and confirm it parses as the intended structure." This release is the first to apply that step. The static-render harness produced rendered HTML for every possible `active_tab` value, then ran six assertions against the resulting markup. All six passed before the build was packaged. The CSS cascade was walked manually by listing the new selectors, calculating specificity, and confirming each rule's properties win or lose against the existing rules in the expected way.

## 1.3.65

Bug-fix release. The inline "Delete this path" button on Overview findings, introduced in 1.3.61 and described as working in the 1.3.61 changelog, has not actually worked since it was added. This release fixes the underlying cause and verifies the fix end-to-end.

### What was broken
The 1.3.61 implementation rendered the button with this PHP template:

```php
<button type="button" class="button wps-finding-delete-btn"
    onclick="wpsForensicAct(this, 'wps_delete_file', { path: <?php echo wp_json_encode( $f['delete_path'] ); ?> }, <?php echo wp_json_encode( $confirm_msg ); ?>)">
    Delete this path
</button>
```

`wp_json_encode()` returns JSON values with double-quote string delimiters: `"\/wp-content\/plugins\/..."`. Interpolating those directly into a double-quoted `onclick="..."` attribute produced HTML like:

```html
onclick="wpsForensicAct(this, 'wps_delete_file', { path: "/wp-content/..." }, "...")"
```

Browsers parse HTML attributes by reading until the next un-escaped delimiter. The first inner `"` after `path:` closed the attribute. The browser interpreted the rendered onclick as `wpsForensicAct(this, 'wps_delete_file', { path: ` and treated everything after as separate (malformed) HTML. No click handler was installed. Clicking the button did nothing  no AJAX request, no error, no feedback. The button was silently inert.

### Why it took four releases to catch
1.3.61 shipped the feature with a code review that confirmed the markup compiled and the AJAX handler was registered, but did not actually click the rendered button or inspect the produced HTML. 1.3.62, 1.3.63, and 1.3.64 each touched other parts of the codebase  child-theme cleanup, header pill restyling, CSS cascade fix  but none of them re-verified the 1.3.61 button. The bug was caught only when an operator reported "Delete this path button doesn't work?" with screenshots.

This is a real failure of process. Documenting it in the SSOT audit history because: (a) the audit trail should record it, (b) it represents a discipline gap that needs to be closed for future work, (c) future maintainers reviewing the project history should see what went wrong and what changed in response.

### What 1.3.65 fixes
- **HARDEN-20260508-008** `includes/class-admin-overview.php` button rendering rewritten to match the working pattern used by the Forensics-tab `forensic_action_button()` helper. The onclick JS expression is now built as a single PHP string and passed through `esc_attr()` before placement into the rendered HTML. `esc_attr()` converts inner `"` to `&quot;`, which the browser HTML-decodes back to `"` when populating the JS engine's argument list. The resulting JS engine receives `wpsForensicAct(this, "wps_delete_file", {"path": "..."}, "...")` with all three arguments intact, the click handler installs correctly, and clicking the button now triggers the AJAX call to `wps_delete_file`.

### Verification
End-to-end test simulates the browser's HTML-attribute extraction and JS engine's argument parsing:
- 4/4 test paths pass (simple, apostrophe, ampersand, the actual `seo-by-rank-math/vendor/donatj/phpuseragentparser/.helpers` path from the operator screenshot).
- The simulated browser parse extracts the complete `wpsForensicAct(this,...)` expression rather than truncating at the first inner double-quote.
- The simulated JS engine parse round-trips `data.path` to the original delete_path value, the `action` argument to `'wps_delete_file'`, and the confirmation message arg to a string containing the path.

### Process gap and what changes
The 1.3.61 release shipped under a release-checklist that verified version markers, PHP syntax, JS syntax, and ZIP package integrity. It did not verify that the new feature actually worked when rendered. The same gap let 1.3.63's CSS specificity regression ship (the severity-aware issue alert design did not actually render in 1.3.63 because the existing rule's `!important` declarations overrode the new class-based rules; fixed in 1.3.64). Two consecutive releases shipping features that did not work as documented is not coincidence  it is the absence of an end-to-end verification step.

For releases touching the rendered admin UI going forward, the release-checklist now includes:
1. Render the affected component to a static HTML string in a PHP test harness.
2. Extract the rendered attribute or text in question and confirm it parses as the intended structure (well-formed HTML attribute, well-formed JSON, syntactically-valid CSS rule).
3. For interactive elements with onclick or similar event handlers, confirm the JS-engine-visible argument list matches the intended values.

This will not catch every class of regression but it would have caught both 1.3.63 and 1.3.61's bugs.

### Code changes
- `includes/class-admin-overview.php` lines ~95-122: button rendering rewritten. New behaviour: build the onclick JS expression as a single PHP string, pass through `esc_attr()` for HTML-attribute placement.

### What 1.3.65 does NOT change
- No detection changes. No new finding types. No IoC catalogue updates.
- No new AJAX handlers. No capability changes. No nonce model changes. The 1.3.57 audit's residual-risk acceptances stand.
- No effect on the Forensics tab's existing buttons, the 1.3.62 child-theme `clean_functions()` walking, the 1.3.63/1.3.64 header pill design, or any other prior behaviour.

### Compatibility
- No public API changes. No breaking changes for site operators or external integrators.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.64-1` to `1.3.65-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.65`. Rebuild as `wp-perf-shield-1.3.65.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.64

CSS-only release. Two changes: a specificity-cascade fix that allows the 1.3.63 severity-aware issue-alert design to actually render, and a tagline update from "Focused malware defense." to "Forensic WordPress malware defence."

### What 1.3.63 was supposed to deliver but did not
The 1.3.63 release converted the header pills from inline-styled `<span>` elements to class-based markup (`wps-version-pill`, `wps-issue-alert`, `wps-issue-dot`, `wps-sev-{critical|high|medium|low}`) and added a block of new rules at the bottom of `assets/css/admin.css` to give the issue alert a severity-aware coloured pill with a pulsing dot. Independent post-release inspection of the cascade  prompted by an operator screenshot showing what looked like an unchanged header  found that the existing rule at line 50 of the stylesheet, `.wps-app > h1 span { ... }`, continued to match both header pills (the version pill and the issue alert) because both are `<span>` children of the `<h1>`. That rule used `!important` on `background`, `color`, `font-size`, `font-weight`, and `padding`. The 1.3.63 issue-alert rules at the bottom of the file did not use `!important`, so even though their selector specificity was technically higher (`.wps-issue-alert.wps-sev-critical` is `0,2,0` vs `.wps-app > h1 span` at `0,1,2`), the existing rule's `!important` declarations won the cascade for the colour-and-size properties that drove the visible appearance. The issue alert continued to render as a white-gradient pill with teal text, identical to the version pill, identical to the pre-1.3.63 appearance.

### What 1.3.64 fixes
- **HARDEN-20260508-006** Selector rescope. The existing rule at `assets/css/admin.css` line 50 changed from `.wps-app > h1 span` to `.wps-app > h1 .wps-version-pill`. The version pill keeps its existing white-gradient teal-text appearance (this was working). The issue alert is no longer captured by that rule, so the 1.3.63 `.wps-issue-alert` and `.wps-sev-*` rules at the bottom of the file now drive its visual without competition. The severity-aware red/orange/amber/blue colouring documented in the 1.3.63 changelog is now what actually renders.
- Dead-code removal. The attribute selector `.wps-app > h1 span[style*="background:#c00"]` (lines 73-75 in pre-1.3.64 admin.css) was a hack that overrode the OLD inline-styled issue pill's `background:#c00` red with translucent pink, which is what produced the lavender appearance visible in pre-1.3.63 operator screenshots. The 1.3.63 markup conversion eliminated all inline `style=""` attributes on header pills, so the attribute selector could no longer match anything. Removed.
- Redundant-rule removal. The `.wps-version-pill` rule added at the bottom of admin.css in 1.3.63 attempted a different (gray-rectangle) treatment for the version pill, but the version pill's existing white-gradient pill styling was already correct and the operator's reported visual concern was about the issue pill specifically. Two rules competing for the version pill would have created confusion. Removed.

### Tagline change
- **DOC-20260508-007** Tagline updated. The CSS `::after` content at line 41 changes from `"Focused malware defense."` to `"Forensic WordPress malware defence."` Three things drive the change: (1) "Focused" is a generic positive adjective that does no specific work, (2) "malware defense" is generic and indistinguishable from every other security plugin's marketing copy, (3) the original used American spelling ("defense") inconsistent with the British-spelling editorial register the rest of the project documentation uses. The replacement specifies WordPress as the threat surface, signals depth of analysis (drop-in audits, persistence detection, structural shape heuristics, captured-sample IoC catalogue) via "Forensic", and matches the documentation register's British spelling.

### Code changes
- `assets/css/admin.css` line 41: tagline content updated.
- `assets/css/admin.css` line 50: selector rescoped from `.wps-app > h1 span` to `.wps-app > h1 .wps-version-pill`.
- `assets/css/admin.css` lines 73-75 (pre-1.3.64): dead attribute selector `.wps-app > h1 span[style*="background:#c00"]` removed.
- `assets/css/admin.css` end-of-file: redundant `.wps-version-pill` rule removed.

### What 1.3.64 does NOT change
- No PHP changes. The header markup in `class-admin.php` was already correct as of 1.3.63; the bug was in the CSS cascade only.
- No scanner changes. No new finding types. No IoC catalogue updates.
- No AJAX handler changes. No capability changes. No nonce model changes. The 1.3.57 audit's residual-risk acceptances stand.
- No effect on the 1.3.61 inline "Delete this path" button on Overview findings, the 1.3.62 `clean_functions()` parent+child theme walking, or any prior remediation behaviour.

### Tests
- PHP parser fallback (`php -l`): clean across all 20 PHP files.
- CSS validation by inspection: no missing braces, no trailing operators, no orphan selectors. Specificity cascade walked manually and confirmed correct.
- CSS/PHP class symmetry verified: every class referenced in `includes/class-admin.php` has a matching rule in `assets/css/admin.css`.
- Tagline length check: "Forensic WordPress malware defence." is 35 characters, fits within the existing `max-width: 240px` constraint at `font-size: 13px`.

### Audit history note
1.3.63 represents the INTENT of the header redesign  the operator-facing changelog and SSOT entries from that release describe what the design was supposed to be, and that record is left intact rather than retroactively edited. 1.3.64 represents the actual delivery. An auditor reviewing the trail can see the sequence: design intent in 1.3.63, cascade-bug discovery between 1.3.63 and 1.3.64, fix in 1.3.64. This kind of two-release "intent then delivery" pattern is the correct way to handle a buggy release once the build has shipped, because retroactively editing the 1.3.63 docs would erase the audit history.

### Compatibility
- No public API changes. No breaking changes for site operators or external integrators.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.63-1` to `1.3.64-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.64`. Rebuild as `wp-perf-shield-1.3.64.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.63

UI polish only. No detection changes, no security boundary changes, no scanner changes. This release closes a single visual-design issue raised against the admin header pills.

### User-facing
- **DOC-20260508-005** Header pill restyling. The pre-1.3.63 admin header rendered the plugin version (`v1.3.62`) and the issue-count alert (`1 issue` / `5 issues`) as two visually-similar pill-shaped spans sitting immediately after the "WP Perf Shield" title. The two pills were at near-identical sizes with similar border-radius values, which made them read as equal-weight metadata. Information hierarchy was wrong: the version pill is informational, the issue-count is actionable, but the visual treatment did not differentiate them. Compounding the problem, the issue-count's `#c00` red sat against the magenta-tinted right portion of the gradient header background and rendered as muted lavender after JPEG compression on operator screenshots, defeating the alert intent. The 1.3.63 redesign keeps both pills in their original position (the right side of the gradient header has the "Focused malware defense." tagline so the alert cannot move there without colliding) but gives each pill a distinct visual identity: the version pill becomes a smaller rounded-corner rectangle in muted gray (`#555` text on `#f0f0f0` background), the issue alert becomes a fully rounded pill with severity-aware colour, larger padding, drop shadow for depth on the gradient, and a subtle pulsing dot.
- The issue alert's colour is severity-aware. Critical findings produce a red alert (`#dc2626`), high produces orange (`#ea580c`), medium produces amber (`#ca8a04`), low produces blue (`#2563eb`). The alert displays the highest severity present in the cached findings array. Findings with no `severity` field fall back to the medium amber default rather than red so the UI does not over-claim severity when the data is absent.
- The pulsing dot animation respects the `prefers-reduced-motion: reduce` media query. Operators who set this preference at the OS or browser level see the dot as a static circle. The dot is also `aria-hidden="true"` because it duplicates the count text for screen readers.

### Code changes
- `includes/class-admin.php` — header `<h1>` markup converted from inline-styled `<span>` elements to class-based markup (`wps-app-title`, `wps-version-pill`, `wps-issue-alert`, `wps-issue-dot`, plus a severity modifier class `wps-sev-{critical|high|medium|low}`). New PHP block before the markup walks the cached findings array, finds the highest severity, and emits the corresponding modifier class.
- `assets/css/admin.css` — appends ~70 lines of new rules covering the four classes plus the `@keyframes wps-issue-pulse` animation and the `prefers-reduced-motion` override. The colour palette stays inside the conventional security-UX vocabulary (red/orange/amber/blue) and uses sufficiently saturated values to survive JPEG compression on screenshots without bleeding toward the surrounding gradient.

### What this release does NOT change
- No scanner changes. No new finding types. No changes to the detection IoC catalogue.
- No AJAX handlers added or modified. No capability changes. No nonce changes. The 1.3.57 audit's residual-risk acceptances stand.
- No effect on any operator workflow other than the appearance of the header pills. The version pill still shows the plugin version, the issue alert still shows the cached findings count, and clicking either does nothing in 1.3.63 (consistent with prior behaviour). Making the alert clickable to deep-link into the Overview tab is potential future work but is out of scope for this release.

### Tests
- PHP parser fallback (`php -l`) on all 20 PHP files: clean.
- Severity-rank logic isolated test: 8/8 PASS covering single-severity, mixed-severity, default fallback, and unknown-severity cases.
- CSS/PHP class symmetry verified: every class referenced in the PHP markup has a matching rule in `assets/css/admin.css`.
- CSS syntax verified by inspection (no missing braces, no trailing operators, no unclosed selectors).

### Compatibility
- No public API changes. No breaking changes for site operators or external integrators.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.62-1` to `1.3.63-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.63`. Rebuild as `wp-perf-shield-1.3.63.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.62

Selective uptake of findings from a third-party static code review of 1.3.59. The review proposed seven hardening changes plus two documentation corrections; this release acts on the four findings that were genuinely valid bugs and explicitly defers the remaining three (one that was already mitigated by the 1.3.57 audit's WPSEC-006 stub guard, two that contradicted prior 1.3.57 audit decisions documented in SSOT). The selective uptake protects the integrity of prior audit decisions while addressing the actual gaps the review identified.

### User-facing
- **DOC-20260508-001** `clean_functions()` cleanup now scans both parent and child theme `functions.php` files. Previously the method only inspected `get_template_directory() . '/functions.php'`, which on any child-theme site resolves to the parent theme's file. The credential-harvester injection delivered by the wp-locale-handler RAT v1.7 family lands in whichever `functions.php` WordPress treats as active when the malicious payload runs, so on child-theme sites the injection persisted in the child's `functions.php` and the cleanup was missing it. The new logic takes the union of `get_template_directory()` and `get_stylesheet_directory()`, de-duplicates (when no child theme is active both return the same path), inspects each file independently, and reports per-file outcomes via a single message field listing every file's status ("themename: cleaned" / "themename: already clean" / "themename: pattern not matched").
- **DOC-20260508-002** Plugin documentation now correctly states that security events are stored under `wp-content/plugins/wp-perf-shield/logs/events.php`. The previous text said `wp-content/uploads/wps-logs/events.php`, which contradicted the actual `WPS_LOG_DIR` and `WPS_LOG_FILE` constants defined at lines 20-21 of `wp-perf-shield.php`. An operator looking for the log file based on the readme would have failed to find it. No code change; this is a documentation correction only.

### Hardening
- **HARDEN-20260508-003** Admin JavaScript message rendering now escapes user-controlled fragments before HTML insertion at the vulnerable call sites. The exposure was narrow (admin clicking remediation on attacker-influenced filenames, option names, or attachment titles) but the pattern was fragile. Specific changes: `assets/js/admin.js` lines 175 / 190 / 205 now wrap `r.data.message` and `r.data.error` in `esc()` before passing to `remMsg()`. The `wps_clean_wpconfig` flow now wraps the success message in `esc()` (the per-pattern `esc()` for `removed[]` items was already correct). The `wps_delete_db_options` flow now escapes the success message and replaces the unsafe `d.deleted.join('</code>, <code>')` pattern (which would let an option name containing `</code>` break out of the markup) with a per-item map that wraps each option name in `esc()` independently. The `wpsForensicAct` success replacement now uses jQuery's element constructor `$('<span>', { class: ..., text: ... })` instead of string concatenation, so the message is text-inserted and auto-escaped by jQuery rather than treated as raw HTML.
- The `msg()` and `remMsg()` helper functions themselves remain `.html()`-based because legitimate callers (the `Run scan now` flow at line 86, the exfil-cleanup flow at line 157, the wp-config-cleanup flow at line 222, the DB-options-delete flow at line 251) compose detail messages with intentional `<a>`, `<br>`, `<strong>`, and `<code>` markup. Switching the helpers to `.text()` blindly would render that markup as literal text and break the UI. The escape-at-call-site pattern matches the existing `esc(f.file)`, `esc(item.label)` style already in use elsewhere in the file.

### Documentation
- **DOC-20260508-004** Selective correction of the "operator-target" terminology slip-back identified by the third-party reviewer. The 1.3.56 rename retired "operator-target site" in favour of "victim site" because the original term was ambiguous (could mean "target FOR the operator" / correct OR "target OWNED BY the operator" / incorrect). Several 1.3.59 entries reintroduced the deprecated terminology in new content. Corrected: `readme.txt:109` (1.3.59 entry), `doc/changelog.md` 1.3.59 entry, `doc/ssot.md:248` (1.3.59 entry), `doc/upgrading.md:438` (1.3.59 entry), `doc/upgrading.md:447` (1.3.59 acceptance criteria). Deliberately left unchanged: historical text in 1.3.55 and 1.3.56 changelog entries describing the original terminology and the rename, references to the deprecated function name `WPS_Indicators::known_rat_operator_targets()` (the alias still exists in code and renaming the documentation references would create a code-vs-docs mismatch), and pre-1.3.56 release entries (those describe the codebase as it was at that release). A blanket find-and-replace across all four files would have broken these legitimate references.

### Findings explicitly NOT acted on
The third-party review proposed three additional changes that this release deliberately does not implement, with the rationale recorded for future audit reference:
- **`delete_file()` per-path nonce binding.** The reviewer recommended generating a path-specific nonce hash and verifying it before deletion, on the grounds that admin-session compromise could turn the handler into a broad file-deletion primitive. The 1.3.57 formal audit explicitly considered this trade-off and accepted the residual risk: the existing nonce + `manage_options` capability + ABSPATH containment + WPSEC-003 (1.3.57) protected-basename list controls were judged sufficient, and per-path nonces would create race conditions between scan output and click action that would break legitimate operator workflows. Reopening this decision warrants its own audit cycle rather than a third-party review's recommendation.
- **Per-finding `delete_scope` validation.** The reviewer recommended adding an explicit `delete_scope` field to every finding and validating that the target path matches the declared scope before auto-remediation. The architectural point is reasonable as a defence-in-depth layer, but in practice the scope is already implicit (only specific scanner checks set `auto_delete=true`, and each check has knowledge of which directory class its findings belong to). Adding explicit `delete_scope` plumbing across every check is meaningful refactor work, not a third-party-review-driven point fix. Deferred for deliberate consideration in a future audit cycle.
- **`tools/update-indicators.php` removal from release ZIP.** The 1.3.57 audit's WPSEC-006 finding noted the same concerns the reviewer raised (incomplete WordPress bootstrap, unsafe regex-based PHP source rewriting, absent feed trust model) and chose to keep the file as a clearly-labelled stub with an explicit `example.com` execution guard. The dangerous code paths are unreachable until someone replaces the placeholder URL. The reviewer's "remove from release ZIP" recommendation is more aggressive than 1.3.57's accepted position; reopening it would silently overturn a documented audit decision.

### Code changes
- `includes/class-remediation-controller.php` — `clean_functions()` rewritten to walk a de-duplicated array of parent and child theme `functions.php` paths. Per-file outcomes accumulated into a `$results` array and emitted as a single combined message via `wp_send_json_success` (or `wp_send_json_error` if any individual file failed to write). The injection-marker constant `d3AtY29udGVudC91cGxvYWRz` is hoisted into a local variable for clarity. The injection-removal regex is unchanged.
- `assets/js/admin.js` — `esc()` calls added at lines 175 / 190 / 205 / 222 / 233 / 251 / 259, the `d.deleted.join('</code>, <code>')` pattern replaced with `d.deleted.map(...).join(', ')`, and the line 349 `replaceWith` converted to `$('<span>', { class: ..., text: ... })` jQuery element constructor.
- `readme.txt` — log path documentation corrected, 1.3.59 changelog entry "operator-target site" -> "victim site", 1.3.62 changelog entry added, stable tag bumped.
- `doc/changelog.md`, `doc/ssot.md`, `doc/upgrading.md` — selective "operator-target" corrections in 1.3.59 entries; doc/changelog.md gets the 1.3.62 entry; doc/ssot.md gets the 1.3.62 audit history table row and incremental update note; doc/upgrading.md gets the "From 1.3.61 to 1.3.62+" section.

### Tests
- PHP parser fallback (`php -l`): clean across all 20 PHP files.
- JS syntax check (`node --check assets/js/admin.js`): clean.
- Manual call-site audit confirms no remaining `r.data.message` or `r.data.error` reaches `.html()`-using code paths without `esc()` interposition.

### Compatibility
- No public API changes. No breaking changes for site operators or external integrators.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.61-1` to `1.3.62-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.62`. Rebuild as `wp-perf-shield-1.3.62.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.61

- **Inline "Delete this path" button on Overview findings.** Closes a real UX gap: previously every finding on the Overview tab rendered with a "Needs action" badge plus a manual remediation instruction, but no in-UI delete affordance. Operators with multiple findings to clear had to either run them through Forensics tab actions one by one (where action buttons already existed) or SSH into the server. This release renders an inline "Delete this path" button on Overview finding cards when the scanner has confirmed the path is contained within the post-WPSEC-001 safe boundary (`WP_PLUGIN_DIR`).

### User-facing
- **DOC-20260507-012** Overview finding cards now render a small destructive-style button labelled "Delete this path" for findings whose `delete_path` field is populated. The button calls the existing `wps_delete_file` AJAX handler with a confirmation prompt; on success the row greys out and the button is replaced with a green "deleted" message. On failure the operator gets an alert with the error message and the button re-enables.
- The button only renders when the scanner has explicitly attested that the path is inside `WP_PLUGIN_DIR`. Findings outside that boundary (ABSPATH-root files, `.user.ini` directives, mu-plugins backdoors, surgical-edit cases like the `wordfence-waf.php` auto_prepend hijack) continue to show instruction-only text because their remediation requires either surgical editing of a legitimate file or admin-level filesystem access that exceeds the AJAX-handler's safety guarantees. The button is suppressed for findings already remediated (`remediated` flag set) or where auto-delete was explicitly skipped (`auto_delete_skipped` flag set), since the operator has already been given the choice once and chose review.

### Code changes
- **HARDEN-20260507-013** `WPS_Scanner::check_dropper_cache()` now populates `delete_path` on `Hidden development directory under wp-content/` and `Hidden directory under wp-content/ (no benign explanation)` findings when the candidate directory is contained within `WP_PLUGIN_DIR`. The boundary check uses `realpath` resolution on both sides plus `WPS_Utils::path_is_inside()` to defeat symlink traversal. Outside the boundary, `delete_path` is set to empty string so the UI does not render a button.
- `includes/class-admin-overview.php` renders the button conditionally inside `<div class="wps-finding-action">`. Confirmation prompt includes the path being deleted so the operator can verify before confirming. The `onclick` handler calls the existing `wpsForensicAct(this, 'wps_delete_file', { path: ... }, confirmMsg)` JS helper.
- `assets/js/admin.js` updates `wpsForensicAct`'s row-selector from `tr,div.wps-finding` to `tr,div.wps-finding,div.wps-finding-card` so the success-state animation (grey out + replace button with success message) works on the new Overview cards.
- `assets/css/admin.css` adds `.wps-finding-delete-btn` (small destructive-style button with red border, hover state inverts to filled red) and `.wps-inline-success` (green text shown after successful deletion).

### What this release does NOT change
- No new AJAX handlers. The `wps_delete_file` handler from prior releases is reused as-is, with all its existing safety constraints: `manage_options` capability check, nonce verification via `WPS_Utils::guard_request`, `path_is_inside( ABSPATH )` containment check, the WPSEC-003 (1.3.57) protected-basename list for ABSPATH-root configuration files (`.htaccess`, `.user.ini`, `wp-cron.php`, etc.).
- No new capabilities. The button is purely a UI affordance over capability that already existed and was reachable through the Forensics tab. An operator with `manage_options` could already delete these paths via the Forensics tab's row-level action buttons; this release just makes that capability visible from the Overview tab where the findings are surfaced.
- No widening of `wps_delete_file`'s path acceptance. The 1.3.57 audit's residual-risk acceptance for the handler (ABSPATH-wide trust under `manage_options`) stands. The new `delete_path` field on findings is a UI gating mechanism, not a security boundary  if an attacker bypasses both nonce and capability checks, the AJAX handler itself remains the authoritative defence.

### Tests
- Behavioural test (`/tmp/v61_test.php`): 8/8 PASS.
  - `.vscode/` inside `wp-content/plugins/<plugin>/` is found, severity is `medium`, `delete_path` is populated.
  - `.helpers/` inside `wp-content/plugins/<plugin>/` is found, severity is `high`, `delete_path` is populated.
  - `.idea/` inside `wp-content/themes/` (outside `WP_PLUGIN_DIR`) is still found, but `delete_path` is empty so no button would render.

### Compatibility
- No public API changes. No breaking changes for site operators or external integrators. Existing finding consumers that read `delete_path` will see additional values populated on these two finding types; consumers that check for the field's presence and skip empty values continue to work unchanged.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.60-1` to `1.3.61-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.61`. Rebuild as `wp-perf-shield-1.3.61.zip` with `wp-perf-shield/` as the package root before publishing.

### Deferred (not in this release)
- Surgical-edit button for `wordfence-waf.php auto_prepend hijack: non-canonical include` and similar findings that require removing one specific line from a legitimate file rather than deleting the whole file. This requires a backup-on-edit safety mechanism, careful pattern matching to avoid removing legitimate include directives, and a rollback path if the edited file becomes invalid. Targeted for a subsequent release pending operator review of the 1.3.61 inline-delete behaviour.

## 1.3.60

- **Documentation-only redaction release.** Public-disclosure audit against the WordPress security audit YAML protocol's `public-disclosure-guidance` section identified that all five victim-site domains were named explicitly across the four public-facing documentation files (`readme.txt`, `doc/changelog.md`, `doc/upgrading.md`, `doc/ssot.md`). The protocol's guidance is to avoid customer data and private file paths from production in public docs. The named domains are the operator's own sites, which are not customer data in the strictest sense, but the explicit listing publishes a connection between the operator's network and a malware compromise that anyone reading the public docs would be able to trace back. This release closes that disclosure gap.

### Documentation
- **DOC-20260507-011** Replaced explicit victim-site domain names with positional references (the first/second/third/fourth/fifth victim site in the captured corpus) across `readme.txt`, `doc/changelog.md`, `doc/upgrading.md`, and `doc/ssot.md`. Replaced the thematic descriptor identifying the network's content category with a generic "sites within a coherent thematic cluster" formulation; the forensic insight (theme-targeted campaign rather than opportunistic infection) is preserved without identifying the specific theme. Per-build attributions in older changelog entries (parenthetical "(<domain> build)" forms) become "(the <Nth> victim site's build)". Per-build timing context that previously combined domain names with version markers is rewritten to combine positional references with version markers, preserving the forensic timeline without the identifying data. The aggregate effect is that public-facing documentation now describes the captured corpus by structure (first victim, second victim, etc.) rather than by identity.

### What stays unchanged
- `includes/class-wps-indicators.php`: `WPS_Indicators::known_rat_victim_sites()` retains the five explicit domain entries. The XOR-seed extraction logic in `WPS_Scanner::extract_rat_victim_site()` performs domain-string matching against this list at runtime; the function cannot work without the literal domain values present. The 1.3.56 explanatory comment block adjacent to the accessor (which documents that the list is identification-only and never used as a blocklist) stays in place.
- `includes/class-blocker.php`: inline source comments adjacent to per-victim hash entries in `get_blocked_hashes()` retain domain attributions. These are technical annotations operators see when reading the code, not public-facing prose. Removing them would make the hash entries opaque to anyone investigating a future capture against the existing catalogue.
- All detection-capability code: `check_well_known_php()`, `check_clickfix_shape_heuristic()`, the family content-signature scanner, the `.well-known/` walker, the upload-guard hash blocklist all behave identically. No code paths changed.

### Compatibility
- No public API changes. No behavioural changes. No breaking changes for site operators or external integrators of the plugin's classes.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.59-1` to `1.3.60-1`. The bump on a docs-only release is intentional: the protocol's `versioning-and-documentation.trigger-conditions.documentation-update-required-when` clause is satisfied (the docs change is non-trivial and tracks a security-relevant decision), and bumping the indicator version makes the redaction visible to operators who inspect the plugin's reported state.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.60`. Rebuild as `wp-perf-shield-1.3.60.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.59

- **Fifth-victim cert-check.php sibling hash captured.** A new wp-locale-handler RAT family build was captured at `.well-known/pki-validation/cert-check.php` with XOR seed for the fifth victim site. The catalogue previously contained the parent-location build (`wp-content/languages/wp-locale-handler.php`, MD5 `70358bb32a2cf6fcbfc9edfe2848a579`, added in an earlier release) for this same victim site, but the sibling-location build at `.well-known/pki-validation/` was missing. The five known victim sites now all have both parent-location and sibling-location builds catalogued.
- **The capture itself was already caught by existing detection layers**, independent of the hash. The 1.3.45+ `WPS_Scanner::check_well_known_php()` flags any PHP file in `.well-known/` at critical severity with auto_delete enabled (the IETF `.well-known/` is meant for static text only; PHP execution there is illegitimate by definition). The family content-signature scanner additionally fires on the HMAC seed `a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e` and the base64 harvester markers `Ci8vIFdvcmRQcmVzcyBTZXNzaW9uIENhY2hlIEhhbmRsZXIK` / `Ci8vIFdvcmRQcmVzcyBzZXNzaW9uIGFuYWx5dGljcw`. The hash addition is defence-in-depth (faster upload-guard rejection, faster forensic identification), not the primary catch.

### Security
- **SEC-20260507-010** Added MD5 `c053446a3916beb41df3e3428c085a3c` and SHA-256 `0c1d67c3d5036b5ced4f761d05326b8a3e98946ca89fb5fc0bd276c0b095cff0` to `WPS_Blocker::get_blocked_hashes()` for the fifth victim site's sibling-location cert-check.php build.

### Compatibility
- No public API changes. No breaking changes for site operators or for external integrators of the plugin's classes.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.58-1` to `1.3.59-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.59`. Rebuild as `wp-perf-shield-1.3.59.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.58

- **New ClickFix variant captured plus generic shape-based detection added.** A new ClickFix render-hijacker variant `auto-content-profiler-0b8d.php` was captured on 2026-05-07 with a previously-unseen evasion technique: instead of concatenating string literals (which the 1.3.39+ content-signature scanner caught at the literal-substring level), the new variant builds the strings in variables. The hook name `wp_footer` no longer appears in the file as a literal; it is assembled at runtime from fragments. The dismiss-cookie names `_cf_verified` and `_wp_perf_ok` are similarly fragmented. The content-signature scanner is partially blind to this evasion. This release adds the specific catch for the new variant AND a generic shape-based detector that catches future ClickFix variants without requiring per-prefix IoC entries.

### Security
- **SEC-20260507-008** Added `auto-content-profiler` slug to `get_blocked_slugs()`. Folder/file suffix patterns added to `get_blocked_path_patterns()`. MD5 `c87d8c472f827704a2ef6beb997729ff` and SHA-256 `d7ec2991f822bc9d8811526f83e84dad6002d8ca8471fd3a763f40252e59ea32` added to `get_blocked_hashes()`. DB option key `wp_e07ded4e61_cfg` added to `WPS_Indicators::malware_option_keys()`. Class name literal `DB_Worker_1c49` added to `WPS_Scanner::SIGNATURES_PERF`.
- **HARDEN-20260507-009** New scanner check `WPS_Scanner::check_clickfix_shape_heuristic()` performs structural fake-plugin-folder detection that does not depend on per-prefix string matching. The check walks `wp-content/plugins/` non-recursively and scores each folder against six structural traits: (1) single-file plugin shape (no readme, no /assets/, no LICENSE  real plugins almost always ship more than one file); (2) main file size 5-15 KB (the band all ten captured ClickFix variants fall in); (3) Plugin URI pointing to `developer.wordpress.org/plugins/` (real plugins point to their own homepage; the developer-docs root URI is a copy-paste tell); (4) single class with name pattern `[A-Z][A-Za-z_]+_[a-f0-9]{4,8}` (family naming convention); (5) literal `wp_<10hex>_cfg` option key (cannot be fragmented because `update_option()` and `get_option()` require the literal); (6) `add_action` registration with numeric priority >= 50000 (family uses very late priorities to defeat theme/plugin output filters). Score 5-6 -> high severity, auto_delete enabled. Score 4 -> high severity, review-only. Score 3 -> medium severity, review-only.
- The heuristic skips folders whose slug already matches a per-prefix entry in `get_blocked_slugs()`. The two layers are complementary: the per-prefix layer catches known builds quickly with no scoring overhead; the heuristic layer catches new prefixes the blocklist has not seen yet.
- Bonus trait: known shell-company author names (Page Software, Site Group, Dev Group, Cache Team, Pro Team, Performance Team, Optimizer Team, Web Optimizer, WP Studio) are recorded as a non-scoring annotation when matched. The operator can rotate these freely so they are not reliable as a primary trait.
- Allowlist (`clickfix_heuristic_allowlist()`) prevents the heuristic from flagging the plugin itself or known-good single-file plugins like akismet.
- New event label `clickfix_shape_match` added to `WPS_Admin`'s map.

### Tests
- Per-prefix layer assertions (6/6 PASS): slug present in `get_blocked_slugs()`; suffix pattern present in `get_blocked_path_patterns()`; MD5 and SHA-256 in `get_blocked_hashes()`; option key in `malware_option_keys()`; class name in `SIGNATURES_PERF`.
- Heuristic layer assertions (6/6 PASS): hypothetical future variant `data-flow-analyzer-9999` (with prefix not in slug list) IS flagged by the heuristic at high severity with auto_delete=true; legitimate plugin NOT flagged; WP Perf Shield itself NOT flagged; already-blocklisted prefix `page-seo-toolkit-a937` SKIPPED (delegated to per-prefix layer).
- 12/12 total assertions PASS across both layers.

### Strategic note
- This is the inflection point on the per-prefix-vs-shape detection question. From 1.3.34 through 1.3.55 the catalogue grew prefix-by-prefix as new variants were captured (fourteen prefixes by 1.3.55). The auto-content-profiler-0b8d capture demonstrated that the operator can rotate prefixes faster than the IoC catalogue can grow. The shape heuristic raises the operator's cost: rotating prefixes no longer evades detection because the heuristic does not depend on the prefix at all. The operator must rotate at least one of the six structural traits (file shape, file size, Plugin URI, class naming, option key shape, hook priority), each of which is more expensive to change because each is load-bearing for the malware's bootstrap. The plugin slug, the class declaration, and the option key in particular are difficult to fragment because they pass through PHP language constructs that require literals.

### Compatibility
- No public API changes. No breaking changes for site operators or for external integrators of the plugin's classes.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.57-1` to `1.3.58-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.58`. Rebuild as `wp-perf-shield-1.3.58.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.57

- **First formal security audit against the WordPress theme/plugin security audit and remediation YAML protocol.** Six confirmed findings; five fixed in code, one proposed clarification implemented; four false positives verified. Detailed findings catalogue and audit history maintained in `doc/ssot.md`.

### Security
- **SEC-20260507-001 (WPSEC-001)** Fixed privilege-escalation in `WPS_Remediation_Controller::delete_plugin_folder()`. Containment base narrowed from `WP_CONTENT_DIR` to `WP_PLUGIN_DIR`. The handler is named and capability-gated as a plugin-folder operation, but the previous containment authorised deletion of any directory under `wp-content/` (themes, uploads, mu-plugins, languages, cache). Under custom role configurations a `delete_plugins`-only user could trigger deletion of theme directories, upload directories, etc. Theme deletion remains available through the dedicated `delete_theme_file` handler gated on `edit_themes`.
- **SEC-20260507-002 (WPSEC-002)** Fixed sensitive-file-exposure: added `tools/index.php` placeholder and `tools/.htaccess` `Deny from all`. The previous package layout exposed `tools/verify-package.ps1` source code via direct URL request when Apache directory indexing was on, since `.ps1` is not server-side mapped to PHP execution by default.
- **HARDEN-20260507-003 (WPSEC-003)** Extended the protected-basename list in `WPS_Remediation_Controller::delete_file()`. Previously protected: `wp-config.php`, `wp-load.php`, `wp-settings.php`, `wp-blog-header.php`, `index.php`. Now also protected: `.htaccess`, `.user.ini`, `wp-cron.php`, `wp-trackback.php`, `wp-comments-post.php`. Defence-in-depth against an admin session (or a session-stealing XSS bypassing nonce) deleting server-rewrite or PHP per-directory config files via this handler.
- **HARDEN-20260507-004 (WPSEC-004)** Switched all four runtime `wp_remote_get` call sites to `wp_safe_remote_get`: `class-wps-utils.php`, `class-forensics.php`, `class-scanner.php`, `class-hardening.php`. No user-controlled URLs flow into any of these calls today, but `wp_safe_remote_get` blocks loopback, private-IP, and metadata-IP destinations by default and gives defence-in-depth coverage if a future change introduces user-controlled URLs.
- **HARDEN-20260507-005 (WPSEC-005)** Added `$wp_version` format validation in `clean_login` and `clean_cron` before interpolation into remote URLs. The handlers fetch `https://raw.githubusercontent.com/WordPress/WordPress/{$wp_version}/wp-login.php` and `https://core.svn.wordpress.org/tags/{$wp_version}/wp-cron.php`; if `wp-includes/version.php` is ever compromised, `$wp_version` could carry path-traversal payload. The validation `preg_match('/^\d+\.\d+(\.\d+)?$/', $wp_version)` rejects any non-version-shaped value before URL construction.
- **DOC-20260507-006 (WPSEC-006)** Clarified `tools/update-indicators.php` stub status. Added explicit `STATUS: STUB` header and an early-exit guard that refuses to make any network request while the `$feedUrl` placeholder still contains `example.com`. The CLI-only tool was already protected by `php_sapi_name() !== 'cli'` from web execution; the early-exit guard adds defence against accidental misconfigured deployment.

### False positives verified
- Three non-prepared `$wpdb` queries (`class-forensics.php:833`, `class-remediation-controller.php:611`, `class-remediation-controller.php:625`) all use constant SQL with no user-input interpolation.
- 278 admin-page output points: every dynamic value flows through an appropriate escape function. Apparent unescaped echoes resolve to ternary-of-constants, helper-function-internal escaping, or static literals.
- All 26 AJAX handlers verified to call `WPS_Utils::guard_request()` with appropriate capability before any state change.
- Settings sanitisation chain (`sanitize_slug_list` via `sanitize_title()`, `sanitize_hash_list` via strict hex regex) verified end-to-end.

### Documentation
- **DOC-20260507-007** `doc/ssot.md` updated. Replaced previous "no vulnerabilities discovered" assertion with the formal protocol audit history. Going forward, every release maintains an audit-history entry in `doc/ssot.md`.

### Tests
- Behavioural regression test for WPSEC-001 (delete_plugin_folder containment) covering 7 scenarios: legitimate plugin folder allowed, theme folder blocked, uploads year folder blocked, mu-plugins folder blocked, wp-content itself blocked, plugins root itself blocked, WP Perf Shield itself blocked. 7/7 assertions passed.
- PHP parser fallback passes on all 19 PHP files.
- `wp_safe_remote_get` migration verified by grep: zero remaining `wp_remote_get` calls in runtime files.

### Compatibility
- No public API changes. No breaking changes for site operators or for external integrators of the plugin's classes.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.56-1` to `1.3.57-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.57`. Rebuild as `wp-perf-shield-1.3.57.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.56

- **Naming correction.** A site operator reviewing the 1.3.55 changelog flagged that the term "operator target" used in the IoC catalogue was ambiguous and read backwards. The list at `WPS_Indicators::known_rat_operator_targets()` contains domains extracted from XOR seeds inside captured RAT binaries; every entry is a VICTIM site (a domain owned by a site operator whose installation has been compromised by this RAT family), not attacker infrastructure. The label "operator target" could be misread as "domain owned by the operator" when the actual semantics is "site the operator built a binary against." Rename and clarification across every code path, comment, finding annotation, and document.
- Renamed `WPS_Indicators::known_rat_operator_targets()` to `WPS_Indicators::known_rat_victim_sites()`. The old name is retained as a `@deprecated` backward-compatibility alias that calls through to the new method, so any external integrators using the old API continue to work.
- Renamed `WPS_Scanner::extract_rat_operator_target()` to `WPS_Scanner::extract_rat_victim_site()`. Same backward-compat alias pattern.
- Updated the finding annotation key from `[target=<domain>]` to `[victim_site=<domain>]` in `check_well_known_php()`. The action text now reads "polymorphic variant customised against the victim site `<domain>`" rather than the previous "polymorphic variant targeting `<domain>`".
- Added a prominent comment block at `WPS_Indicators::known_rat_victim_sites()` with two explicit clarifications: (1) every entry is a VICTIM site, never attacker infrastructure; (2) the list is for IDENTIFICATION ONLY and is never used by the plugin for blocking, blacklisting, filtering, deny-list enforcement, or any other restrictive purpose. Confirmed via codebase audit: zero call sites use this list as a blocklist input.
- Updated all comments in `class-blocker.php` and `class-scanner.php` that referred to "operator-target" terminology to use "victim-site" terminology instead. Two comment fragments referenced "operator gets a custom binary"  rewritten to "each victim site receives a custom-built binary keyed against its own domain."
- No data loss: all five victim sites remain in the list (the five victim sites in the captured corpus). The data was always correct; only the terminology was misleading.
- No detection-logic change: the rename is purely semantic. The XOR-seed extractor still works the same way; the finding fields still carry the same domain string; the captured binaries are still correctly identified.
- Verified via behavioural sanity check: both `known_rat_victim_sites()` and `known_rat_operator_targets()` (the deprecated alias) return identical 5-element arrays. The codebase audit found zero remaining "operator-target" usages outside the deprecation-notice docblocks themselves.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.55-1` to `1.3.56-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.56`. Rebuild as `wp-perf-shield-1.3.56.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.55

- Tiny intelligence-only release. A re-upload of `wp-locale-handler.php` (MD5 `70358bb32a2cf6fcbfc9edfe2848a579`) was already present in the upload-guard hash list and triggered correctly through every existing detection layer. The XOR seed extracted from the binary was the fifth victim site, which was not yet present in the `known_rat_operator_targets()` accessor.
- Added an entry for the fifth victim site to `WPS_Indicators::known_rat_operator_targets()` annotated as `CONFIRMED ACTIVE` (a captured RAT instance with that XOR seed is at hand). The list now covers five operator targets: the five victim sites in the captured corpus). Three of the five entries are confirmed-active because we have captured binaries; the other two are inferred from the operator-target lookup table inside the captured cert-check.php sample set.
- The accessor is consumed by `WPS_Scanner::extract_rat_operator_target()` (added in 1.3.45). Any future scan that finds a wp-locale-handler / cert-check sample whose XOR seed matches one of these five domains will be auto-annotated with the operator-target identification, which helps incident response triangulate which campaign the binary belongs to.
- No new code paths, no new checks, no new findings types. This is a single-line IoC catalogue update with documentation. Detection of the captured sample was already correct in 1.3.49+; this release only updates the campaign intelligence catalogue.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.54-1` to `1.3.55-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.55`. Rebuild as `wp-perf-shield-1.3.55.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.54

- New scanner check `check_drop_ins()` audits WordPress drop-ins at canonical wp-content/ paths against a known-safe-publisher signature list. WordPress drop-ins (`object-cache.php`, `advanced-cache.php`, `db.php`, `db-error.php`, `maintenance.php`, `fatal-error-handler.php`, `install.php`, `php-error.php`, `sunrise.php`) load on every request BEFORE plugins initialise. They run earlier than any security plugin can intercept, which makes them the highest-privilege location a backdoor can live on a WordPress install. The 1.3.46 generic-webshell pattern scanner walks wp-content/ and would catch obvious shell shapes, but it has no special awareness that drop-ins exist as a category, and would not flag a drop-in that uses original code (no `eval`, no `base64_decode`, no `preg_replace /e`) to install a backdoor  for example, a drop-in that simply registers `add_filter('pre_user_query', ...)` to hide users.
- `WPS_Scanner::DROP_IN_CANONICAL_NAMES` is the list of nine canonical drop-in basenames the audit checks. `WPS_Scanner::known_drop_in_publishers()` returns a map of substring -> publisher label. The substrings are conservative: short enough to survive minor publisher version changes (e.g., the literal `Object cache drop-in from Performance Lab plugin` from Performance Lab, the literal `GENERATED AUTOMATICALLY` from Plesk WP Toolkit) but long enough that legitimate-non-publisher code is unlikely to contain them. Allowlist coverage as of 1.3.54: Performance Lab, Plesk WP Toolkit, W3 Total Cache, WP Super Cache, LiteSpeed Cache, Redis Object Cache, WP-Optimize, Memcached Object Cache, Batcache, Hummingbird Performance, SG Optimizer, Cloudflare APO, Pantheon, plus WordPress core's default fatal-error-handler.
- A drop-in that does not match any publisher signature produces a finding at `medium` severity. Action text frames both possibilities (custom drop-in deliberately installed by the operator vs. planted backdoor) and recommends operator inspection before deletion. No `auto_delete`: the false-positive risk on a less-common publisher justifies operator review, and removing a legitimate cache drop-in reverts performance optimisations.
- The 1.3.54 batch surfacing this gap was a benign upload (Performance Lab `object-cache.php` and Plesk WP Toolkit `maintenance.php`)  no actual malware in the captured drop-ins. The check is defence in depth: it closes a real attack-surface gap that the existing detection layers do not specifically cover, ahead of any captured incident in this exact location.
- New event label `unknown_drop_in` added to `WPS_Admin`'s map.
- Wired into `WPS_Scanner::run()` between `check_hidden_admin_users()` and `check_malicious_db_options()`.
- Verified via behavioural test using MENJ's actual drop-in samples (Performance Lab object-cache.php, Plesk-generated maintenance.php) plus a synthesised malicious drop-in that uses original code (a hidden-user filter installer disguised as "Custom_Cache_Layer") plus a synthesised legitimate Redis drop-in. 8/8 assertions passed: all three legitimate drop-ins correctly allowlisted, the synthesised malicious drop-in correctly flagged at medium severity with no auto_delete, and a clean site (no drop-ins at all) correctly produces zero findings.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.53-1` to `1.3.54-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.54`. Rebuild as `wp-perf-shield-1.3.54.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.53

- Captured the filter installer that explains the 1.3.52 hidden-admin-user finding. After 1.3.52 surfaced the count-mismatch detection, the operator searched their site for the source of the user-hiding filters and found a plugin at `wp-content/plugins/wp-security-helper/wp-security-helper.php` (3789 bytes, MD5 `50c02424e0e723c019b4d2bf849f2a9b`, SHA-256 `0a26e477951896659dbc5b0b18929995303a9ab4e071288b40691e0b366b96a1`) disguised as "WP Security Helper" by "WordPress Security Team"  same fake author as wp-security-cache.php, confirming same operator chain. The file uses hex/octal escape sequences in WordPress filter names plus `goto`-flow obfuscation to evade static analysis. Decoded, it installs five filters/actions that hide every user except the currently-logged-in admin from the dashboard, plus one filter that hides the plugin itself from the Plugins page unless `?sp` is set.
- The five user-hiding filters: `pre_get_users` action sets `include => [current_user_id]` on `users.php`; `users_list_table_query_args` filter same effect via list-table args; `wp_count_users` filter forces total to 1; `get_users` filter at priority 999 post-filters the result array to keep only the current user; `all_plugins` filter hides the plugin itself.
- Added `wp-security-helper` to `WPS_Blocker::get_blocked_slugs()`. The existing slug-blocking machinery (added pre-1.3.0 for the wp-perf-analytics ClickFix family) auto-deactivates and auto-removes any plugin matching this slug. No new code path needed.
- Added MD5 `50c02424e0e723c019b4d2bf849f2a9b` and SHA-256 `0a26e477951896659dbc5b0b18929995303a9ab4e071288b40691e0b366b96a1` to `WPS_Blocker::get_blocked_hashes()`. Defence in depth: the slug match handles directory-level removal; the hash match handles single-file copies of the malware found anywhere on disk.
- Added `wp-security-helper.php` to `WPS_Indicators::secondary_backdoor_filenames()`. The existing 1.3.43 dropper-cache walker, the 1.3.50 toolkit-at-root finding, and the 1.3.50 root-PHP-with-signature finding all now treat this basename as a confirmed-malicious filename for auto-delete purposes.
- Added six new content signatures to `WPS_Scanner::SIGNATURES_BACKDOOR`. Two plain-text strings catch unobfuscated builds and the docblock: `WP_Security_Helper` (class name) and `WP Security Helper` (plugin Name string). Four byte-exact escape-sequence patterns catch the obfuscated filter names: encoded `WP_Secur` as a class-name anchor, plus full encoded `pre_get_users`, `wp_count_users`, and `users_list_table_query_args`. The escape-sequence signatures are byte-exact extracts from the captured sample. A polymorphic variant swapping octal/hex encoding for individual characters (e.g. `\151` vs `\x69` for `i`) would defeat the full-name patterns; the `WP_Secur` anchor uses only the leading characters that are encoded the same way across both encoding styles in this family.
- Initial implementation iteration found a signature-encoding mismatch: my first attempt used `\151` (octal `i`) where the captured sample uses `\x69` (hex `i`). Test caught this  only 2/4 expected signatures fired. Fixed by re-extracting the exact bytes from the captured sample. Final test: 6 signature hits on the actual file, 0 hits on a benign plugin sample. The lesson goes to the upgrading.md narrative below: when adding obfuscated-string signatures, extract the exact bytes from the captured sample rather than reasoning about what the encoded form should be.
- Verified via behavioural test using the actual captured sample as fixture. 6/6 assertions passed: hash present in upload-guard, slug present in blocked-slugs list, filename present in secondary-backdoor list, content signatures fire (>= 4 hits, actual = 6), and benign plugin produces 0 hits.
- The 1.3.52 hidden-admin-user check (direct `$wpdb` walk bypassing `get_users()` filters) catches the SYMPTOM of this family regardless of which specific installer is in use; the 1.3.53 hash, slug, and signature additions catch this specific build at file-existence time. Both detection paths are complementary.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.52-1` to `1.3.53-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.53`. Rebuild as `wp-perf-shield-1.3.53.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.52

- **Hidden admin user detection landed.** A coverage gap surfaced when reviewing a live deployment: the wp-security-cache.php malware family creates an administrator user via `wp_create_user()` (a normal database row), but the operator chain frequently pairs it with a separate filter installer that hides the user ID from `pre_user_query` and `users_list_query_args`. The result: the user can log in and act as administrator, but the WP dashboard `Users -> All Users` page does not show them, and `WPS_Forensics::trace_admin_accounts()` (which uses `get_users()`) also did not show them. Both surfaces were silently missing the persistence layer.
- New scanner check `WPS_Scanner::check_hidden_admin_users()`. Queries `wp_users` joined with `wp_usermeta` directly via `$wpdb->get_results()`, bypassing every filter on `pre_user_query`, `users_list_query`, `users_list_query_args`, and related hooks. The query selects every user whose capabilities meta value contains `"administrator"` (catches both singleton-role and multi-role rows). The result is the ground-truth list of administrators in the database, regardless of any filter hiding them from the WP API.
- Three finding shapes:
   - **Count mismatch finding**: critical severity, fires when the direct-DB count of admin users exceeds the count returned by `get_users(['role' => 'administrator', 'fields' => 'ID'])`. The discrepancy is the number of admins hidden by an active filter. The action text identifies which user IDs are hidden and recommends searching active plugins, theme `functions.php`, and mu-plugins for `pre_user_query` / `users_list_query_args` filter installers.
   - **Known malware-created username finding**: critical severity, fires for any user whose `user_login` matches an entry in `WPS_Indicators::hardcoded_admin_usernames()` (currently `adminbackup561801` and `a7f3e9b2c4d1e5f6`). The finding annotates whether the user is visible or hidden from the API. Hidden cases produce a `[HIDDEN]` flag in the subject for operator triage.
   - **Malware email pattern finding**: critical severity, fires for any user whose email matches the deterministic format `scan-<32-hex>@<host>` produced by the wp-security-cache.php credential-rotation logic. This is the IoC deferred from 1.3.51  it catches the case where the operator rotates the username but keeps the email format, which is forensic evidence the malware ran on this site.
- One finding per user, not multiple. When both username and email patterns match the same user, the username finding takes precedence (more specific) and the email check is skipped via `continue`. Adding redundant findings on the same user would only produce noise.
- No `auto_delete` on any user finding. The operator MUST review user records before deletion. wp-security-cache.php's "rotation" pattern recreates the user even after deletion if the file is still active, so the correct sequence is (1) confirm the file is gone, (2) verify the finding via direct DB inspection, (3) `wp user delete` via WP-CLI or the dashboard once the persistence chain is broken.
- Added three event labels to `WPS_Admin`'s map: `hidden_admin_user`, `malware_username_in_db`, `malware_email_pattern_in_db`.
- Wired the new check into `WPS_Scanner::run()` between `check_maintenance_mode()` and `check_malicious_db_options()`.
- Verified via behavioural test covering four scenarios. Scenario 1: 3 admins in DB with 1 hidden by filter, where the hidden user is the malware-created `a7f3e9b2c4d1e5f6`  produces 2 findings (count-mismatch, malware-username) with `[HIDDEN]` flag. Scenario 2: clean site with 1 legitimate admin  0 findings. Scenario 3: malware admin visible (no hiding filter)  produces 1 finding (malware-username) without `[HIDDEN]` flag, count-mismatch correctly does not fire. Scenario 4: rotated username preserving the malware email pattern  produces 1 finding (email-pattern). 13/13 assertions across the two test runs passed.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.51-1` to `1.3.52-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.52`. Rebuild as `wp-perf-shield-1.3.52.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.51

- Two new checks landed for ABSPATH-root anomalies. Together they close two coverage gaps that surfaced when reviewing live-site fixtures: hash-suffixed readme.html backups (Plesk-style or attacker-preserved decoys) and orphan PHP files at WordPress root that are not in the canonical core file set (one-shot operator cleanup tools, hosting-provider diagnostics, planted shells with custom names).
- **`check_core_extra_files()` extended to walk ABSPATH root.** The 1.3.48 walker covered `wp-admin/` and `wp-includes/`. 1.3.51 adds a non-recursive walk of ABSPATH root that compares each `.php` file against (a) a hard-coded canonical-WP-root file set (the 14 wp-*.php files plus index.php and xmlrpc.php) and (b) a known-safe-extras allowlist (currently `wp-config.php` and `wordfence-waf.php`). PHP files that match neither produce a finding. Severity is `medium` rather than `high` because the false-positive rate at root is genuinely higher  hosting providers like Plesk drop diagnostic PHP files at root, operators write one-shot cleanup tools (the `wp-clean-perf.php` pattern), and dev tools like `adminer.php` or `phpinfo.php` have legitimate use. Action text accommodates this with a both-sides framing: common benign causes listed alongside common malicious causes, with operator inspection as the recommended action. No `auto_delete`  the operator decides.
- The hard-coded canonical root file list is `WPS_Scanner::canonical_root_php_files()` (16 entries). The known-safe-extras allowlist is `WPS_Scanner::known_safe_root_php_extras()` (2 entries). Both are intentionally conservative; adding to either list should require a clear justification.
- **New `check_renamed_readme()` method.** Scans ABSPATH root non-recursively for files matching the regex `readme_[a-f0-9]{32}\.html` (case-insensitive). WordPress core ships exactly one readme  `readme.html` with no suffix. The 32-hex pattern matches Plesk WP Toolkit's backup-naming convention and also matches the attacker pattern of preserving the legitimate readme under a hash-named copy while replacing the original with a redirect or fingerprint-leak page. Both scenarios warrant a finding. Severity `medium`, no `auto_delete`  the file might be a Plesk backup the operator wants to keep until they confirm the operation completed.
- Both new checks wired into `WPS_Scanner::run()` between `check_core_extra_files()` and `check_maintenance_mode()`.
- Verified via behavioural test using the actual captured uploads (`readme_d1ec539626c4cb5f25716f6faa7b182a.html` from a live deploy, `wp-clean-perf.php` from the same site). 13/13 assertions passed: renamed-readme detection fires correctly with medium severity and no auto_delete; canonical `readme.html` and short-suffix variants do not fire; orphan-root-PHP detection catches both `wp-clean-perf.php` and `phpinfo.php`; `wp-config.php`, `wordfence-waf.php`, `index.php`, and `wp-blog-header.php` are correctly allowlisted; all root findings are severity `medium` with no `auto_delete`.
- The `wp-default.php` MD5 `8a92828554a087c46cc21c87fd1b15d4` and SHA-256 `673806e0aadc67be107217cc0e3dcf12486022fe39150ee09494236d317ee02d` were already in the upload-guard list as of 1.3.36, so no IoC additions in this release. The signature-content scan and existing hash blocklist have been catching this variant correctly.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.50-1` to `1.3.51-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.51`. Rebuild as `wp-perf-shield-1.3.51.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.50

- Live-deploy bug-fix release. A real-site scan output (sent in for review) showed three confirmed-malicious files at ABSPATH root stuck on "Needs action" rather than being auto-deleted, plus four hidden-directory false-positives inside Composer-vendored packages and the wp-file-manager plugin's own runtime trash directory. Both classes of issue are fixed in this release.
- **`check_auto_prepend_hijack` toolkit-at-root finding now auto-deletes.** Section 3a of `WPS_Scanner::check_auto_prepend_hijack()` flags any file at ABSPATH root whose basename is in `WPS_Indicators::secondary_backdoor_filenames()` (currently `.wp-config-cache.php`, `wp-security-cache.php`, `wp-phpunit.php`, `wp-default.php`, `cert-check.php`, `tji-site-js.php`). This combination  canonical-malicious basename plus canonical-malicious location  is unambiguous and has no benign explanation. The finding shape now carries `auto_delete: true` and `delete_path`. Action text updated from "Delete this file..." to "Auto-deleted because the basename is on the secondary-backdoor list and ABSPATH-root location has no benign explanation. After deletion: confirm auto_prepend_file directives and the includes inside wordfence-waf.php do not reference it; run Hardening > Regenerate auth salts."
- **`check_root_file_signatures` finding now conditionally auto-deletes.** When the file producing a SIGNATURES_BACKDOOR content match is also in `WPS_Indicators::secondary_backdoor_filenames()`, the finding carries `auto_delete: true`. This handles the case where a file like `wp-default.php` matches both the basename list (toolkit-at-root finding) and the content-signature list (`UM_AUTO_ROOT_MODE` / `UMSESSID` markers)  both findings now auto-delete consistently. When the signature match is in a file whose basename is NOT in the known-bad list (e.g. signature found in a tampered `wp-blog-header.php`), the finding remains `Needs action` so the operator can review before the scanner removes a possibly-tampered core file.
- **Hidden-directory hunt false-positive suppression.** Two cases:
   1. **Composer-vendored CI configuration directories**: `.github/`, `.circleci/`, `.gitlab/`, `.gitea/`, `.docker/`, `.husky/`, `.ddev/` directories shipped inside any plugin's `vendor/` tree are now skipped. These are routine library distribution artefacts that thousands of plugins include via Composer; flagging them produces nothing but noise. The check applies only when the path includes `/vendor/`  outside `vendor/` paths, the same basenames remain flagged because their presence at a plugin's root is a deployment-discipline issue.
   2. **wp-file-manager runtime trash directory**: `.trash/` directories under any path containing `/wp-file-manager/` are skipped because the plugin uses this directory as part of its own functional design (user-trash for the file manager UI). The wp-file-manager plugin itself is separately flagged as high-risk via `check_high_risk_plugins` (CVE-2020-25213 unauthenticated RCE), so finding `.trash` inside it is double-counted noise.
- Verified via behavioural test simulating the exact reported scan scenario. Synthetic ABSPATH containing all three secondary-backdoor files plus a wp-file-manager plugin tree with `.trash/`, plus three Composer-vendored CI directories, plus two non-vendor hidden directories. Result: all three toolkit-at-root findings carry `auto_delete: true` and `delete_path`; both signature-content findings on those same files also carry `auto_delete`; all four false-positive hidden directories are correctly skipped; the two legitimate hidden-directory findings outside vendor (`.vscode` medium, `.suspicious` high) still fire correctly. All 11 assertions passed.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.49-1` to `1.3.50-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.50`. Rebuild as `wp-perf-shield-1.3.50.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.49

- New malware family captured. A live-site dump surfaced two co-resident infections at canonical hiding spots: `wp-content/languages/wp-locale-handler.php` (RAT v1.7 polymorphic variant, XOR seed for the second victim site) and `wp-content/mu-plugins/tji-site-js.php` (NEW family  TDS drive-by injector disguised as "Theme JS Injector"). Two separate operator chains active on the same victim site.
- Added two new sample hashes to `WPS_Blocker::get_blocked_hashes()`. (1) MD5 `a4f6a499ea1c34ae15dcf108e0fa197b` / SHA-256 `bae6d2e4f396b9610c11a839a9ffc9740033c7d7a482d5310af63cc45351979b`  the wp-locale-handler.php new variant. The XOR seed extracted from this binary is the seed for the second victim site, which is also one of the operator targets identified from the 1.3.45 cert-check.php sample set. The same operator-target binary appearing on a different victim site confirms the operator reuses one binary across multiple victim sites; the XOR seed identifies which victim's data the build was customised against, not where the build was deployed. (2) MD5 `47ff560f2c1096757cbfad5291ccc959` / SHA-256 `1d2699149bbb1f523cd914cbe2025de77e00dd58dedd11eaded9a04b01246d50`  the `tji-site-js.php` TDS injector.
- Added the TDS injector family to `WPS_Scanner::SIGNATURES_BACKDOOR`. Seven new entries: `tji_mu_script_js` (PHP global variable name unique to this family), `__performance_optimizer_v6` (JavaScript run-once flag; structural marker), `Theme JS Injector` (fake plugin description), `aHR0cHM6Ly9udGRuZXd0ZHMuc2hvcA==` (base64 of `https://ntdnewtds.shop`), `aHR0cHM6Ly9kbnNuZXd0ZHMuc2hvcA==` (base64 of `https://dnsnewtds.shop`), and the plain-text forms `ntdnewtds.shop` and `dnsnewtds.shop` for builds that omit the base64 wrapper. The structural markers (`tji_mu_script_js` and `Theme JS Injector`) catch the family on file content alone regardless of which TDS C2 domains a given build uses; future operator-rotated domain lists do not require plugin updates.
- Added `tji-site-js.php` to `WPS_Indicators::secondary_backdoor_filenames()` so the existing walkers (1.3.43 dropper-cache hunt, auto_prepend hijack check, etc.) catch this basename anywhere on disk.
- Added `WPS_Indicators::tds_c2_domains()` returning the two known TDS C2 domains as informational reference. Detection works without consulting this list  the structural signatures handle it on content alone. Useful for blocking egress traffic at the firewall/edge level.
- Updated `WPS_Indicators::known_rat_operator_targets()` comment for the the the second victim site entry: now annotated as `CONFIRMED ACTIVE` because we have captured a real RAT instance with that XOR seed in the wild.
- Verified via behavioural test using the actual captured samples. Hashes correctly land in the upload-guard list. The seven new SIGNATURES_BACKDOOR entries all register. Content match: tji-site-js.php produces 5 signature hits, wp-locale-handler.php produces 8 signature hits, a synthetic benign mu-plugin produces 0 hits. All 9 assertions passed.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.48-1` to `1.3.49-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.49`. Rebuild as `wp-perf-shield-1.3.49.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.48

- Two complementary checks landed for the wp-admin/ and wp-includes/ surfaces. Together they close the two remaining detection gaps in the core-integrity story that 1.3.47 started.
- **Extra-files-in-core check (`check_core_extra_files`).** 1.3.47's `check_core_checksums` catches modified and missing core files by comparing on-disk SHA-1 against the WordPress.org manifest. It does not catch *added* files: a webshell planted at `wp-includes/class-wp-cache.php` or `wp-admin/admin-tools.php` sits in a path the manifest does not know about, so the checksum check has no expected hash to compare against and silently lets the file through. The new walker reads the same cached manifest, walks `wp-admin/` and `wp-includes/`, and flags any PHP file whose relative path is not a manifest key. Severity is `high` rather than `critical` because the operator may have legitimately added a custom PHP file (debugging, hosting integration); the action text recommends inspection before deletion. No `auto_delete` flag.
- **Stale .maintenance file check (`check_maintenance_mode`).** WordPress creates `<ABSPATH>/.maintenance` during core updates and removes it on completion. Every front-end visitor sees "Briefly unavailable for scheduled maintenance" while the file exists. A persisting `.maintenance` file means either a crashed update or an attacker locking out front-end traffic to install a backdoor on the back end. Severity escalates with age: 10-60 minutes -> `medium` (probably a stuck update), 1-24 hours -> `high`, >24 hours -> `critical` (no benign explanation at that age). Below 10 minutes the check returns nothing because legitimate updates routinely take 1-3 minutes and the false-positive rate would be high. No `auto_delete`: the operator may want to verify a real update is in progress before removing the lock file.
- Added scanner constants `CORE_EXTRA_MAX_FILES` (5000), `MAINTENANCE_STALE_THRESHOLD` (600 sec), `MAINTENANCE_HIGH_THRESHOLD` (3600 sec), `MAINTENANCE_CRITICAL_THRESHOLD` (86400 sec).
- Wired both new checks into `WPS_Scanner::run()` between `check_core_checksums()` and `check_malicious_db_options()`.
- Registered the event label `maintenance_stale` in `WPS_Admin`'s map.
- Verified via behavioural test. Test 1: synthetic core directory tree with 5 canonical files (in manifest) plus 2 extra PHP files (not in manifest) plus 1 non-PHP extra file (CSS) produced exactly 2 `high` findings, both with no `auto_delete`; canonical files were correctly skipped, the non-PHP file was correctly ignored. Test 2-7: maintenance check correctly returned zero findings when the file did not exist or was younger than 10 minutes; produced one `medium` finding at 30 minutes; one `high` at 2 hours; one `critical` at 2 days; no auto-delete on any. All 12 assertions passed.
- Regression: scanned MENJ's actual wp-admin/ upload (240 PHP files, WP 6.9.4 canonical) with a completeness-verified synthetic manifest. Zero findings. Confirms no false positives on legitimate WordPress 6.9.4 wp-admin/ content.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.47-1` to `1.3.48-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.48`. Rebuild as `wp-perf-shield-1.3.48.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.47

- Universal WordPress core integrity verification landed via `api.wordpress.org/core/checksums/1.0/`. WordPress.org publishes SHA-1 checksums for every core file per version. The same endpoint backs WP-CLI's `wp core verify-checksums` command. Previous releases verified one core file at a time (`xmlrpc.php` integrity in 1.3.46, `wp-config.php` integrity since 1.3.x); 1.3.47 covers every file under `wp-includes/`, `wp-admin/`, and ABSPATH-root.
- Added `WPS_Scanner::fetch_core_checksums()` plus the constants `CORE_CHECKSUMS_TRANSIENT` (cache key `wps_core_checksums`), `CORE_CHECKSUMS_TTL` (24 hours), `CORE_CHECKSUMS_API` (`https://api.wordpress.org/core/checksums/1.0/`), `CORE_CHECKSUMS_TIMEOUT` (8 seconds), and `CORE_CHECKSUMS_MAX_FINDINGS` (50). The fetcher reads the running WP version from the `$wp_version` global, falls back to parsing `wp-includes/version.php` if the global is not set, validates the version against `^\d+\.\d+(\.\d+)?$`, and bails silently if neither source produces a usable version. The HTTP call uses `wp_remote_get()` with the WP version-aware user-agent string. Strict shape validation on the response: every entry must be a relative-path string mapping to a 40-hex SHA-1 string; anything else is dropped.
- Added `WPS_Scanner::check_core_checksums()`. Reads the cached manifest, walks every entry, and verifies on-disk SHA-1 against the published value. Three finding shapes:
   - **Modified file (sha1 mismatch).** `critical` severity, NO `auto_delete`. Action: restore via `wp core download --force` or via Updates -> Re-install. Core files must be restored, not removed.
   - **Missing file (manifest entry has no on-disk match).** `high` severity, no `auto_delete`. Action: same restoration path. Some manifest entries are language packs that vary per install; only files under `wp-admin/`, `wp-includes/`, or ABSPATH root are checked.
   - **Clean file.** Skipped silently.
- Capped at 50 findings per scan (`CORE_CHECKSUMS_MAX_FINDINGS`) to prevent email-flood on a fully-trojanized install. The `core_checksum_mismatch` event log captures the full mismatch and missing counts even when the finding list is capped.
- Network-failure handling. If `wp_remote_get()` returns `WP_Error`, or the HTTP status is not 200, or the response body cannot be parsed as JSON with the `checksums` key, the check caches an empty manifest for 1 hour and returns zero findings. Subsequent scans within that hour skip the network call. The signature-based and pattern-based checks continue to run independently.
- Added `wps_core_checksums` to the uninstall transient-clear list.
- Added the event label `core_checksum_mismatch` ("WP core file integrity violation (api.wordpress.org sha1 mismatch)") to `WPS_Admin`'s map.
- Verified via behavioural test with a mocked WP HTTP layer. Test 1: synthetic manifest with 4 clean files + 1 modified + 1 missing produced exactly 1 critical and 1 high finding (clean files correctly skipped, no auto_delete on either). Test 2: cache prevented a second network call within the TTL. Test 3: network failure (WP_Error) produced zero findings. Test 4: HTTP 503 produced zero findings. All 7 assertions passed.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.46-1` to `1.3.47-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.47`. Rebuild as `wp-perf-shield-1.3.47.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.46

- Generic webshell pattern detection landed. Family-specific signatures (the wp-perf-analytics ClickFix family, the .sbs cookie-exfil toolkit, the wp-locale-handler RAT) catch known threats. Generic patterns close the gap left when a new variant surfaces faster than the IoC database can be updated. The conversation history of this plugin shows how often that happens.
- Added `WPS_Scanner::check_generic_webshell_patterns()` plus the constants `WEBSHELL_MAX_FILES` (8000), `WEBSHELL_MAX_DEPTH` (8), and `WEBSHELL_MAX_FILE_BYTES` (524288 / 512 KiB). Walks ABSPATH recursively (which covers wp-content/) and matches PHP file contents against five high-confidence regex patterns. Each pattern requires a user-input superglobal inside an eval/assert/include construct, which has no legitimate use in 2026. All five matched patterns produce `critical` findings with `auto_delete: true`:
   1. `assert(\$_POST/_GET/_REQUEST/_COOKIE/_SERVER)` -> always a shell
   2. `eval(\$_POST/_GET/_REQUEST/_COOKIE)` -> always a shell
   3. `eval(<decoder>(\$_POST/_GET/_REQUEST/_COOKIE))` where `<decoder>` is `base64_decode`, `gzinflate`, `str_rot13`, `gzuncompress`, `hex2bin`, or `pack` -> always a shell
   4. `(include|require)(_once)?(\$_POST/_GET/_REQUEST/_COOKIE)` -> always a remote-file-inclusion vulnerability or live shell
   5. `preg_replace('/.../e', ...)` -> always a PHP-pre-7 RCE shell
- Excluded from the walker: `wp-includes/`, `wp-admin/` (pure WP core; their integrity is verified separately), and the plugin's own directory (whose source contains literal regex strings that would otherwise self-match).
- Calibration: static-string variants (e.g. `eval(base64_decode('<long-string>'))`) are deliberately NOT matched here because they have rare-but-real benign uses in commercial-plugin licence-key obfuscation. The signed RAT family signatures already cover the malicious cases of static-string base64+eval that have been observed.
- Added `WPS_Scanner::check_xmlrpc_integrity()`. Verifies that `<ABSPATH>/xmlrpc.php` is the canonical WordPress core file and not a webshell replacement. Two failure modes are flagged. First, missing structural markers (`XMLRPC_REQUEST` define, `class-IXR.php` require, `class-wp-xmlrpc-server.php` require) -> `critical` finding with action text directing the operator to restore via `wp core download --force`. Second, file size larger than 10 KiB while structural markers are present -> `high` finding (canonical xmlrpc.php is ~3.2 KiB; a much larger file with intact markers is consistent with prepended/appended injection). Neither finding carries `auto_delete: true` because xmlrpc.php is a core file: removal would surface as 404s, restoration is the correct action.
- Wired both new checks into `WPS_Scanner::run()` between `check_well_known_php()` and `check_malicious_db_options()`.
- Verified via behavioural test. All five webshell patterns trigger `critical` with `auto_delete: true` when planted in a synthetic plugin directory; legitimate plugin code is correctly ignored; the plugin's self-directory is excluded from matching; `wp-includes/` is excluded from matching. xmlrpc.php integrity check correctly returns zero findings on the real WordPress 6.x core file, fires `critical` on a webshell replacement that lacks canonical markers, and fires `high` on a structurally-correct but oversized file. Regression test against the actual WordPress core dump from MENJ's site returns zero findings  no false positives on legitimate core. All 12 assertions plus the regression test passed.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.45-1` to `1.3.46-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.46`. Rebuild as `wp-perf-shield-1.3.46.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.45

- Polymorphic-variant capture and analysis. Three additional `cert-check.php` samples surfaced in a single live-site dump alongside the 1.3.44 sample. Diff between any pair shows only 8 lines different out of ~78 total, and the only variable bytes are inside two base64-encoded credential-harvester payloads. Every family marker count is identical across all four samples (2 hits each on `a3f8b2c1d4e5f607` and `d3AtY29udGVudC91cGxvYWRz`, 1 hit each on `wp_session_tokens_config` / `session-manager.php` / the HMAC tail, 3 hits on the mode-q gate key). The 1.3.44 signature-based walker already catches the new variants without code changes; this release hardens the signature set and adds forensic enrichment.
- Added three new sample hashes to `WPS_Blocker::get_blocked_hashes()` for fast-path detection: MD5 `3e92c07fa807bcc3a1754c9ba3d1c142` / SHA-256 `95f0ad704e7e163b288373a94520d881b830e9d127ea1f75d72e281d56711c23` (the second victim site's build), MD5 `a667e49c601d874cbacc40e158bb56c1` / SHA-256 `c374f8f34b136a5021cbf0da1e1e760c5b29c430c4c49a6722c863eabfedf583` (the third victim site's build), MD5 `8203c5bb61b21777519bef3af299842d` / SHA-256 `fba50e891764d1b8a6f7e7e2887df1d568fd818ff2e22b8db8372ffd32bfcd53` (the fourth victim site's build).
- Added three new entries to `WPS_Scanner::SIGNATURES_BACKDOOR`. (1) The full 62-character HMAC-and-XOR seed `a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e`, which is constant across the family and the most specific single-string marker available. (2) The base64-encoded form of the mode-l credential-harvester header, `Ci8vIFdvcmRQcmVzcyBTZXNzaW9uIENhY2hlIEhhbmRsZXIK` (decodes to `\n// WordPress Session Cache Handler\n`). (3) The base64-encoded form of the mode-t harvester header, `Ci8vIFdvcmRQcmVzcyBzZXNzaW9uIGFuYWx5dGljcw` (decodes to `\n// WordPress session analytics`). The two encoded-form signatures detect the harvester wherever it has been written, not only inside the RAT's own file. They catch the payload after `mode-l` injects it into `wp-login.php` and after `mode-t` injects it into the active theme's `functions.php`.
- Added `WPS_Scanner::extract_rat_operator_target()`, a private static method that takes the raw bytes of a captured RAT sample, finds every `base64_decode('...')` call inside, decodes each blob, and looks for the literal sequence `'<HMAC_SEED>'.'<DOMAIN>'`. Returns the operator-target domain as a sanity-validated lowercase string or empty if the pattern is not found. Capped at 10 candidate blobs per file.
- Wired the extractor into `WPS_Scanner::check_well_known_php()`. When a critical RAT match is emitted, the operator-target domain is appended to the finding's `subject` field as `[target=<domain>]` and to the action text as a contextual note. The admin email and the Overview-tab finding row both display the target, so the operator immediately knows which site this build was customised to attack.
- Added `WPS_Indicators::known_rat_operator_targets()` returning the four known operator-target domains as an informational reference list. Useful for peer-victim notification: every captured target so far runs an Islamic apologetics website, suggesting the campaign is theme-targeted rather than opportunistic. Detection works without consulting this list  the constant HMAC seed and the encoded harvester headers identify the family on byte content alone.
- Verified via behavioural test: all four known samples are flagged `critical` with `auto_delete: true`; the extractor correctly returns the first four victim sites in the captured corpus from their respective samples; the new encoded-harvester signature matches when the payload is injected into a faux `wp-login.php`; the legitimate Let's Encrypt ACME challenge file (87 bytes, format `<token>.<thumbprint>`) is correctly ignored. All 5 assertions passed.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.44-1` to `1.3.45-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.45`. Rebuild as `wp-perf-shield-1.3.45.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.44

- Closed the `.well-known/` blind spot. The wp-locale-handler RAT v1.7 was caught hidden in `.well-known/pki-validation/cert-check.php` on a live site  a deliberately legitimate-looking path that none of the existing scanner walkers reached. Every prior walker operates on `wp-content/`, `wp-includes/`, ABSPATH root, or active theme; the IETF `.well-known/` directory at the web root was outside the scope. From 1.3.44 onward the scanner walks `<ABSPATH>/.well-known/` on every run.
- Added the new sample's hashes to the upload-guard hash list in `WPS_Blocker::get_blocked_hashes()`: MD5 `d75140a8db6edc1147f826b7eec30812`, SHA-256 `7e1f7a9b622f3cc7941cf6a36c6f23682e02191ae430ccd24cb3ac5cb1d8eb82`. The sample's signature counts confirm it is the wp-locale-handler RAT family rebranded with the `cert-check.php` basename: 2 hits on the activation key `a3f8b2c1d4e5f607`, 2 on the mode-l/t `d3AtY29udGVudC91cGxvYWRz` marker, 1 on `wp_session_tokens_config`, 1 on `session-manager.php`, 1 on the auth-bypass HMAC tail `4a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e`, 3 on the mode-q gate key `b2c1d4e5`. The XOR seed embedded in the credential-harvester payload is the operator-target domain literal, so each operator gets a custom-built binary.
- Added `cert-check.php` to `WPS_Indicators::secondary_backdoor_filenames()` so all existing walkers and the 1.3.43 dropper-cache hunt also catch this basename anywhere on disk.
- Added `WPS_Scanner::check_well_known_php()` plus the constants `WELL_KNOWN_MAX_FILES` (500) and `WELL_KNOWN_MAX_DEPTH` (6). The walker runs the full `RecursiveDirectoryIterator` against `<ABSPATH>/.well-known/` (if it exists), extension-filters to `.php` files only, content-matches each candidate against the existing `SIGNATURES_BACKDOOR` constant, and emits one of two finding shapes:
   1. **Signature match.** `critical` severity with `auto_delete: true`. The matching signature name is included in the finding type so the operator sees which family was hit.
   2. **No signature match.** `high` severity with NO auto-delete flag. Review-only finding. Preserves operator agency for the rare-but-possible legitimate case (some Plesk configurations generate ACME challenges via PHP); the operator inspects manually before deleting.
- The walker is bounded: 500-file cap (this directory should never legitimately contain more), depth 6, 512 KiB read cap per file. Extension filter to `.php` only means legitimate `.well-known/` content (ACME challenge tokens, security.txt, host-meta, openid-configuration, apple-app-site-association, assetlinks.json, etc.) is ignored entirely.
- Wired `check_well_known_php()` into `WPS_Scanner::run()` between `check_dropper_cache()` and `check_malicious_db_options()`. Findings flow through the existing aggregation: critical findings trigger the rate-limited admin email and contribute to the 1.3.42 redrop baseline on auto-delete.
- Verified via behavioural test against the actual `cert-check.php` sample. Test set up a synthetic `.well-known/` tree containing the real RAT file plus benign confounders: a legitimate ACME challenge token (no extension), a `security.txt`, an unsigned PHP file (`admin-helper.php` simulating a Plesk ACME helper), and a PHP file outside `.well-known/` to verify walker scope. Result: the real RAT fired `critical` with `auto_delete: true` and the matched signature `a3f8b2c1d4e5f607`; the unsigned PHP fired `high` with no auto-delete; all three benign confounders were correctly ignored. All 8 assertions passed.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.43-1` to `1.3.44-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.44`. Rebuild as `wp-perf-shield-1.3.44.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.43

- Dropper-cache hunt landed. The plugin now sweeps `wp-content/` for three things on every scan: cached toolkit ZIPs that the operator has parked as the source for redroped files, loose dropper component PHP files anywhere in the tree, and hidden directories that have no benign explanation under `wp-content/`. Closes the loop the redrop detector caught but could not fix: removing only the dropped files leaves the cached ZIP intact, so the next cycle reproduces the toolkit byte-for-byte. Diagnostics export bumps to `1.3.43-1`.
- Added `WPS_Indicators::dropper_cache_zip_patterns()` returning the basename substrings that identify dropper-cache ZIP containers. Initial entry: `wp-config-cache` (covers the `.sbs` toolkit container, including the `_wp-config-cache.zip` sanitiser variant and any `__2_` / `__3_` numbered duplicates that WordPress's `sanitize_file_name()` produces on filename collisions).
- Added `WPS_Scanner::check_dropper_cache()` plus the constants `DROPPER_CACHE_MAX_FILES` (5000) and `DROPPER_CACHE_MAX_DEPTH` (6). The walker iterates `wp-content/` with `RecursiveDirectoryIterator::SELF_FIRST` (so directory entries hit the visitor before their children) and bounds itself to those two limits. The plugin's own directory is excluded from both file matching and directory matching.
- Three sub-hunts inside `check_dropper_cache()`:
   1. **ZIP container hunt.** Any `.zip` file whose basename contains any substring from `dropper_cache_zip_patterns()` is flagged `critical` with `auto_delete: true`. No benign explanation; auto-removal is safe.
   2. **Loose dropper component hunt.** Any file whose basename matches an entry in `WPS_Indicators::secondary_backdoor_filenames()` (currently `.wp-config-cache.php`, `wp-security-cache.php`, `wp-phpunit.php`, `wp-default.php`) is flagged `critical` with `auto_delete: true`. Complements the existing per-directory walkers (uploads, cache, mu-plugins, languages) by catching copies the operator has parked in unexpected nested directories like `wp-content/some-vendor-cache/`.
   3. **Hidden-directory hunt.** Any directory whose basename starts with a dot is flagged. Severity `medium` if the basename matches a known development directory list (`.git`, `.svn`, `.hg`, `.idea`, `.vscode`, `.cache`) so a developer who deployed an intentional checkout to staging gets a review prompt rather than an alarm; severity `high` otherwise (the staging area for a parked-toolkit dropper is exactly this shape).
- Wired the new check into `WPS_Scanner::run()` between `check_redrop()` and `check_malicious_db_options()`. Findings flow through the existing aggregation: critical findings trigger the rate-limited admin email, the `auto_delete: true` flag means the auto-remediator removes the cache and the loose components on the same scan, and successfully-deleted files contribute to the 1.3.42 redrop baseline. The full chain is now connected: detect the cycle, alert, delete the redroped file, delete the cache that produced it, record the hash so the next cycle is detected immediately.
- Verified via behavioural test on a synthetic `wp-content/` tree containing four ZIP containers (varying naming patterns: `_wp-config-cache.zip`, `_wp-config-cache__2_.zip`, `.wp-config-cache.zip`, and the bare `wp-config-cache.zip`), three loose dropper components in unexpected locations, one `.git` development directory, two hidden non-development directories, and several confounders (legitimate plugin file, normal-backup.zip, plugin's own internal files including a planted backdoor name and a planted ZIP). All 7 critical findings emerged, the dev directory got `medium`, the two hidden non-dev directories got `high`, the self-directory exclusions held, and no confounders fired.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.42-1` to `1.3.43-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.43`. Rebuild as `wp-perf-shield-1.3.43.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.42

- Redrop detection landed. The auto-remediator now persists the SHA-256 of every confirmed-malicious file it deletes; subsequent scans flag any byte-identical reappearance as `redrop_detected (critical)`. The signal has no benign explanation — a hash-blocked, signature-flagged, name-known sample does not reappear on disk without an active dropper. Closes the operator-attention gap that earlier releases papered over with advisory text saying "watch for reappearance."
- Added five private static methods on `WPS_Scanner`: `compute_redrop_hashes()` hashes the file (or up to 20 PHP files in a target directory) before deletion; `record_redrop_baseline()` persists the hash with `family`, `deleted_at`, `redrop_count`, `last_redrop_at`, and `last_redrop_path` to the new `wps_redrop_history` option; `check_redrop()` walks `wp-content/` on every scan, hashes candidate files, and emits a critical finding for every match; `load_redrop_history()`, `save_redrop_history()`, and `prune_redrop_history()` manage the option lifecycle.
- Wired `compute_redrop_hashes()` and `record_redrop_baseline()` into `WPS_Scanner::auto_remediate()` so every successful auto-delete contributes to the baseline. The pre-delete hash capture is bounded: 20-file cap on directory targets, 200 KiB cap per file, hashing skipped on files larger than the cap.
- Wired `check_redrop()` into `WPS_Scanner::run()` between `check_dropper_persistence()` and `check_malicious_db_options()`. The check is bounded: 5000 candidate files maximum per scan, 200 KiB cap per file, mtime pre-filter that skips any file modified before the oldest `deleted_at` in history (a file modified before the deletion cannot be a redrop of anything in the catalogue), and the plugin's own directory excluded from both the recording and the scan path.
- The new findings flow through the existing scanner aggregation: `auto_delete: true` so the redroped file is also automatically deleted on the same scan, severity `critical` so the rate-limited admin email fires, and a structured `redrop_recorded` / `redrop_detected` event log line that names the family, the truncated hash, and the redrop count.
- TTL: history entries expire after 30 days (`REDROP_TTL_SECONDS`). Capacity: 500 entries with FIFO eviction by `deleted_at` (`REDROP_MAX_RECORDS`). Reasonable for any site short of an active full-on incident; a fresh batch starts cleanly the moment all the records have aged out.
- Added `wps_redrop_history` to the uninstall option-clear list in `wp-perf-shield.php`.
- Added two new event labels to `WPS_Admin`'s map: `redrop_recorded` ("Redrop baseline recorded") and `redrop_detected` ("Redrop detected (previously-cleaned hash reappeared)").
- Verified via Reflection-based behavioural test: a synthetic file is hashed before deletion, the baseline persists with `redrop_count = 0`, the file is deleted, a byte-identical recreation is detected on the next scan with `redrop_count` incremented to 1, the finding emerges with `severity = critical` and `auto_delete = true`, files inside the plugin's own directory are excluded from matching, and 40-day-old records get pruned by the TTL sweep.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.41-1` to `1.3.42-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.42`. Rebuild as `wp-perf-shield-1.3.42.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.41

- Wired the three 1.3.40 behavioural checks (`auto_prepend_file` sweep, unknown-base64 wp_options sweep, cron callback resolution) into the hourly `wps_hourly_scan` cron run. The diagnostics export bundle's `indicator_version` field bumps to `1.3.41-1`.
- Added `WPS_Forensics::dropper_persistence_findings()`, a public wrapper that exposes only the three behavioural checks under a fixed three-key shape (`auto_prepend_anomalies`, `unknown_base64_options`, `cron_callbacks`). Keeping it as a separate accessor rather than making the three private methods public means future refactors of the broader `run()` report shape do not break the scanner integration contract.
- Added `WPS_Scanner::check_dropper_persistence()` which calls the new wrapper, translates each structured finding into the scanner's canonical `severity` / `type` / `subject` / `path` / `action` shape, and merges it into the hourly findings array. The translation maps `auto_prepend` `critical` to scanner-`critical` and `review` to `high`; both `php_payload` and `clickfix_js` unknown-base64 verdicts to `critical` (the classifier already requires structural confirmation, so a flagged row is a confirmed payload-shaped blob); `cron_callback` `malicious_substring` and `known_backdoor_filename` to `critical`, `outside_expected_dirs` to `high`, and the lower-confidence `missing_file` and `unresolvable` cases to `medium`.
- The existing `WPS_Scanner::run()` aggregation, transient cache, `scan_issues` event log, rate-limited admin email (`WPS_Logger::notify_admin`), Overview-tab findings table, and Diagnostics Source-Trace timeline pick up the new findings automatically because they share the same canonical finding shape. No new code paths in the email or rendering layers; the existing flow simply receives more types of finding.
- The wrapper is bounded by design: the auto_prepend walker caps at depth 6 and 2000 files, the wp_options sweep caps at 60 candidate rows, and the cron resolver only iterates events already scheduled. Adding all three to an hourly scan adds well under a second of work on a healthy site.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.40-1` to `1.3.41-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.41`. Rebuild as `wp-perf-shield-1.3.41.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.40

- Three new behavioural detection layers landed for the dropper-hunt workflow. These are not new indicator data; they are new classifiers that catch the persistence vectors a name-based catalogue cannot reach. The diagnostics export bundle's `indicator_version` field bumps to `1.3.40-1`.
- Added `WPS_Forensics::check_auto_prepend_files()` and the supporting classifier `classify_auto_prepend_target()`. The walker iterates `.user.ini`, `.htaccess`, and `php.ini` under ABSPATH (depth 6, max 2000 files) and parses each one for `auto_prepend_file` and `auto_append_file` directives in both Apache (`php_value` / `php_admin_value`) and ini-file syntax. Each resolved target is classified `safe` (matches a hosting-agent prefix such as `/usr/lib/php/`, `/opt/newrelic/`, `/etc/php/`, `/opt/plesk/`, `/opt/bitnami/`, `/opt/cpanel/`, `/usr/local/lsws/`, `/opt/hostinger/`), `critical` (target lives inside ABSPATH, `wp-content/`, `wp-includes/`, `wp-admin/`, `/tmp/`, `/var/tmp/`, or `/dev/shm/`), or `review` (plausible system path that operators should verify by hand).
- Added `WPS_Forensics::check_unknown_base64_options()` and the structural classifier `classify_decoded_option_blob()`. The check selects up to 60 `wp_options` rows whose `option_value` is between 200 and 200000 bytes and matches the pure-base64 regex `^[A-Za-z0-9+/=]+$`, skips known-bad option names (already covered by `check_option_anomalies`) and a conservative core/framework safe-substring list, then base64-decodes the value and runs two structural checks against the decoded bytes: a PHP-payload check (opener tag plus an executor or loader call such as `eval`, `base64_decode`, `gzinflate`, `file_put_contents`, `shell_exec`, `system`, `passthru`, `assert`) and a ClickFix outer-JS check (an IIFE that uses `String.fromCharCode` indexing and feeds the result into `new Function`). Verified against all four ClickFix samples on file: every one of them encodes a `clickfix_js`-shaped payload that the classifier flags. A redacted, length-bounded `safe_decoded_preview()` is included in the report so an operator can read the verdict without raw exfil bytes ever reaching the admin DOM.
- Added `WPS_Forensics::check_cron_callback_resolution()` and the classifier `classify_callback_source()`. For every scheduled hook in `_get_cron_array()`, the resolver walks `$wp_filter[$hook]->callbacks` and reflects each registered callable down to its source file via `ReflectionFunction` (closures, function names) or `ReflectionMethod` (`Class::method`, `[object, method]`). The source file is then classified `safe` (lives inside `wp-includes`, `wp-admin`, `WP_PLUGIN_DIR`, `wp-content/themes`, or `wp-content/mu-plugins`), `malicious_substring` (matches an entry in `WPS_Indicators::malicious_cron_hook_substrings()`), `known_backdoor_filename` (matches an entry in `WPS_Indicators::secondary_backdoor_filenames()`), `missing_file` (callback registered against a path that no longer resolves), or `outside_expected_dirs` (the dropper hideout case: callback file lives in `wp-content/uploads`, `wp-content/cache`, `wp-content/languages`, or somewhere else outside the WordPress code tree).
- Wired the three new findings into `WPS_Forensics::run()` under the keys `auto_prepend_anomalies`, `unknown_base64_options`, and `cron_callbacks`. The Forensics admin tab gained three new cards rendering each finding with verdict colour-coding (yellow for `review`, red for `critical`/`malicious_*`).
- Added a dedicated AJAX action `wps_delete_unknown_b64` (`WPS_Remediation_Controller::delete_unknown_b64_option()`) so an operator can delete a flagged unknown-base64 option in one click. The handler refuses any name that matches a hardcoded core-protected list (`siteurl`, `home`, `blogname`, `admin_email`, `template`, `stylesheet`, `active_plugins`, `wp_user_roles`, `cron`, `rewrite_rules`, `db_version`) and additionally requires the option name to currently appear in the cached `unknown_base64_options` finding set, so a synthetic POST cannot trick the handler into deleting an option that Forensics never flagged. Logs as `db_option_deleted_unknown_b64`.
- Added the new event label `db_option_deleted_unknown_b64` ("DB option deleted (unknown base64)") to `WPS_Admin`'s event-label map.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.39-1` to `1.3.40-1`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.40`. Rebuild as `wp-perf-shield-1.3.40.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.39

- Confirmed two further ClickFix render-hijacker variants from the same family observed in the wild as `page-seo-toolkit-a937.zip` and `starter-image-guard-e9a2.zip`. Both fit the family pattern exactly: fake performance/SEO plugin disguise, single handler class with a hex suffix, base64 payload stored in a per-variant DB option, late-priority `wp_footer` injection that skips administrators, REST/AJAX/cron contexts, role-bearing logged-in users, bots, and visitors carrying the `_cf_verified` or `_wp_perf_ok` dismiss cookie. The new variants are `Plugin Name: Page SEO Toolkit / Author: Page Software / handler: Opt_Handler_841e / option: wp_b6786d21cb_cfg / wp_footer priority: 91734` and `Plugin Name: Starter Image Guard / Author: Dev Group / handler: Render_Module_5b7d / option: wp_a326b31e44_cfg / wp_footer priority: 91411`. Most string literals are concatenated with `'.'.` to evade naive substring grepping; the option key, class name, and slug remain literal in source.
- Added `page-seo-toolkit` and `starter-image-guard` to the blocked-slug list in `class-blocker.php` and to the suffix-pattern list (`/page-seo-toolkit[-_][a-z0-9]{3,8}\//i` + `.php$` variant; same for `starter-image-guard`) so renamed-folder uploads of any variant prefixed with either slug are rejected.
- Added MD5 `a23f9c0fb1eb85247d0f4a8264bd9c18` and SHA-256 `ee4b899d93655e4fc15b6ed8692a25e3b4052a005f85c5460d22a444e4245b9e` for `page-seo-toolkit-a937.php`, plus MD5 `bb398fb4783c7fc3647a633b51811099` and SHA-256 `acf2aaf34ceac250b03c77ab2afa221f3290508b7f876209ab332830d0ae4105` for `starter-image-guard-e9a2.php`, to `class-blocker.php`'s blocked-hashes list.
- Added `wp_b6786d21cb_cfg` and `wp_a326b31e44_cfg` to `WPS_Indicators::malware_option_keys()` so they appear in the Forensics database-anomaly card and the **Remediation -> Delete malicious DB options** action.
- Added `page-seo-toolkit`, `starter-image-guard`, `wp_b6786d21cb_cfg`, `wp_a326b31e44_cfg`, `Opt_Handler_841e`, `Render_Module_5b7d`, `Page SEO Toolkit`, and `Starter Image Guard` to `class-scanner.php`'s `SIGNATURES_PERF` so any PHP file containing any of these substrings is flagged in scans.
- Extended `class-blocker.php`'s `find_malicious_marker()` content-signature list with the same eight tokens, plus gap-filled the `wp_fe99c06901_cfg`, `DB_Handler_5dfe`, `Advanced Asset Insights`, and `advanced-asset-insights` tokens that 1.3.37 added to the scanner but missed in this list. ZIP-content inspection at the upload guard now matches every confirmed variant uniformly.
- Extended `class-hardening.php`'s wp-config malware regex (`clickfix_marker_line`, `suspicious_remote_or_upload_include`, and `known_malware_comment_block`) with the two new option keys, two new handler classes, and two new slugs. Also added `RewriteRule` lines for `advanced-asset-insights` (gap-fill from 1.3.37), `page-seo-toolkit`, and `starter-image-guard` to the `perf_analytics` `.htaccess` rule block. **Remediation -> Clean wp-config.php** removes any line carrying these markers; **Hardening -> Apply ClickFix folder block** now denies HTTP access to renamed folders of all eight variant prefixes.
- Extended Forensics: the media-uploads `LIKE` query covers `%page-seo-toolkit%`, `%starter-image-guard%`, and `%advanced-asset-insights%` (the last gap-filled from 1.3.37); the suspicious-active-plugin slug list and the `trace_plugin_file_timestamps` slug list both pick up the two new slugs; the four SSH grep commands now include `page-seo-toolkit`, `starter-image-guard`, `wp_b6786d21cb_cfg`, `wp_a326b31e44_cfg`, and `wp_fe99c06901_cfg` (the last gap-filled).
- Extended Diagnostics Source Trace SSH-grep `$terms` array with the two new slugs and updated the `class-admin-hardening.php` `perf_analytics` rule description to list the new variant prefixes.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.37-1` to `1.3.39-1`. The diagnostics export bundle reflects the bump automatically.
- Updated `doc/ssot.md` Confirmed ClickFix Indicators block to list the two new slugs.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.39`. Rebuild as `wp-perf-shield-1.3.39.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.37

- Confirmed `advanced-asset-insights-ec06.php` as a new ClickFix render-hijacker variant. Identical family behaviour: fake performance plugin disguise (`Plugin Name: Advanced Asset Insights`, `Author: Cache Team`), single handler class with `DB_Handler_5dfe`, base64 payload stored in DB option `wp_fe99c06901_cfg`, late-priority `wp_footer` injection (`add_action('wp_footer', ..., 92101)`), bot/admin/AJAX/REST evasion, dismiss cookies `_cf_verified` and `_wp_perf_ok`. Most string literals are concatenated with `'.'.` to evade naive substring grepping; the option key, class name, and slug are still literal.
- Added `advanced-asset-insights` to the blocked-slug list in `class-blocker.php` and to the suffix-pattern list (`/advanced-asset-insights[-_][a-z0-9]{3,8}\//i` + `.php$` variant) so renamed-folder uploads of any Advanced-Asset-Insights-prefixed variant are rejected.
- Added file MD5 `7dbc51fa960a74a79bd2cb475a2dfd04` and SHA-256 `ff96b828b345755c728cebbf3fc041290f14f12a535f693d06b520d89d106e3b` for the confirmed sample to `class-blocker.php`'s blocked-hashes list.
- Added `wp_fe99c06901_cfg` to `WPS_Indicators::malware_option_keys()` so it appears in the Forensics database-anomaly card and the **Remediation -> Delete malicious DB options** action.
- Added `advanced-asset-insights`, `wp_fe99c06901_cfg`, `DB_Handler_5dfe`, and `Advanced Asset Insights` to `class-scanner.php`'s `SIGNATURES_PERF` so any PHP file containing any of these substrings is flagged in scans.
- Extended `class-hardening.php`'s wp-config malware regex with `wp_fe99c06901_cfg`, `advanced-asset-insights`, and `DB_Handler_5dfe`. **Remediation -> Clean wp-config.php** removes any line carrying these markers.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.36-1` to `1.3.37-1`. The diagnostics export bundle reflects the bump automatically.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.37`. Rebuild as `wp-perf-shield-1.3.37.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.36

- Confirmed a third campaign on top of the ClickFix RAT family and the `.sbs` cookie-exfil toolkit: a standalone PHP file manager / webshell shipped as `wp-default.php`. Independent infrastructure (no shared markers with the other two), independent session cookie (`UMSESSID`), independent hardcoded credentials (`admin` / `adminpass`), full filesystem access at DOCUMENT_ROOT scope including upload/download/edit/rename/delete and a deliberate `setmtime` action specifically for forensic-timeline evasion.
- Added `wp-default.php` to `WPS_Indicators::secondary_backdoor_filenames()` so 1.3.34's `check_auto_prepend_hijack` flags the file by basename when present at ABSPATH (catches both the standalone case and the file-referenced-from-another-file case).
- Added MD5 `8a92828554a087c46cc21c87fd1b15d4` and SHA-256 `673806e0aadc67be107217cc0e3dcf12486022fe39150ee09494236d317ee02d` for the confirmed `wp-default.php` build to `class-blocker.php`'s blocked-hashes list. ZIP uploads carrying this exact file are now rejected at the upload guard.
- Added two distinctive content signatures (`UM_AUTO_ROOT_MODE`, `UMSESSID`) to `class-scanner.php`'s `SIGNATURES_BACKDOOR`. Both are unique enough that a single substring hit confirms the file is a copy of this webshell, even if the attacker renames the file or modifies surrounding code.
- Added `WPS_Scanner::check_root_file_signatures()` to the scanner aggregation. This is a new check that walks `ABSPATH` non-recursively, runs every PHP file at WordPress root through the full `SIGNATURES_PERF` / `SIGNATURES_ANTY` / `SIGNATURES_BACKDOOR` content matcher, and flags any hit as critical. Closes the long-standing gap where a standalone PHP webshell dropped next to `wp-config.php` would slip past every other walker (the other walkers cover descendants of `wp-content/` and a few specific named files at root, but no one was generically signature-scanning ABSPATH-root PHP). Uses `scandir()` so leading-dot hidden files are visible, skips `wp-config.php` (dedicated checks), and skips the canonical "Silence is golden" directory-listing guard at `ABSPATH/index.php` to avoid noise.
- Bumped `WPS_Indicators::INDICATOR_VERSION` from `1.3.33-1` to `1.3.36-1`. The diagnostics export bundle picks this up automatically.
- Mtime untrustworthiness note (documentation only): when `wp-default.php` or any rename of it is or has been present, every file modification time on the site may have been altered via the webshell's `setmtime` action. Forensic timelines that rely on "files modified after wp-config" or "files modified within attack window" should be treated as untrustworthy until the webshell is verifiably gone and a fresh baseline is established. Documented in `doc/upgrading.md`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.36`. Rebuild as `wp-perf-shield-1.3.36.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.35

- Reorganised admin tabs so destructive buttons live next to the data they act on, and so the tab dependency order matches the natural workflow.
- Tab order swapped: **Forensics** now sits at position 2 and **Diagnostics** at position 3. Source Trace on Diagnostics requires a Forensics report to populate; the previous order had the dependency backwards. Tab slugs and aliases are unchanged so existing `?tab=diagnostics` URLs still resolve.
- **Diagnostics export** moved from Settings to **Diagnostics** (new section, between the analytics tables and the Active hostile IP blocks card).
- **Clear hostile IP blocks** button moved from Settings to **Diagnostics**, immediately under the Active hostile IP blocks table where the data being cleared is shown. The button only renders when the list is non-empty.
- **Reset wp-config.php baseline** button moved from Settings to **Hardening** Section 2 (wp-config.php hardening), inside an inline note explaining when to use it.
- **Environment checks** grid (was "System readiness" on Overview) moved to **Diagnostics** as a final subsection. Overview is now focused on scan + findings + recent events.
- **Settings tab** is now configuration only: extra blocked slugs, blocked file hashes, the three behaviour toggles, and the Save button. The "Danger zone" section is gone; its three buttons moved to where their data lives. The `wps-clear-btn-settings` button (a duplicate of the Events tab's Clear log button) has been removed; the Events tab still has its own Clear log button.
- **Hardening tab** trimmed: removed the informational Section 2 (activation-blocker status, no action button), Section 6 (ongoing-monitoring bullet list), and the root-cause reminder paragraph at the bottom. Sections renumbered: Section 1 Immediate cleanup, Section 2 wp-config.php hardening (now includes Reset baseline), Section 3 .htaccess hardening, Section 4 Auth salt rotation. The removed informational content is preserved in `doc/upgrading.md`.
- No DOM IDs or AJAX action names changed. The four moved buttons (`wps-rebaseline-btn`, `wps-clear-ip-blocks-btn`, `wps-export-diag-btn`, plus the deleted `wps-clear-btn-settings`) keep the same ids; their JavaScript handlers in `assets/js/admin.js` were not touched. The shared `#wps-settings-msg` status div is now rendered on Diagnostics and Hardening (where the moved buttons live) instead of Settings.
- No detection logic changed. All scanner, blocker, hardening, and forensics code is identical to 1.3.34.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.35`. Rebuild as `wp-perf-shield-1.3.35.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.34

- Added `WPS_Scanner::check_auto_prepend_hijack()` to detect the auto_prepend_file persistence pattern observed in the field as a malicious `include_once` injected into `ABSPATH/wordfence-waf.php` above the canonical Wordfence WAF bootstrap line. The check has three independent angles: (1) parses `wordfence-waf.php` and flags any `include`/`require`/`include_once`/`require_once` whose path argument is not the canonical `wp-content/plugins/wordfence{,-protect}/waf/bootstrap.php`; (2) parses `ABSPATH/.user.ini` and `ABSPATH/.htaccess` for `auto_prepend_file` directives, flags any value other than `wordfence-waf.php` or any path resolving outside the WordPress tree; (3) walks every regular file at the ABSPATH root via `scandir()` and flags both files whose basename exactly matches `WPS_Indicators::secondary_backdoor_filenames()` (catches a standalone toolkit file dropped at root, including hidden-named `.wp-config-cache.php` that `glob('*.php')` would silently skip) AND PHP files at root whose contents reference any toolkit filename (catches the `wordfence-waf.php`-style reference even when the payload is somewhere else).
- Wired the new check into the scanner aggregation so it runs on every `Run scan now` action and every hourly cron scan. Findings are tagged `critical`.
- The new check is purely additive: it doesn't change any existing detection, so cached scan results from 1.3.33 remain readable, and no behavior changes for sites that don't have an auto_prepend hijack.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.34`. Rebuild as `wp-perf-shield-1.3.34.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.33

- Confirmed two new malware samples and added detection coverage. The first is a `wp-locale-handler.php` content-variant rebuild from the existing ClickFix RAT family (same `?_wph=a3f8b2c1d4e5f607` activation token, same five modes, same MU-plugin restore loop, customised XOR key seed). The second is a complete attacker toolkit shipped together as `.wp-config-cache.zip` containing three coordinated payloads from a separate campaign that targets WordPress with cookie-stealing rather than ClickFix render-hijacking.
- Added eight new file hashes to `class-blocker.php`'s built-in blocked-hashes list. The new ClickFix RAT variant gets MD5 `70358bb32a2cf6fcbfc9edfe2848a579` plus its SHA-256. The new toolkit gets six entries: `2d746471df530568e76e280c6dec8c2d` and SHA-256 for `.wp-config-cache.php` (cookie exfil), `54b60e56a90d0ed4b8a4de79c0916193` and SHA-256 for `wp-security-cache.php` (persistent admin user creator), `cd35f8c14a03fecba0b72e67804dd337` and SHA-256 for `wp-phpunit.php` (five-fallback webshell). Renamed-ZIP uploads of any of these files now get rejected at the upload guard.
- Added three new accessors to `WPS_Indicators` (bumped `INDICATOR_VERSION` to `1.3.33-1`): `cookie_exfil_c2_domains()` returning `['webanalytics-cdn.sbs']`, `hardcoded_admin_usernames()` returning `['adminbackup561801', 'a7f3e9b2c4d1e5f6']`, and `secondary_backdoor_filenames()` returning `['.wp-config-cache.php', 'wp-security-cache.php', 'wp-phpunit.php']`. Forensics' admin-account check and admin-tab Forensics renderer now both load the malware-created username list from the indicator class instead of a local literal.
- Extended `SIGNATURES_BACKDOOR` in `class-scanner.php` with two high-entropy content markers from the new toolkit (`webanalytics-cdn.sbs`, `a7f3e9b2c4d1e5f6`). These are unique enough that a single substring hit is sufficient for confirmation.
- Extended the wp-content/cache scan and the forensics-tab known-backdoor name lists with the three new toolkit filenames so any of them dropped into a cache, mu-plugins, or other under-`wp-content/` location is auto-flagged.
- Extended `class-hardening.php`'s removable-malware regex (the `clickfix_marker_line` pattern used by `wp-config.php` cleanup) with `webanalytics-cdn.sbs` and `a7f3e9b2c4d1e5f6` so the cleaner removes any of these strings if injected into wp-config.php.
- The diagnostics export bundle now includes the bumped `indicator_version` automatically; no separate edit needed.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.33`. Rebuild as `wp-perf-shield-1.3.33.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`).

## 1.3.32

- Fixed an administrator lockout when the operator's own IP lands in the hostile-IP auto-block list (commonly via uploading an earlier malformed release ZIP, or while testing malware samples on the same egress IP). `WPS_Blocker::maybe_block_request()` now allows the request through when the user is signed in with `manage_options`, registers an `admin_notices` (and `network_admin_notices`) callback that surfaces a top-of-admin recovery banner, and logs a new `self_block_bypassed` event the first time per IP per hour. Unauthenticated requests from a blocked IP are still rejected with a 403, and `wp-login.php` requests still hit the 403 so brute-force defence is unchanged.
- Added `WPS_Blocker::render_self_block_notice()` which prints the recovery banner with an inline "Clear hostile IP blocks now" button and a link to Settings. JavaScript is inlined in the notice because `assets/js/admin.js` is enqueued only on the WP Perf Shield admin screen and the notice must work on every admin page where the admin lands first. The button calls the existing `wps_clear_ip_blocks` AJAX action, then reloads the page.
- Added `self_block_bypassed` to the admin Events tab label map ("Self-block bypassed (admin)").
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.32`. Rebuild as `wp-perf-shield-1.3.32.zip` with `wp-perf-shield/` as the package root before publishing. Use `bsdtar` (not `Compress-Archive`); see the project memory note "Release ZIP build pattern" for why.

## 1.3.31

- Phase 4 indicator data split (conservative scope): created `includes/class-wps-indicators.php` exposing `WPS_Indicators::malware_option_keys()`, `mu_persistence_option_keys()`, `exfil_filenames()`, and `malicious_cron_hook_substrings()` as static accessors. Bumped `WPS_Indicators::INDICATOR_VERSION` to `1.3.31-1`.
- Replaced the duplicate hard-coded arrays in `includes/class-remediation-controller.php` (delete_db_options, delete_single_option, delete_exfil), `includes/class-forensics.php` (check_option_anomalies, exfil sweeps), and `includes/class-scanner.php` (exfil check) with calls to the shared loader. The actual indicator values are unchanged in this release; the move is structural so future indicator-policy changes have a single source of truth.
- Hash lists, suffix patterns, and PCRE catalogues that are tightly coupled to specific scanner or hardening logic intentionally stay in their owning class. The roadmap calls for a parity test before extracting those, and the test harness does not exist yet.
- Phase 5 diagnostics export: added `wps_export_diagnostics` AJAX handler in the remediation controller. The handler returns a redacted JSON support bundle containing plugin version, indicator version, WP and PHP versions, settings counts (not raw slug/hash content), active protections, environment checks, last scan summary, redacted findings, blocked IP summaries, recent events with subjects truncated to 240 characters, and a forensics summary. `exfil_file_read` events are explicitly dropped from the bundle. Raw credentials, auth salts, DB passwords, and full exfil contents are never included.
- Added a "Diagnostics export" panel in the Settings tab with a `wps-export-diag-btn` button. The matching handler in `assets/js/admin.js` wraps the JSON response in a Blob, generates a timestamped filename, and triggers a browser download. Nothing is sent off-site.
- Added a "Manual Smoke-Test Checklist" section to `doc/upgrading.md`, an operator-facing checklist covering plugin upload, tab navigation, scan/auto-delete/detect-only flows, hostile IP self-recovery, ZIP self-package exemption, wp-config.php hardening writes and cleanup, forensics, diagnostics export, events log, and final integrity validation. Cited as Phase 5 acceptance #3. The checklist sits next to the upgrade notes that operators already read after each release rather than in a separate file.
- Added `tools/verify-package.ps1`, a pre-release validation script that codifies the parser fallback used through Phases 0-5. Runs PHP and JS bracket-balance checks, asserts version-marker consistency across the four declared release files, walks the required directory layout, and refuses any stray markdown at the package root. Cited as Phase 5 acceptance #2. Run from the repo root before building each release ZIP.
- Updated `doc/ssot.md` to document the new `includes/class-wps-indicators.php` indicator data location and the `tools/verify-package.ps1` pre-release script. The operator smoke-test checklist is now referenced as a section of `doc/upgrading.md`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.31`. The release ZIP has not been rebuilt in this turn; rebuild as `wp-perf-shield-1.3.31.zip` with `wp-perf-shield/` as the package root before publishing. Run `tools/verify-package.ps1` first.

## 1.3.30

- Phase 3 admin view split landed. The 2115-line `includes/class-admin.php` was broken into one 283-line orchestrator (which builds shared context and dispatches to tab classes) and seven new tab files: `class-admin-overview.php`, `class-admin-diagnostics.php`, `class-admin-forensics.php`, `class-admin-remediation.php`, `class-admin-hardening.php`, `class-admin-events.php`, `class-admin-settings.php`.
- Tab order, tab aliases (`dashboard -> overview`, `analytics -> diagnostics`, `log -> events`), button IDs (`wps-scan-btn`, `wps-clear-btn-log`, `wps-del-exfil-btn`, `wps-clean-login-btn`, `wps-clean-funcs-btn`, `wps-clean-cron-btn`, `wps-clean-wpconfig-btn`, `wps-del-db-btn`, `wps-h-transients`, `wps-h-sessions`, `wps-h-salts`, `wps-hc-*`, `wps-hh-*`, `wps-rebaseline-btn`, `wps-clear-ip-blocks-btn`, `wps-clear-btn-settings`, `wps-forensics-btn`), JSON action names, and DOM message containers (`wps-msg`, `wps-rem-msg`, `wps-log-msg`, `wps-settings-msg`, `wps-forensics-status`) are unchanged. The admin JavaScript was not modified.
- Hardening tab's two anonymous closures (`$badge` and `$applyBtn`) became private static methods `WPS_Admin_Hardening::badge()` and `WPS_Admin_Hardening::apply_btn()`. The generated button markup, `data-wps-action`, `data-wps-payload`, `data-wps-confirm`, and the per-action `*-msg` status span IDs match what 1.3.29 produced byte-for-byte.
- Diagnostics tab now owns its supporting helpers locally: `build_analytics`, `build_source_trace`, `source_trace_*`, `render_source_trace`, `render_analytics_table`, and `render_blocked_ips_table` are private static methods on `WPS_Admin_Diagnostics`. Forensics tab similarly owns `render_forensics`, `forensic_card`, and `forensic_action_button`.
- Fixed a Phase-2 regression: `WPS_Admin::register_hooks()` was no longer being called from the bootstrap, so the admin menu, asset enqueueing, and settings save handler were not registering. The bootstrap now calls both `WPS_Admin::register_hooks()` and `WPS_Remediation_Controller::register_hooks()` at load time.
- Added the seven new tab class requires to `wp-perf-shield.php`. The bootstrap remains short (~95 lines).
- Behavior is unchanged. No action name, button ID, log type, capability, stored option, transient, or AJAX response shape changed in this release. Cached scan results, the events log, and existing baselines remain readable.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.30`. The release ZIP has not been rebuilt in this turn; rebuild as `wp-perf-shield-1.3.30.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.29

- Phase 2 controller and service split landed. Phase 0 baseline checks pass on all 10 PHP files plus `assets/js/admin.js`.
- Created `includes/class-wps-utils.php` exporting `WPS_Utils::path_is_inside()`, `WPS_Utils::guard_request()`, `WPS_Utils::guard_path()`, `WPS_Utils::path_is_self()`, `WPS_Utils::fetch_remote_file()`, and `WPS_Utils::is_clean_wp_cron()` as static methods. The previous global `wps_*` functions for path containment, request gating, remote fetching, and core file validation have been removed; their logic is unchanged.
- Created `includes/class-remediation-controller.php` carrying every existing `wp_ajax_wps_*` handler as a static method. A single `WPS_Remediation_Controller::register_hooks()` call wires the 23 actions at plugin load time. Every action name is preserved exactly; the admin JavaScript and DOM IDs continue to work without modification.
- Slimmed `wp-perf-shield.php` from 1083 lines to 85 lines. The bootstrap file now carries only the plugin header, constants, `require_once` statements, the activation/deactivation/uninstall hooks, the cron scheduling, and the controller registration call. No remediation logic remains inline.
- Preserved the wp-login.php and theme functions.php cleaner regexes byte-for-byte during the move; the only surface change is the literal-newlines-in-source single-quoted strings became `\n`-escaped double-quoted strings, which compile to identical PCRE patterns.
- Behavior is unchanged: no action name, button ID, log type, or stored option changed in this release. Cached scan results, the events log, and existing baselines remain readable.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.29`. The release ZIP has not been rebuilt in this turn; rebuild as `wp-perf-shield-1.3.29.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.28

- Phase 1 safety stabilization landed. Phase 0 baseline checks were re-run beforehand and all eight PHP files plus `assets/js/admin.js` passed structural parser checks.
- Added shared destructive-action guard helpers `wps_guard_request()`, `wps_guard_path()`, and `wps_path_is_self()` in `wp-perf-shield.php` so AJAX handlers can express nonce + capability + path-containment checks in one call instead of repeating the boilerplate.
- Tightened capability checks on destructive AJAX handlers, with `manage_options` retained as a fallback so older installs and custom roles do not lose access. `wps_delete_user` now requires `delete_users`, `wps_delete_attachment` and `wps_delete_exfil` require `delete_posts`, `wps_delete_plugin_folder` requires `delete_plugins`, `wps_delete_theme_file` and `wps_clean_functions` require `edit_themes`, and `wps_clean_cron` / `wps_clean_login` / `wps_clean_wpconfig` / `wps_rebaseline_wpconfig` / `wps_regenerate_salts` / `wps_wpconfig_constant` require `update_core`.
- Hardened `wps_delete_exfil`: harvested credential lines are no longer returned to the browser in the AJAX response. The handler now logs only the line count, validates path containment via `wps_guard_path()` against the uploads basedir, refuses to follow symlinks, and uses tighter log labels (`exfil_skipped_outside_uploads`, `exfil_skipped_symlink`, `exfil_delete_failed`).
- Fixed admin-side exfil rendering in `assets/js/admin.js` so file paths are escaped via the existing `esc()` helper before being injected into the destructive-action message panel, and removed the misleading "Credentials logged from deleted file(s)" heading now that no credential bodies cross the wire.
- Routed `WPS_Logger::log_event()` and `notify_admin()` through a new private `remote_ip()` helper that reads `REMOTE_ADDR` only, applies `wp_unslash()`, validates with `FILTER_VALIDATE_IP`, and returns `cli` outside a request context or `invalid` for malformed values. Proxy headers are still not trusted.
- Added a pre-edit `looks_like_wpconfig()` sanity check, a post-edit sanity re-check, and a versioned backup via `next_backup_path()` to `WPS_Hardening::set_wpconfig_constant()` and `WPS_Hardening::regenerate_salts()`. A second hardening action no longer overwrites the previous action's recovery point.
- `regenerate_salts()` now records which salt define lines actually changed and refuses to write when nothing matched, so a parse error in the WordPress.org salt API response cannot quietly leave wp-config.php half-rotated.
- Added `wp_unslash()` calls before `sanitize_*` on scalar request inputs at `wp-perf-shield.php` (`constant`, `rule`, `ip`, `option_name`), `includes/class-admin.php` (`extra_slugs`, `extra_hashes`, `_GET['tab']`), and `includes/class-blocker.php` (`_REQUEST['action']`).
- Added distinct event log labels for auto-remediation outcomes: `auto_deleted` (success, unchanged), new `auto_delete_failed` (delete attempt returned false), `auto_delete_already_gone` (target missing on disk), `auto_delete_parent_handled` (subsumed by an earlier delete in the same scan), and `auto_delete_skipped_disabled` (detect-only mode). The shared `format_auto_delete_log_subject()` now includes the result tag in every subject line.
- Added a Phase 1 destructive-AJAX audit table to `doc/upgrading.md` documenting each handler's required capability, target boundary, and self-protection state.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.28`. The release ZIP has not been rebuilt in this turn; rebuild as `wp-perf-shield-1.3.28.zip` with `wp-perf-shield/` as the package root before publishing.

## 1.3.27

- Added a Source Trace diagnostic panel to the Diagnostics tab.
- Correlates blocked uploads, active hostile IP blocks, current scan findings, media ZIP upload records, suspicious plugin/PHP file mtimes, database persistence options, core integrity findings, and SSH grep commands into one newest-first timeline.
- Generates trace-focused Apache/nginx grep commands from the current timeline indicators, filenames, database option keys, and hostile IPs.
- Added responsive Source Trace styling to `assets/css/admin.css`.
- Documented the `wp_options` timestamp limitation: WordPress does not store native option creation times, so DB persistence rows are shown at Forensics report time unless scan/remediation events caught them earlier.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.27`.
- Rebuilt the release archive as `wp-perf-shield-1.3.27.zip` with `wp-perf-shield/` as the package root.

## 1.3.26

- Added a controlled development roadmap to `doc/upgrading.md` covering current architecture, safe change boundaries, high-risk areas, files to avoid, WordPress security concerns, performance concerns, directory compliance, phased implementation order, acceptance criteria, and future-agent prompts.
- Organized the next implementation pathway into Phase 0 baseline guardrails, Phase 1 safety stabilization, Phase 2 controller/service split, Phase 3 admin view split, Phase 4 indicator data split, and Phase 5 diagnostics/export/test harness work.
- Analyzed `site-speed-insights-d6e7.zip` and confirmed it as another ClickFix render-hijacker malware plugin.
- Added built-in blocked slug, suffix pattern, MD5/SHA-256 hashes, scanner signatures, ZIP content markers, database-option cleanup, forensics trace terms, and `.htaccess` hardening coverage for `site-speed-insights`, `Health_Manager_5fec`, and `wp_204acd2d43_cfg`.
- Analyzed `languages.zip` and confirmed `languages/wp-locale-handler.php` as a disguised PHP RAT/backdoor that can live under `wp-content/languages`.
- Added `wp-content/languages` backdoor scanning and auto-removal for confirmed `wp-locale-handler.php` while allowing legitimate WordPress `.l10n.php` translation files.
- Reviewed `2026.zip` as an uploads/media archive; no PHP entries or confirmed executable malware indicators were found during static inspection.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.26`.
- Rebuilt the release archive as `wp-perf-shield-1.3.26.zip` with `wp-perf-shield/` as the package root.

## 1.3.25

- Removed the legitimate `bismikaallahuma` administrator username from hard-coded attacker-account heuristics.
- Limited confirmed malware-created account matching to the known persistence-style account `adminbackup561801`.
- Reworded administrator-account forensics to distinguish confirmed malware-created accounts from generally suspicious or recently created accounts.
- Updated event labels so account findings do not accuse legitimate admins as attackers.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.25`.
- Rebuilt the release archive as `wp-perf-shield-1.3.25.zip` with `wp-perf-shield/` as the package root.

## 1.3.24

- Fixed Auth salt rotation feedback not appearing after confirmation because the page contained both a hidden `<div>` and generated status `<span>` with the same `wps-h-salts-msg` ID.
- Added action-specific confirmation messages for auth salt rotation, session invalidation, `wp-config.php` constants, and `.htaccess` rules.
- Hides one-way session and salt action buttons after success so the completed status badge is visible.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.24`.
- Rebuilt the release archive as `wp-perf-shield-1.3.24.zip` with `wp-perf-shield/` as the package root.

## 1.3.23

- Reworked the Overview findings display from a dense table into compact incident cards.
- Moved auto-delete completion and skipped states into each finding card instead of rendering separate status rows.
- Added severity badges, resolution badges, signature chips, and safer wrapping for long subjects, matches, and actions.
- Improved mobile behavior for the findings panel so incident details stack cleanly.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.23`.
- Rebuilt the release archive as `wp-perf-shield-1.3.23.zip` with `wp-perf-shield/` as the package root.

## 1.3.22

- Fixed `.htaccess` hardening removal so disabled rules delete the WordPress marker block instead of leaving an empty `# BEGIN` / `# END` block behind.
- Changed `php_uploads` and `xmlrpc` status checks to verify the expected rule lines, not only the marker header.
- Added post-write verification for both applying and removing `.htaccess` hardening rules.
- Reloads the Hardening tab after `.htaccess` or `wp-config.php` state changes so badges reflect the actual persisted file state.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.22`.
- Rebuilt the release archive as `wp-perf-shield-1.3.22.zip` with `wp-perf-shield/` as the package root.

## 1.3.21

- Fixed a self-blocking false positive where WP Perf Shield release ZIPs could be rejected because the plugin source contains its own malware indicator strings.
- Added a narrow self-package check for ZIPs rooted at `wp-perf-shield/` with the real `wp-perf-shield.php` plugin header and `WPS_VERSION` definition.
- Kept ZIP scanning active for unknown extra PHP files inside the package, so unexpected payload files are still inspected.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.21`.
- Rebuilt the release archive as `wp-perf-shield-1.3.21.zip` with `wp-perf-shield/` as the package root.

## 1.3.20

- Analyzed `total-render-toolkit-adae.zip` and confirmed it as a ClickFix render-hijacker malware plugin.
- Analyzed `pro-font-optimizer-c88b.zip` and confirmed it as a ClickFix render-hijacker malware plugin.
- Added built-in blocked slugs and suffix patterns for `total-render-toolkit` and `pro-font-optimizer`.
- Added built-in MD5 and SHA-256 indicators for both analyzed plugin files.
- Added scanner signatures for the new plugin names, option keys, handler class names, and render-hijacker markers.
- Added malicious database option detection and deletion for `wp_0b05838858_cfg` and `wp_e3ef2393dd_cfg`.
- Expanded upload ZIP content inspection so renamed uploads containing these samples are blocked before WordPress accepts them.
- Expanded forensics checks for media uploads, plugin timestamps, active plugin anomalies, option anomalies, and SSH log-tracing commands.
- Expanded `.htaccess` hardening rules and `wp-config.php` cleaning markers for the new ClickFix plugin folder suffix variants.
- Updated Remediation and Hardening copy to name the new render-hijacker variants.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.20`.
- Rebuilt the release archive as `wp-perf-shield-1.3.20.zip` with `wp-perf-shield/` as the package root.

## 1.3.19

- Added inner-ZIP malware inspection to the upload guard before WordPress accepts uploaded ZIP files.
- Blocked renamed malware ZIPs when their contents include known plugin folder names, suffix patterns, blocked PHP file hashes, or ClickFix render-hijacker payload markers.
- Added upload event details for the matched ZIP entry, hash, or signature so the source and detection reason are visible in Diagnostics and Events.
- Kept trusted administrator ZIP upload routes available while still inspecting their ZIP contents for confirmed malware indicators.
- Added an Overview readiness check for the PHP `ZipArchive` extension required by inner-ZIP inspection.
- Updated Settings copy, requirements, WordPress readme, project readme, upgrade notes, and SSOT documentation for ZIP content inspection.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.19`.
- Rebuilt the release archive as `wp-perf-shield-1.3.19.zip` with `wp-perf-shield/` as the package root.

## 1.3.18

- Fixed Forensics inline action buttons by generating safely escaped JSON payloads for option names, file paths, plugin paths, attachment IDs, and user IDs.
- Fixed the `Delete now` buttons for malicious database options such as `wp_94d4678186_cfg` and `wp_a26c00cc40_cfg`.
- Cleared the cached Forensics report after bulk or single malicious option deletion so stale database-anomaly rows do not keep displaying after cleanup.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.18`.
- Rebuilt the release archive as `wp-perf-shield-1.3.18.zip` with `wp-perf-shield/` as the package root.

## 1.3.17

- Analyzed `native-render-toolkit-9401.zip` and confirmed it as a ClickFix render-hijacker malware plugin.
- Analyzed `total-render-profiler-3753.zip` and confirmed it as a ClickFix render-hijacker malware plugin.
- Added built-in blocked slugs and suffix patterns for `native-render-toolkit` and `total-render-profiler`.
- Added built-in MD5 and SHA-256 indicators for both analyzed plugin files.
- Added scanner signatures for the new plugin names, option keys, handler class names, and render-hijacker markers.
- Added malicious database option detection and deletion for `wp_94d4678186_cfg` and `wp_a26c00cc40_cfg`.
- Expanded suspicious cron hook purging for native/total render naming variants.
- Expanded forensics checks for media uploads, plugin timestamps, active plugin anomalies, option anomalies, and SSH log-tracing commands.
- Expanded `.htaccess` hardening rules to block the new ClickFix plugin folder suffix variants.
- Made the `.htaccess` hardening status check verify the current expected rule lines, so stale marker blocks can be refreshed.
- Updated Remediation, Hardening, and Settings copy to name the new render-hijacker variants.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.17`.
- Rebuilt the release archive as `wp-perf-shield-1.3.17.zip` with `wp-perf-shield/` as the package root.

## 1.3.16

- Reworked Hardening tab action feedback so successful Apply actions collapse into compact status badges.
- Hid Apply buttons after successful one-way hardening applies to avoid showing both an action and an "Applied" message.
- Added reusable `.wps-hardening-actions` and `.wps-action-status` styles for cleaner AJAX feedback.
- Reduced the generic right-aligned table action column width to improve hardening table balance.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.16`.
- Rebuilt the release archive as `wp-perf-shield-1.3.16.zip` with `wp-perf-shield/` as the package root.

## 1.3.15

- Added a targeted `wp-config.php` malware scanner for removable executable payloads, suspicious local/remote includes, option-loader restorers, and ClickFix markers.
- Added a Remediation button to clean known `wp-config.php` malware patterns.
- Added pre-write `wp-config.php.wps-clean.bak` backup creation with timestamped fallback names when a backup already exists.
- Added sanity checks before and after cleaning so the plugin refuses to write a file that no longer looks like a valid `wp-config.php`.
- Added `wp_config_cleaned` and `wp_config_clean_skipped` event log entries.
- Reset the stored `wp-config.php` clean baseline after a successful cleanup.
- Added `wp_config_cleaned` to clearance analytics.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.15`.
- Rebuilt the release archive as `wp-perf-shield-1.3.15.zip` with `wp-perf-shield/` as the package root.

## 1.3.14

- Reorganized the admin tabs into `Overview`, `Diagnostics`, `Forensics`, `Remediation`, `Hardening`, `Events`, and `Settings`.
- Added backward-compatible tab aliases so older `dashboard`, `analytics`, and `log` links resolve to the new tab names.
- Reduced the Overview tab to status, readiness, findings, and the newest eight events.
- Moved full event review into the Events tab.
- Moved active hostile IP block details from Settings into Diagnostics.
- Removed the now-unused Overview clear-log button handler.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.14`.
- Rebuilt the release archive as `wp-perf-shield-1.3.14.zip` with `wp-perf-shield/` as the package root.

## 1.3.13

- Added upload-pathway diagnostics for blocked malware uploads.
- Enriched `upload_blocked` events with request route, method, AJAX action, REST route, current WordPress user, roles, upload/install/manage capabilities, and referrer.
- Added a default-on strict ZIP upload pathway guard that blocks ZIP uploads unless they come from an administrator using trusted WordPress upload routes.
- Added `upload_path_blocked` events for ZIP uploads attempted through unsafe front-end, REST, admin-ajax, file-manager, or unauthenticated pathways.
- Extended hostile IP records with last pathway and last WordPress user context.
- Added pathway and user columns to the Active hostile IP blocks table.
- Added Analytics coverage for upload pathway blocks and corrected unique attacker IP counting before top-IP truncation.
- Added a Settings toggle for the ZIP upload pathway guard.
- Documented the upload pathway protection convention in `doc/ssot.md`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.13`.
- Rebuilt the release archive as `wp-perf-shield-1.3.13.zip` with `wp-perf-shield/` as the package root.

## 1.3.12

- Added an Analytics tab for operational attack and cleanup tracking.
- Added summary cards for attack attempts, blocked malware uploads, active hostile IP blocks, clearance actions, clean scans, and issue scans.
- Added a diagnostics posture panel for auto-delete status, hostile IP auto-block status, event log writability, cached findings, and log retention usage.
- Added latest-signal tracking for last attack, last clearance, unique attacker IPs, and current blocked-IP attempt totals.
- Added a recent activity table grouped by UTC day with attacks, clearances, clean scans, and issue scans.
- Added top attacking IP and top attack subject tables derived from retained event-log data.
- Added an event mix panel showing the most common event types in the retained log.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.12`.
- Rebuilt the release archive as `wp-perf-shield-1.3.12.zip` with `wp-perf-shield/` as the package root.

## 1.3.11

- Added hostile IP auto-blocking for confirmed malware upload attempts such as `wp-perf-analytics.zip`.
- Added a 7-day WordPress-level request block for IPs that attempt blocked malware uploads.
- Added `ip_auto_blocked`, `ip_block_refreshed`, and `ip_request_blocked` event log entries.
- Added admin email notification when a new malware-upload source IP is auto-blocked.
- Added a Dashboard count for active hostile IP blocks.
- Added a Settings tab control for enabling or disabling hostile IP auto-block enforcement.
- Added an Active hostile IP blocks table showing IP, attempts, last filename, last seen time, and expiry.
- Added a Danger Zone action to clear hostile IP auto-blocks.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.11`.
- Rebuilt the release archive as `wp-perf-shield-1.3.11.zip` with `wp-perf-shield/` as the package root.

## 1.3.10

- Fixed `wp-cron.php` forensics reporting clean current WordPress files as `unverified`.
- Added shared WordPress core checksum retrieval through the official `api.wordpress.org` checksum endpoint.
- Updated `wp-cron.php` integrity checks to compare against the installed WordPress version's official `wp-cron.php` MD5.
- Kept the legacy local known-clean hash list as a fallback when the WordPress checksum API is unavailable.
- Added WordPress version, expected MD5, and explanatory note rows to the Forensics `wp-cron.php integrity` panel.
- Reused the shared checksum helper in the broader WordPress core integrity check.
- Cleared the cached forensics report after one-click `wp-cron.php` replacement so the status cannot remain stale.
- Added plugin-version tracking in the admin screen to clear stale cached forensics once after an upgrade.
- Verified that WordPress `6.9.4` reports `wp-cron.php` MD5 `b1f6b11b2b5fa069df6cc6a22e3944dd`, matching the reported screenshot.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.10`.
- Rebuilt the release archive as `wp-perf-shield-1.3.10.zip` with `wp-perf-shield/` as the package root.

## 1.3.9

- Added Phase 1 controlled auto-remediation behavior.
- Added `auto_delete_enabled` to plugin settings, defaulting to enabled for existing behavior.
- Added a Settings tab checkbox for "Auto-delete confirmed malware artifacts."
- Updated `WPS_Scanner::run()` to respect the auto-delete setting and mark auto-delete findings as skipped when disabled.
- Added richer auto-delete audit log subjects with path, finding type, matched signature/hash when available, and severity.
- Added Dashboard scan result status rows for auto-delete completed or skipped-by-setting outcomes.
- Recorded the three-phase architecture plan and Phase 1 upgrade notes in `doc/upgrading.md`.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.9`.
- Rebuilt the release archive as `wp-perf-shield-1.3.9.zip` with `wp-perf-shield/` as the package root.

## 1.3.8

- Added Dashboard system readiness checks for plugin log writability, admin CSS asset availability, admin JS asset availability, and `wp-cron.php` writability.
- Added `WPS_Logger::can_write()` so the admin UI can report logger health before an operator depends on the event log.
- Added a `wp-cron.php.wps.bak` backup step before one-click `wp-cron.php` replacement.
- Updated the successful `wp-cron.php` remediation message to mention the backup file.
- Updated `readme.txt` and `doc/readme.md` for version `1.3.8`.
- Rebuilt the release archive as `wp-perf-shield-1.3.8.zip` with `wp-perf-shield/` as the package root.

## 1.3.7

- Fixed `wp-cron.php` remediation rejecting valid WordPress downloads because the clean 6.9.4 file does not contain the literal string `wp-cron.php`.
- Added `wps_is_clean_wp_cron()` to validate downloaded replacements using required core markers such as `wp-load.php`, `DOING_CRON`, and cron scheduling functions.
- Changed the replacement source order to try official WordPress SVN first, then the WordPress GitHub mirrors.
- Added the `wordpress-develop` source mirror fallback for `src/wp-cron.php`.
- Preserved malware indicator checks for downloaded replacements before writing to disk.
- Improved AJAX failure messages so failed URLs and validation failures are shown in the Remediation UI.
- Updated Remediation UI copy and manual fallback command to reference official WordPress source mirrors instead of only GitHub.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.7`.
- Rebuilt the release archive as `wp-perf-shield-1.3.7.zip` with `wp-perf-shield/` as the package root.

## 1.3.6

- Moved project Markdown documentation into the plugin-local `doc/` folder.
- Kept WordPress-compatible `readme.txt` at the plugin root.
- Renamed root `README.md` to `doc/readme.md`.
- Renamed root `CHANGELOG.md` to `doc/changelog.md`.
- Added `doc/upgrading.md` with upgrade, log migration, permissions, and package-root notes.
- Added `doc/ssot.md` as the packaging and release single source of truth.
- Updated `readme.txt` to describe the `doc/` folder layout.
- Bumped plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs to `1.3.6`.
- Rebuilt the release archive as `wp-perf-shield-1.3.6.zip` with `wp-perf-shield/` as the package root.

## 1.3.5

- Moved the structured event log into the plugin folder at `logs/events.php`.
- Changed `WPS_LOG_DIR` to use the plugin directory instead of writing new logs under `wp-content/wps-security`.
- Added `WPS_LEGACY_LOG_FILE` so the previous `wp-content/wps-security/events.php` file is treated as a migration source only.
- Added first-run migration from the previous `wp-content/wps-security/events.php` location when present.
- Added plugin-local `logs/index.php` and `logs/.htaccess` protection files.
- Updated `README.md` and `readme.txt` to document the new plugin-local log path and write-access requirement.
- Bumped plugin header, `WPS_VERSION`, and WordPress readme stable tag to `1.3.5`.
- Rebuilt the release archive as `wp-perf-shield-1.3.5.zip` with `wp-perf-shield/` as the package root.

## 1.3.4

- Added `WPS_URL` for WordPress asset enqueue URLs.
- Moved admin UI CSS into `assets/css/admin.css` and admin behavior into `assets/js/admin.js`.
- Replaced page-level inline scripts with enqueued WordPress assets and localized AJAX configuration.
- Delegated hardening action button behavior through the shared admin script.
- Cleaned visible admin status text to avoid broken glyphs in notices and badges.
- Updated plugin documentation to describe the new `assets/css` and `assets/js` structure.
- Bumped plugin header, `WPS_VERSION`, and WordPress readme stable tag to `1.3.4`.
- Rebuilt the release archive as `wp-perf-shield-1.3.4.zip` with `wp-perf-shield/` as the package root.

## 1.3.3

- Added MD5 and SHA-256 hashes for confirmed wp-perf-analytics XOR 60, 84, 113, and 114 builds.
- Added scanner coverage for malicious wp-content root drop-ins that restore `mu-plugins/session-manager.php` from `wp_session_tokens_config`.
- Added detection logic for the confirmed `advanced-cache.php` `_sm_ac_v5` self-healing loader pattern.
- Documented sample-derived persistence and ClickFix / Polygon payload indicators.

## 1.3.2

- Bumped plugin version and refreshed release package metadata.

## 1.3.1

- Added protected structured logging under `wp-content/wps-security/events.php`.
- Added safer path-boundary checks for deletion and scanner auto-remediation flows.
- Replaced remote `file_get_contents()` replacement downloads with WordPress HTTP API requests.
- Added validation for custom blocked slugs and MD5/SHA-256 custom hashes.
- Added SHA-256 custom hash matching in the blocker.
- Added multisite network-active plugin scrubbing.
- Updated the Settings UI copy for MD5 and SHA-256 support.
- Refreshed the admin interface with a modern minimalist visual layer:
  - gradient hero treatment,
  - rounded panels and controls,
  - cleaner tab navigation,
  - softer status surfaces,
  - pill-shaped buttons,
  - hover transitions,
  - responsive improvements for narrow screens.

## 1.3.0 and Earlier

- Real-time blocking for known wp-perf-analytics and session-manager malware variants.
- Hourly scheduled scans.
- Manual scan action from the WordPress admin.
- One-click remediation actions for known file, option, cron, login, theme, and user artifacts.
- Forensic reporting for upload traces, plugin timestamps, admin accounts, theme tampering, option anomalies, PHP checks, and WordPress core integrity.
- Hardening tools for `wp-config.php`, `.htaccess`, transients, sessions, and auth salts.
