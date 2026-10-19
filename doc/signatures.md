# Signature database (1.4.146)

WP Perf Shield can scan with a database in the file formats ClamAV uses. It is not ClamAV: there is no executable, nothing is unpacked, and nothing calls a binary. It reads the signature files so a database written for ClamAV, or written by hand, can be used on a WordPress host that cannot run ClamAV.

## Where the files go

Put the database files in `wp-content/wps-signatures/`. Nothing is scanned until that folder holds a usable database. The folder name can be changed with the `wps_signature_dir` filter. Files are read from the folder itself, not from sub-folders; symlinked files are not followed. Settings, Detection shows how many signatures loaded, how many were skipped and how many were rejected, with the first few rejected lines.

## What is read

| File | Content |
| --- | --- |
| `.hdb` | `MD5:size:name` |
| `.hsb` | `hash:size:name` with an MD5, SHA-1 or SHA-256 hash; size may be `*` |
| `.ndb` | `Name:Target:Offset:HexSignature[:minFL[:maxFL]]` |
| `.ldb` | `Name;Target description;Logical expression;Subsig0;Subsig1;...` |
| `.fp`, `.sfp` | hashes of files that are never reported |
| `.ign`, `.ign2` | signature names to ignore (the first field of each line) |

Hex signatures support `??`, `a?`, `?a`, `*`, `{n}` `{-n}` `{n-}` `{n-m}`, `[x-y]`, `(B)` `(L)` `(W)`, `(aa|bb)` and `!(aa|bb)`, and generic alternates with wildcards. Offsets: `*`, a number, `EOF-n`, and `n,max` floating. Logical expressions support `&`, `|`, parentheses, `=X`, `>X`, `<X` with an optional `,Y`, and the subsignature modifiers `::i`, `::w`, `::f`, `::a`. Target 0 matches the raw file; targets 3 (HTML) and 7 (text) match a lower-cased copy with whitespace collapsed (and, for 3, HTML comments removed), as ClamAV normalises them.

## What is left out

Counted as "skipped", not as errors: signatures for executables (PE, ELF, Mach-O), documents, images and mail; entry-point and section offsets; `Container`, `Intermediates`, `EntryPoint`, `NumberOfSections`, `IconGroup` and `HandlerType` conditions; macro and PCRE subsignatures; and the database types for other engines (`.mdb`, `.msb`, `.imp`, `.cdb`, `.idb`, `.ftm`, `.cbc`, `.yar`, `.cvd`, `.cld`). The signed `.cvd` and `.cld` bundles are not read; unpack them with `sigtool --unpack` first.

Two rules are stricter than ClamAV's. A body signature must hold at least eight fixed bytes (four per logical subsignature) and a run of three fixed bytes to anchor on, or it is rejected as too generic: this engine reports files on a live site and cannot lean on ClamAV's other conditions. And a logical signature may have at most 64 subsignatures.

## Who can change it

Anyone who can write to `wp-content/wps-signatures/` can make the scanner remove files (a hash signature for a plugin file, for example). Keep the folder as protected as `wp-config.php`: owned by the deploy user, not writable by the web server where you can avoid it.

## What happens on a match

- **Whole-file hash match:** exact. The file is reported as critical and removed (quarantined first, so it can be restored from Diagnostics).
- **Body or logical match:** reported, not removed, because a match is only as reliable as its signature. Settings, Detection, "Also remove files that match a body signature" turns removal on for these.
- **`PUA.`, `Heuristics.` and `Hunting.` names:** reported and never removed, whatever the setting.
- **False positives:** add the signature name to an `.ign2` file, or the file's hash to a `.fp` file. A listed hash is never reported.

Files in this plugin, the quarantine, the signature folder and symlinks are never read. Only code-like files are scanned (PHP, `.js`, `.html`, `.htm`, `.ini`, `.htaccess`), in the plugins, mu-plugins, themes and other wp-content folders, up to 25,000 files per scan.

## Limits

Up to 20,000 body signatures and 500,000 hash signatures are loaded; a file over 1 MB is checked by hash only; a database file over 32 MB is not read. Matching is bounded: each signature is anchored on its longest run of fixed bytes through a three-byte index before any pattern runs, `*` and `{n-}` split a signature into parts matched in order (never a backtracking `.*`), a pattern error counts as no match, and a file gets a three-second budget, after which the remaining signatures are not tried on it.

## Where the idea comes from

The formats and the normalisation follow the ClamAV manual (Signatures: body, extended, logical and hash formats), from the ClamAV 1.5.4 source package. The engine here is written for PHP; no ClamAV code is copied.
