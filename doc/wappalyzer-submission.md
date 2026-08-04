# WP Perf Shield — technology profiler submission

Everything needed to get WP Perf Shield listed under **WordPress plugins** in Wappalyzer and the open-source forks. Prepared for 1.4.52, which added the marker this fingerprint matches on.

## What the marker looks like

With **Settings → Public identification** enabled, WP Perf Shield emits exactly one tag on front-end pages:

```html
<meta name="generator" content="WP Perf Shield" />
```

No version, deliberately. Nothing else about the plugin is visible to an anonymous visitor: its CSS and JavaScript enqueue only on its own settings screen, and the optional CSP header carries no identity.

The tag is off by default, so a fingerprint will only match sites whose operator has opted in.

## Route 1 — Wappalyzer (the commercial product)

Wappalyzer closed its repository in 2023, so there is no pull request route to the product any more. Submissions go through the form linked as *"Something wrong or missing?"* at the foot of any result panel:

**https://www.wappalyzer.com/technologies/suggest/**

Suggested field values:

| Field | Value |
| --- | --- |
| Name | WP Perf Shield |
| Website | https://github.com/menj |
| Categories | Security; WordPress plugins |
| Description | WordPress security scanner and endpoint detection platform. Blocks known malware plugin families at activation and upload, scans for web shells, cloaked injectors, doorway kits and credential exfiltration, and correlates events into incidents. |
| Detection — HTML | `<meta name="generator" content="WP Perf Shield"` |
| Implies | WordPress |
| Example URL | *(a site with the marker enabled)* |

An example URL matters more than anything else on that form. Without a live site emitting the tag there is nothing for them to confirm against.

## Route 2 — the open-source forks

These maintain the pre-paywall fingerprint set, accept pull requests, and feed a good deal of the tooling security researchers actually use.

- `tunetheweb/wappalyzer`
- `enthec/webappanalyzer`
- `dochne/wappalyzer`

Fingerprints are JSON, one file per initial letter — this entry belongs in `src/technologies/w.json`, keyed alphabetically.

```json
"WP Perf Shield": {
  "cats": [16, 87],
  "description": "WordPress security scanner and endpoint detection platform: blocks known malware plugin families, scans for web shells and cloaked injectors, and correlates events into incidents.",
  "icon": "WP Perf Shield.svg",
  "implies": "WordPress",
  "meta": {
    "generator": "WP Perf Shield"
  },
  "website": "https://github.com/menj"
}
```

Category identifiers in the shared taxonomy: `16` is Security, `87` is WordPress plugins. Check both against `src/categories.json` in the fork you are submitting to before opening the pull request, since numbering has diverged slightly between forks.

### The icon

An icon is required. WP Perf Shield ships its own, so submit that rather than drawing a new one — the file in the plugin is the canonical source and the two should not diverge:

```
assets/img/wp-perf-shield.svg
```

Rename the copy you submit to `WP Perf Shield.svg`, matching the technology name exactly, as the forks resolve icons by filename.

It is a 442-byte square SVG on a `0 0 64 64` viewBox: a shield silhouette in the plugin's own accent blue (`#1e6ba8`, the `--wps-blue` token) with three ascending bars knocked out in white. The bars are the plugin's lineage rather than decoration — it exists because malware impersonated performance plugins, and the name still carries it.

There is no text in the mark, no gradient and no filter, all of which fail at the 16 pixels these directories actually render. Bars are 8 units wide with 4-unit gaps so the gaps survive at that size; an earlier draft used narrower bars and they merged into a block.

If SVG is refused, a 32×32 PNG named `WP Perf Shield.png` rasterised from the same file. Do not redraw it by hand.

## Why the pattern is a meta tag rather than an asset path

Profilers commonly match WordPress plugins on script and stylesheet URLs containing `/wp-content/plugins/<slug>/`. That will never work here, because WP Perf Shield loads no front-end assets at all — the admin bundle is gated to `tools_page_wp-perf-shield`.

The meta tag exists solely so that recognition is possible without the plugin having to start doing front-end work it otherwise has no reason to do.

## What to expect afterwards

A fingerprint only populates a directory listing once the crawler finds sites in the wild emitting the marker. With the setting off by default, that needs a reasonable number of installs to opt in first. Expect the entry to be accepted well before it shows meaningful adoption figures.
