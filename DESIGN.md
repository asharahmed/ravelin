# Ravelin Design System

A clean, confident, restrained identity for a vulnerability SLA & compliance tracker. The
goal is a professional security tool with a few deliberate, distinctive choices — **not** a
template, and not an over-themed costume. Distinction comes from typography, a meaningful
colour model, and clean structure, applied with restraint.

Tokens: `src/Ravelin/wwwroot/ledger.css`. Component layout: scoped `*.razor.css`. Fonts:
`src/Ravelin/Components/App.razor`.

## Typography

A slab-serif-led system, chosen to avoid the obvious defaults — not the editorial
serif-headline-plus-sans pairing (Caslon/Fraunces/Newsreader), not the designer grotesque
(Bricolage/Space Grotesk/Geist), and not a typewriter gimmick. A slab serif reads like an
*engineering / technical-compliance document*, which is exactly the product's job.

| Role | Typeface | Why |
|------|----------|-----|
| Display, titles, figures, wordmark | **Zilla Slab** | Mozilla's engineered slab serif — serious, technical, document-like, and uncommon. The distinctive voice; the slab leads. |
| UI, labels, body, data | **Hanken Grotesk** | A quiet, readable sans workhorse so the slab carries the character. Tabular figures for data. |
| Code identifiers | **Geist Mono** | Used *semantically* for actual code: CVE ids, `group:artifact version`, project slugs. Monospace because the content is monospace data, not for theme. |

Display/figures use Zilla Slab; tabular data uses Hanken with `tabular-nums`; labels are quiet
uppercase Hanken (600, light tracking). Three families, each with a specific justified job.

**Self-hosted, not a CDN default.** All three families are served from `/fonts` (WOFF2,
latin subset, `font-display: swap`, with the two render-critical weights preloaded) — owned and
delivered by Ravelin, with no third-party font CDN. See `wwwroot/fonts.css`.

**Brand mark — a bastion salient, not a letter.** The mark *is* the namesake: a *ravelin* is a
triangular detached fortification that shields a fort's wall. So the logo is a **bastion salient**
— a sharp barbed arrowhead with a fletch-notched gorge — which simultaneously signals defence
(the product) and an **up-trend** (compliance improving). It is paired with a custom
**monoline-geometric "RAVELIN" wordmark** drawn as SVG letterforms (constructed, angular,
technical — matching the engineered slab voice). Both are hand-built assets in `NavMenu.razor`;
the mark fills `var(--brand)` and the wordmark inherits `currentColor`, so both invert with the
theme. The same salient is the favicon (an inline `<svg>` that swaps oxblood→cream via
`prefers-color-scheme`) and the iOS app icon (cream salient on a full-bleed oxblood field).

## Colour — meaning, not decoration

Warm paper + blue-black ink. **No green.** Status is carried by ink, with one rule that ties
to the domain: **red = breached/overdue** ("in the red"), amber = aging/due-soon, black ink =
within SLA. Severity is an earthen ink scale, never bright UI colour. The single brand accent
is an **oxblood** seal (also links). Dark mode is a coherent deep-ink inversion.

Accessibility: `--ink-faint` is tuned so small labels clear **WCAG AA (4.5:1)** on paper;
large status figures clear AA large-text (3:1). Verified by measuring sRGB contrast on the
live build.

## Structure — clean, restrained

- **Compliance balance** (a labelled figure + a simple bar: compliant filled, breached
  remainder in red) instead of a radial gauge.
- **Balance sheet** hero: the balance beside ruled **Totals** line items — not a stat-card
  quadrant.
- **Dot leaders** (`Critical · · · · · 3`) for breakdowns — a clean typographic device.
- **Flat, square sheets** defined by a single hairline rule (no shadows, no rounded "cards").
- **Squared status tags** for severity/SLA; an **oxblood bastion salient** for the mark.
- One focal animation per view (the balance fill); all motion honours
  `prefers-reduced-motion`. Single hairline rules throughout (no decorative double-rules,
  ruled-paper textures, folio numbering, or other skeuomorphic affectation).

## What it is / isn't

It **is**: a clean professional tool with a serif display voice, a meaningful red-for-breach
colour model, and restrained structural choices (balance, totals, dot leaders).

It is **not**: a generic dashboard (no radial gauge, stat-card quadrant, bar meters, dark
SaaS rail, green=good, Inter/Plex), and **not** an over-themed skeuomorphic costume (no fake
ruled paper, manila folders, typewriter type, rubber-stamp hatching, or folio theatrics —
these were tried and removed for reading as costume rather than design).

## Tokens — the complete foundation

An established system is defined by a consistent, documented token set; every value below is a
CSS custom property in `ledger.css`, used rather than hand-typed.

- **Colour** — surfaces, the three ink tiers, lines, the oxblood brand, and `--red` / `--amber`
  status + the severity scale. No green.
- **Type** — `--font-display` (Zilla Slab), `--font-text` / `--font-mono` (Hanken Grotesk),
  `--font-code` (Geist Mono).
- **Spacing** — a 4px scale, `--space-1` (4px) … `--space-7` (64px).
- **Shape** — `--radius` / `--radius-sm` = 0 (squared, letterpress).
- **Motion** — one entrance easing `--ease` and one symmetrical `--ease-inout`; three durations
  `--dur-fast` (.12s) / `--dur` (.2s) / `--dur-slow` (.5s). Every animation is gated behind
  `prefers-reduced-motion`.

## Living style guide

The system is published as a living component reference at **`/styleguide`** (public, no
auth) — the single source of truth, rendered from the real tokens and components. It covers:

- **Tokens**: every colour swatch with its CSS variable (surfaces, ink tiers, accent/status,
  severity scale).
- **Type**: the full scale — Zilla Slab display/title/figures, Hanken Grotesk prose/label,
  Geist Mono code.
- **Components in every state**: buttons (default / hover / focus / disabled), status tags
  (all severity + SLA variants), form fields (default / focus / invalid / disabled / select),
  data display (balance, dot leaders, stat figure), and feedback/loading (inline error,
  spinner, skeleton).
- Renders coherently in both light and the "night" dark theme.

## Verification

Changes are checked on the live deployment: computed `font-family` and colour from the DOM,
WCAG contrast via canvas sRGB, a 390px mobile pass (no overflow; sheets stack; sidebar
collapses), the `/styleguide` component matrix across light/dark, and a non-happy-path state
sweep (validation, auth error, empty filter, triage editor, server error, 404).
