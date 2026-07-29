# Design

## Overview

Tawny-SOC is a dense operational dashboard aligned to the free [shadcndashboard](https://github.com/shadcndashboard/shadcndashboard) shell: inset sidebar + bordered content stage, neutral shadcn tokens, and metric cards with icon wells. Semantic blue/red/green accents stay reserved for investigation state and critical risk.

## Theme

Primary scene: analyst workspace for endpoint telemetry triage. Light and dark both ship via the header theme toggle (class on `html`).

## Color

Use OKLCH tokens matching shadcn neutral palette.

- Background / surface: neutral light or charcoal
- Sidebar + content: bordered inset panels on muted page background
- Foreground: near-black / near-white
- Accent: solid primary for active nav and primary actions
- Investigation: muted blue for analyst and AI work
- Critical: red only for true alert severity
- Success: green only for healthy ingestion or completed actions

## Typography

Use system UI fonts. Keep headings compact. Tables, rule metadata, IDs, and JSON snippets should use 12 to 14px text with monospace only for code or identifiers.

## Layout

shadcn-style full layout: sticky left sidebar with grouped nav, sticky shell header (theme), dense content grid of bordered panels. Metric cards use label/value/icon. Tables stay readable on laptop widths.

## Components

Icon buttons should use lucide-react. Controls should have stable heights, visible focus states, and clear disabled states. Badges pair color with text. Empty states should show the ingestion endpoint and expected Tawny configuration.
