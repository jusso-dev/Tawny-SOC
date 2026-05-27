# Design

## Overview

Tawny-SOC is a dense operational dashboard. It borrows Tawny's warm dark neutrals and amber action color, then adds restrained blue and red semantic accents for investigation state and critical risk. The interface should feel closer to a detection engineering workbench than a marketing analytics page.

## Theme

Primary scene: a security engineer is watching endpoint telemetry and triaging alerts beside terminal windows during an evening investigation. Dark mode is the default because it reduces glare and fits the operational context.

## Color

Use OKLCH tokens. Avoid pure black and pure white.

- Background: warm graphite
- Sidebar: slightly lifted charcoal
- Panel: quiet warm gray
- Foreground: warm near-white
- Accent: amber for primary action and active navigation
- Investigation: muted blue for analyst and AI work
- Critical: red only for true alert severity
- Success: green only for healthy ingestion or completed actions

## Typography

Use system UI fonts. Keep headings compact. Tables, rule metadata, IDs, and JSON snippets should use 12 to 14px text with monospace only for code or identifiers.

## Layout

Use a persistent left navigation and a dense responsive dashboard grid. Avoid nested cards. Use full-width bands and bordered panels for operational views. Tables should remain readable on laptop widths.

## Components

Icon buttons should use lucide-react. Controls should have stable heights, visible focus states, and clear disabled states. Badges pair color with text. Empty states should show the ingestion endpoint and expected Tawny configuration.
