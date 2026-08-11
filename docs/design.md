# Kavach.ai Design Architecture

The interface of Kavach.ai is built to mimic state-of-the-art Security Operation Center (SOC) terminals. The frontend is built using a **React (Vite) single-page application (SPA)**. 

## 1. Core Principles

- **Premium Glassmorphism**: Surfaces should feel deep and layered, utilizing backdrop blurs (`backdrop-blur-md`, `backdrop-blur-xl`) over solid, flat hex colors. 
- **Absolute Sharpness**: We employ a strict `radius: 0px` globally to convey precision, technicality, and seriousness.
- **High-Contrast Dark Mode**: The default and only theme is dark mode, heavily inspired by modern IDEs and forensic terminals (e.g., Obsidian).

## 2. Global Design Tokens (Tailwind)

Our UI strictly adheres to the semantic scale defined in `index.css`. **Do not use ad-hoc hex values** (e.g., `bg-[#0d0d10]`).

| Token Context | CSS Variable | Tailwind Class | Usage Scenario |
| :--- | :--- | :--- | :--- |
| **Background** | `--color-background` | `bg-background` | Main application canvas, deep space (`#09090B`). |
| **Card / Surface** | `--color-card` | `bg-card` | Popovers, primary content containers (`#121215`). |
| **Muted / Secondary** | `--color-muted` | `bg-muted` | Inactive tabs, secondary pill backgrounds (`#1F1F23`). |
| **Border / Accent** | `--color-border` | `border-border` | Hairline dividers, strict 1px grid borders (`#27272A`). |
| **Primary (Brand)** | `--color-primary` | `text-primary`, `bg-primary` | Cyan/Blue electric glow for active states or critical KPIs. |

## 3. Typography Hierarchy

1. **Sans-Serif (Primary)**: `Inter` or `Outfit`
   - Used for all standard UI labels, buttons, headers, and tabs.
   - Headers: `tracking-tight`, `font-semibold` or `font-bold`.
   - Small labels: `tracking-widest`, `uppercase`, `text-[10px]`.
2. **Monospace (Secondary)**: `JetBrains Mono`
   - Exclusively used for bytecode slices, log streaming output, hex hashes, and file metrics.

## 4. Interactions and State

- **Snappy Hover States**: Use `transition-all duration-200` with subtle background shifts (`hover:bg-muted`) rather than aggressive color changes.
- **Data Loading**: Use pulsing glows (e.g. `animate-pulse`, `shadow-[0_0_8px_rgba(6,182,212,0.5)]`) rather than standard spinners to maintain the SOC terminal immersion.
- **Syntax Highlighting**: Implement custom highlight renderers for Smali code where malicious slices glow red (`text-destructive drop-shadow-md`) and benign slices glow blue.
