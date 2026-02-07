# CLAUDE.md

## Project Overview

DarkTrace is an interactive cybersecurity learning platform for CompTIA Security+ (SY0-701) certification. It teaches through gamified investigation missions rather than traditional lectures. Built with React + TypeScript, deployed via Firebase Hosting.

## Tech Stack

- **Frontend:** React 18, TypeScript 5.8, Vite 6
- **Styling:** Tailwind CSS (loaded via CDN in `index.html`)
- **Animations:** Framer Motion
- **Icons:** Lucide React
- **Backend/DB:** Firebase (Firestore, Auth, Analytics, Hosting)
- **AI:** Google Generative AI API (`@google/generative-ai`)

## Project Structure

```
components/     # React UI components (IntelExplorer, NetworkMap, Terminal, etc.)
data/           # Game datasets (quiz scenarios, investigation missions)
utils/          # Shared integrations (firebase.ts, storage.ts)
scripts/        # Build/tooling scripts (PDF processing)
App.tsx         # Main app component
index.tsx       # React entry point
types.ts        # TypeScript type definitions
```

## Build & Dev Commands

```bash
npm install          # Install dependencies
npm run dev          # Start dev server (localhost:3000)
npm run build        # Production build to dist/
npm run preview      # Serve built output locally
npm run convert-pdf  # Process PDF study materials into data
```

Requires Node.js 20. Set `GEMINI_API_KEY` in `.env.local` for local development (see `.env.local.example`).

## Coding Conventions

- **Language:** TypeScript (`.ts`/`.tsx`) with React function components
- **Indentation:** 2 spaces
- **Components/types:** `PascalCase` (e.g., `NetworkMap`, `SignalNode`)
- **Variables/functions:** `camelCase`
- **Constants:** `UPPER_SNAKE_CASE` for true constants only
- **File organization:** UI in `components/`, integration logic in `utils/`, scripts in `scripts/`
- **Path alias:** `@/*` maps to the project root
- No formatter or linter is configured; match existing style in touched files

## Testing

No automated test suite is configured. Validate changes by:

1. Running `npm run dev` and manually testing affected flows
2. Running `npm run build` to verify the production build succeeds before opening a PR

## Commit Style

- Short, imperative subjects: `<Area>: <change>` (e.g., `scripts: improve PDF chunk parsing`)
- One logical change per commit

## Important Notes

- Never commit secrets; API keys belong in `.env.local`
- Generated artifacts (`.pdf-chunks/`, `.ocr-cache.txt`) are gitignored and must not be committed
- Firebase config lives in `utils/firebase.ts` and `firebase.json` — review changes carefully
- CI/CD deploys to Firebase Hosting on push to `main` via GitHub Actions
