# Repository Guidelines

## Project Structure & Module Organization
This repo is a Vite + React + TypeScript app with a small data-processing script layer.

- `index.tsx` and `App.tsx`: app entry and main UI composition.
- `components/`: UI modules (`IntelHUD.tsx`, `NetworkMap.tsx`, `SignalSearch.tsx`, `Terminal.tsx`).
- `utils/`: shared integrations (`firebase.ts`, `storage.ts`).
- `data/`: in-repo dataset sources (`dataset.ts`).
- `scripts/`: operational tooling (`pdf-to-database.ts`).
- Root config: `vite.config.ts`, `tsconfig.json`, `firebase.json`.

Generated/cache artifacts like `.pdf-chunks/` and `.ocr-cache.txt` are ignored and should not be committed.

## Build, Test, and Development Commands
- `npm install`: install dependencies.
- `npm run dev`: start local dev server.
- `npm run build`: create production bundle in `dist/`.
- `npm run preview`: serve the built output locally.
- `npm run convert-pdf`: run `scripts/pdf-to-database.ts` to process PDF content into database-friendly data.

Use Node.js and keep `GEMINI_API_KEY` in `.env.local` for local runs.

## Coding Style & Naming Conventions
- Language: TypeScript (`.ts`/`.tsx`) with React function components.
- Indentation: 2 spaces; keep imports grouped and readable.
- Components/types: `PascalCase` (e.g., `NetworkMap`, `SignalNode`).
- Variables/functions: `camelCase`; constants: `UPPER_SNAKE_CASE` for true constants only.
- Keep files focused: UI in `components/`, integration logic in `utils/`, scripts in `scripts/`.

No formatter/linter scripts are currently defined; match existing style in touched files and keep diffs small.

## Testing Guidelines
There is no automated test suite configured yet (`package.json` has no `test` script).

- For UI changes, run `npm run dev` and validate affected flows manually.
- For build safety, run `npm run build` before opening a PR.
- When adding tests, place them next to source as `*.test.ts` / `*.test.tsx` and add a project-level `npm test` script.

## Commit & Pull Request Guidelines
Recent history favors short, imperative commit subjects (for example, `Update pdf-to-database.ts`).

- Keep commits scoped to one logical change.
- Use clear subjects: `<Area>: <change>` (example: `scripts: improve PDF chunk parsing`).
- PRs should include: purpose, key files changed, manual verification steps, and screenshots for UI updates.
- Link related issues/tasks when available.

## Security & Configuration Tips
- Never commit secrets; keep API keys in `.env.local`.
- Review Firebase-related changes in `utils/firebase.ts` and `firebase.json` carefully.
- Treat PDF source files and derived data as potentially sensitive; share minimally.
