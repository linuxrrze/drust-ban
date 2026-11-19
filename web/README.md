# web

Placeholder for the SvelteKit frontend (milestone 3, see `../DESIGN.md` §9).

Plan:

- `npm create svelte@latest` with `@sveltejs/adapter-static` (SPA mode),
- TypeScript API client generated from the controller's OpenAPI spec,
- live updates via Server-Sent Events (`/api/v1/events`),
- `npm run build` output (`web/build`) embedded into `df2b-controller` via `rust-embed`.

Pages: Dashboard, Agents, Bans (with unban), IP detail, Policies/Jails,
Allowlist, Audit log.
