<!--
Thanks for contributing to open·kritt! Please fill this out so reviewers can move fast.
Keep PRs focused and small where possible.
-->

## What & why

<!-- What does this change do, and why? Link related issues (e.g. "Closes #123"). -->

Closes #

## Type of change

<!-- Check all that apply. Match your Conventional Commit type. -->

- [ ] `fix` — bug fix
- [ ] `feat` — new feature
- [ ] `docs` — documentation only
- [ ] `refactor` / `chore` / `test` / `ci`
- [ ] Breaking change (`!` / `BREAKING CHANGE:`)

## Affected components

- [ ] frontend
- [ ] backend
- [ ] engine
- [ ] database (migration)
- [ ] docs / CI / tooling

## Checklist

- [ ] Commits use [Conventional Commits](https://www.conventionalcommits.org/) (no empty `()` scope)
- [ ] Commits are **signed off** (`git commit -s`) — DCO
- [ ] Lint & format pass (`npm run lint` / `ruff check .`)
- [ ] Tests added/updated and passing where it makes sense
- [ ] Docs updated if behavior or config changed
- [ ] For DB changes: additive, `IF NOT EXISTS`-guarded migration in `database/init/`,
      Prisma schema updated, and `migrate.js` re-runs cleanly (idempotent)
- [ ] No secrets committed

## Notes for reviewers

<!-- Anything reviewers should focus on, screenshots for UI changes, testing steps, etc. -->
