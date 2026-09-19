# Contributing to open·kritt

Thanks for your interest in contributing! This guide covers how to set up the
polyglot dev environment, run and test each component, and get a change merged.

By participating you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

## TL;DR

```bash
# 1. Get the code
#    External contributors: fork on GitHub, then clone your fork:
git clone https://github.com/<you>/open-kritt && cd open-kritt

# 2. Configure model access and bring the whole stack up
./kritt setup
./kritt start

# 3. Make changes on a branch, commit with sign-off + Conventional Commits
git checkout -b feat/my-change
git commit -s -m "feat(frontend): add X"

# 4. Push and open a PR against main. CI must pass before it can merge.
```

## Project layout

open·kritt is a monorepo of cooperating services:

| Path             | What it is                                        | Stack               |
| ---------------- | ------------------------------------------------- | ------------------- |
| `frontend/`      | Web UI                                             | React + Vite (npm)  |
| `backend/`       | HTTP API                                           | Node + Express + Prisma (npm) |
| `engine/`        | Scan worker that runs the AI harnesses            | Python (pip + Ruff) |
| `database/`      | Postgres image + SQL migrations (`init/*.sql`)    | Postgres            |
| `executor-view/` | Executor viewer                                   | Python              |
| `scripts/`       | Repo tooling (e.g. `sync-version.mjs`)            | Node                |
| `docs/`          | Documentation                                      | Markdown            |

The whole product ships as **one version** — see [RELEASE.md](RELEASE.md).

## Running the stack

The simplest path is Docker Compose (above). For human-readable backend logs while
developing:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

You can also run a component on its own against the Dockerized Postgres.

The repository-local CLI requires Node.js 20+ and has no package-install step. Run
`./kritt help` to see its setup and startup commands; it creates `.env` only when one does
not already exist and never prints secret values. With no subcommand, `./kritt` opens the
full-screen Arrow-key menu; Ctrl+C exits it cleanly.

### Native development with Dockerized Postgres

Use this flow when you want hot reload for every service but do not want to install or
manage Postgres on the host. Commands assume the repository root is your current directory
and Python 3.11+ and Node.js 20+ are installed.

First start only the database and prepare shared directories. In every new terminal, set
`OPEN_KRITT_ROOT` with the first command before running that terminal's block:

```bash
docker compose up -d db
mkdir -p local_repos .data/engine-native .data/engine/credentials .data/codex .data/codex-accounts .data/claude
export OPEN_KRITT_ROOT="$(git rev-parse --show-toplevel)"
export DATABASE_URL='postgresql://open_kritt:open_kritt_password@127.0.0.1:5432/open_kritt?schema=public'
```

Install backend dependencies, generate the platform-native Prisma client, apply the
idempotent migrations, and start the API in terminal 1:

```bash
export OPEN_KRITT_ROOT="$(git rev-parse --show-toplevel)"
cd "$OPEN_KRITT_ROOT/backend"
npm install
npx prisma generate
npm run migrate
export LOCAL_REPOS_PATH="$OPEN_KRITT_ROOT/local_repos"
export OPEN_KRITT_CODEX_HOME_DIR="$OPEN_KRITT_ROOT/.data/codex"
export OPEN_KRITT_CODEX_ACCOUNTS_DIR="$OPEN_KRITT_ROOT/.data/codex-accounts"
export OPEN_KRITT_CODEX_RUNTIME_ACCOUNTS_DIR="$OPEN_KRITT_ROOT/.data/codex-accounts"
export OPEN_KRITT_CLAUDE_HOME="$OPEN_KRITT_ROOT/.data/claude"
export OPEN_KRITT_PROVIDER_CREDENTIALS_PATH="$OPEN_KRITT_ROOT/.data/engine/credentials/providers.json"
export OPEN_KRITT_ENGINE_RUNTIME_CONFIG_PATH="$OPEN_KRITT_ROOT/.data/engine-native/engine-runtime.env"
# Set only the non-secret presence flag matching the key in the engine terminal:
# export OPEN_KRITT_OPENAI_API_KEY_CONFIGURED=1
# export OPEN_KRITT_ANTHROPIC_API_KEY_CONFIGURED=1
# export OPEN_KRITT_OPENROUTER_API_KEY_CONFIGURED=1
npm run dev
```

Start Vite in terminal 2. Its same-origin `/api` requests are proxied to the native
backend:

```bash
export OPEN_KRITT_ROOT="$(git rev-parse --show-toplevel)"
cd "$OPEN_KRITT_ROOT/frontend"
cp -n .env.example .env
npm install
VITE_PROXY_TARGET=http://127.0.0.1:3002 npm run dev
```

Create the engine environment in terminal 3. Install the CLI for the harness you intend
to use (`@openai/codex` and/or `@anthropic-ai/claude-code`) on the host first. A native
engine cannot use the Compose service's nested Claude runner, so disable that mode.

```bash
export OPEN_KRITT_ROOT="$(git rev-parse --show-toplevel)"
npm install --global @openai/codex@0.144.6 @anthropic-ai/claude-code@2.1.215
cd "$OPEN_KRITT_ROOT/engine"
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt

export DATABASE_URL='postgresql://open_kritt:open_kritt_password@127.0.0.1:5432/open_kritt?schema=public'
export LOCAL_REPOS_PATH="$OPEN_KRITT_ROOT/local_repos"
export ENGINE_DATA_DIR="$OPEN_KRITT_ROOT/.data/engine-native"
export ENGINE_CODEX_HOME="$OPEN_KRITT_ROOT/.data/codex"
export CLAUDE_HOME="$OPEN_KRITT_ROOT/.data/claude"
export OPEN_KRITT_PROVIDER_CREDENTIALS_PATH="$OPEN_KRITT_ROOT/.data/engine/credentials/providers.json"
export ENGINE_CLAUDE_DOCKER_RUNNER=0
export ENGINE_WORKER_COUNT=2
export ENGINE_CODEX_AUTO_UPDATE=false
# Export one supported provider credential, or use an existing login home above.
# export OPENAI_API_KEY=...
# export ANTHROPIC_API_KEY=...
# export OPENROUTER_API_KEY=...
python -m open_kritt_engine
```

The container images pin npm `12.0.1`, Codex `0.144.6`, and Claude Code `2.1.215`.
Keep native harness versions aligned when debugging container-versus-host differences.

Finally, reuse the engine virtual environment for executor-view in terminal 4:

```bash
export OPEN_KRITT_ROOT="$(git rev-parse --show-toplevel)"
cd "$OPEN_KRITT_ROOT"
. engine/.venv/bin/activate
EXECUTOR_VIEW_DATABASE_URL='postgresql://open_kritt:open_kritt_password@127.0.0.1:5432/open_kritt' \
EXECUTOR_VIEW_ENGINE_DATA_DIR="$OPEN_KRITT_ROOT/.data/engine-native" \
EXECUTOR_VIEW_CODEX_HOME="$OPEN_KRITT_ROOT/.data/codex" \
EXECUTOR_VIEW_CLAUDE_HOME="$OPEN_KRITT_ROOT/.data/claude" \
python executor-view/server.py
```

The services are then available on frontend `5173`, backend `3002`, executor-view `8090`,
and Postgres `5432`, all on loopback by default. Stop the database when finished with
`docker compose stop db`; `docker compose down` also removes the container but preserves
the host-mounted data under `.data/postgres`.

### Frontend (`frontend/`)

```bash
cd frontend
npm install
npm run dev            # Vite dev server
npm run lint           # ESLint
npm run format         # Prettier (write)   /  npm run format:check
npm test               # Vitest
npm run build          # production build (Rollup)
```

### Backend (`backend/`)

```bash
cd backend
npm install
export DATABASE_URL=postgresql://open_kritt:open_kritt_password@localhost:5432/open_kritt?schema=public
npx prisma generate
npm run migrate        # apply database/init/*.sql (idempotent)
npm run dev            # start the API with --watch
npm run lint           # ESLint
npm run format         # Prettier
npm test               # node:test
```

### Engine (`engine/`)

```bash
cd engine
pip install -r requirements.txt
ruff check .           # lint
ruff format .          # format
pytest                 # tests (note: some currently require a writable /root home; see CI)
python -m open_kritt_engine   # needs DATABASE_URL, provider keys, and Docker isolation; see README
```

### Database (`database/`)

Schema changes are **additive, forward-only, idempotent** SQL files in
`database/init/`, applied by `backend/prisma/migrate.js`. Every statement must be
guarded (`CREATE ... IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, …) so re-running
migrations is always safe — CI runs `migrate.js` twice to prove it. After changing
the schema, update `backend/prisma/schema.prisma` to match and run
`npm run prisma:generate`.

## Code style & pre-commit hooks

- **JS/JSX**: ESLint + Prettier (`frontend/`, `backend/`).
- **Python**: Ruff (`engine/`).
- Shared editor settings live in `.editorconfig`.

Install the git hooks so issues are caught before you push:

```bash
pipx install pre-commit    # or: pip install pre-commit
pre-commit install
pre-commit run --all-files
```

## Versioning

The repo-root [`VERSION`](VERSION) file is the single source of truth. Don't edit a
component's version by hand — change `VERSION` and run:

```bash
node scripts/sync-version.mjs        # propagates to package.json files + engine
node scripts/sync-version.mjs --check   # what CI runs; fails on drift
```

Normal contributions rarely touch `VERSION` — version bumps happen through the
release process (see [RELEASE.md](RELEASE.md)).

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/); release notes
and version bumps are generated from them.

```
<type>[optional scope]: <description>

feat(frontend): add severity-ranker picker
fix(engine): handle empty dependency list
docs: expand deployment guide
```

- Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`.
- **Scope is optional, but never use empty parentheses** — `feat():` is invalid and
  breaks release tooling. Write `feat:` or `feat(scope):`.
- `feat!:` or a `BREAKING CHANGE:` footer marks a breaking change.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/) — a
lightweight statement that you wrote (or have the right to submit) the contribution.
There's no CLA to sign; you keep your copyright.

Add a `Signed-off-by` line to **every** commit by committing with `-s`:

```bash
git commit -s -m "fix(backend): correct pagination"
```

This appends, using your real name and email:

```
Signed-off-by: Your Name <you@example.com>
```

Forgot to sign off? Amend the last commit with `git commit --amend -s --no-edit`, or
for a whole branch: `git rebase --signoff main`. A DCO check runs on every PR.

## Pull requests

We use the **fork & pull** model. `main` is protected, so **all** changes — from
everyone — land through a PR that passes CI; nobody pushes to `main` directly.

- **External contributors:** fork the repo, push your branch to your fork, and open
  the PR from there. (Fork PRs run with a read-only token and no repo secrets — a
  GitHub security feature — which is fine for our checks.)
- **Team members with write access:** you don't need a fork. Push a branch to the
  repo (`git push -u origin feat/my-change`) and open the PR from it.

Then:

1. Branch off `main` (in your fork, or in the repo if you're on the team).
2. Keep PRs focused; add tests and update docs where it makes sense.
3. Ensure everything passes locally: lint, tests, build.
4. Open the PR against `main` and fill in the template.
5. **CI must be green** — it's a required check, so `main` only ever receives
   CI-passing code (see the branch-protection notes in [RELEASE.md](RELEASE.md)).
6. A code owner (see [CODEOWNERS](.github/CODEOWNERS)) reviews and merges.

Not sure where to start? Look for issues labeled **good first issue** / **help
wanted**, or open a Discussion to propose an idea before building it.

## Reporting bugs & security issues

- **Bugs / features:** open an issue using the templates.
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md) (private reporting).

Thanks for helping make open·kritt better! 💚
