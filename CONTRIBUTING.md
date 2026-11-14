# Contributing to the VeilCore registry

Thanks for looking. The most useful contribution right now is an attack: a way to make a
record, a licence, a date or a check say something that isn't true, or to make this registry
show something its holder did not choose to show.

## Reporting

- **Security problems:** privately, never in a public issue. See [SECURITY.md](SECURITY.md).
- **Bugs, unclear docs, wrong wording:** open an issue with the commit, what you did, what
  you expected and what happened. Wording that claims more than the code does counts as a
  bug.

## Running the tests

Node 24 (`.nvmrc` pins 24.11.1). From the repository root:

```bash
npm ci
npm test        # sets VEILCORE_OTS=off; no calendar or block explorer is contacted
npm start       # optional: the registry on PORT (default 8787), then GET /health
```

The tests use in-memory and temporary databases and need no tokens or settings. CI
(`.github/workflows/ci.yml`) runs `npm ci`, `npm test` and
`npm audit --omit=dev --audit-level=high` on every pull request to `main`.

The record format, its specification and conformance vectors live in
[veilcore-sdk](https://github.com/hunterincoming/veilcore-sdk); the website and app, the
contracts and the fee sponsor in [veilcore](https://github.com/hunterincoming/veilcore).

## Pull requests

Branch from `main`, keep each pull request to one change, include the test that shows it,
and make sure CI passes. **Merging to `main` deploys the production registry**, so only the
maintainer merges.

- **Show it, then fix it.** A weakness is first shown as a failing test, then fixed or
  documented. The attack stays in the suite (`test/attack-*.test.mjs` and the rest).
- **No secrets** in code, tests, issues or commit messages: no tokens, keys, seeds or
  project ids. Tests use made-up values.
- **No real names.** Tests, fixtures, docs, comments and commit messages use made-up people
  and organisations (`Example Lab`, `lab.example`). No customer, pilot or adoption claims.
- **Say only what is true.** A record shows *prior possession* by a date, never ownership.
  Say precisely what is live where: on mainnet, on a test network, or not built.
- **Dependencies by hand.** No `npm audit fix`; a lockfile change is made one entry at a
  time and read in review (`.github/dependabot.yml`). The vendored contract in
  `lineage/managed` is not changed by a pull request.
- **History is not rewritten.** No force-pushes to a shared branch.

Much of this code was written with an AI coding assistant. The same tests and reviews apply
to every change, whoever wrote it.

Contributions are licensed under Apache-2.0, the licence of this repository. Please follow
the [Code of Conduct](https://github.com/hunterincoming/veilcore/blob/main/CODE_OF_CONDUCT.md).
