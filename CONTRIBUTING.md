# Contributing

- One module per branch, merged by pull request. Keep commits small.
- Use conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `security:`.
- Before pushing, run `npm run check`.
- Document any security decision in `docs/security-decisions.md` as you make it.
- Never commit secrets. When the project starts using environment variables (API keys, database URLs), only a `.env.example` template belongs in Git — real `.env` files never do.
