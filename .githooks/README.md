# Git hooks

- **prepare-commit-msg** — Removes any `Co-authored-by:` line from commit messages so only the repo author is attributed.

To use these hooks in this repo (one-time per clone):

```bash
git config core.hooksPath .githooks
```

After that, every commit (from CLI or IDE) will have Co-authored-by lines stripped before the commit is created.
