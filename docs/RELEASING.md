# Releasing Unveil

Keep **git tags** and **package versions** aligned so the release label matches what’s inside the assets.

## Before creating a new release tag

1. **Bump version in the repo** so it matches the tag you’re about to push:
   - **CLI / PyPI:** `pyproject.toml` → set `version = "0.10.8"` (or your next version).
   - **Burp (optional):** `unveil-burp/build.gradle.kts` → set `version = "0.7.6"` when the extension changes; otherwise the JAR can stay 0.7.x.

2. **Commit and push:**
   ```bash
   git add pyproject.toml unveil-burp/build.gradle.kts  # and any other version refs
   git commit -m "release: bump version to 0.10.8"
   git push origin main
   ```

3. **Tag and push** (this triggers the release workflow):
   ```bash
   git tag v0.10.8
   git push origin v0.10.8
   ```

Result: tag **v0.10.8** and the Python package version **0.10.8** (and release assets) stay in sync. No more “tag says v0.10.7 but wheel says 0.10.4.”

## What the release workflow produces

- Python: `dist/*` (sdist + wheel) → uploaded to PyPI and attached to the GitHub release.
- Burp: `unveil-burp-*.jar` → attached to the release.
- Windows: `unveil-daemon.exe` and `unveil-burp-plug-and-play-windows.zip` → attached to the release.
