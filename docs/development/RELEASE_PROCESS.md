# Release Process

This document explains the release process for the Dependency Risk Profiler project.

## Automated Release Pipeline

The project uses GitHub Actions for an automated CI/CD pipeline to handle releases. The workflow is defined in `.github/workflows/release.yml` and is triggered when a new version tag is pushed to the repository.

## Creating a New Release

To create a new release, follow these steps:

### 1. Prepare for Release

1. Ensure all intended changes are merged to the `main` branch
2. Make sure all tests pass and the CI pipeline is green
3. Update the version number in `src/dependency_risk_profiler/__init__.py`:

```python
__version__ = "X.Y.Z"  # Update to the new version
```

4. Commit this change with a message like `"chore: bump version to X.Y.Z"`

### 2. Create and Push a Version Tag

Create a new tag following [Semantic Versioning](https://semver.org/) principles:

- **Patch releases** (bug fixes that don't change the API): `vX.Y.Z` → `vX.Y.Z+1`
- **Minor releases** (backward-compatible new features): `vX.Y.Z` → `vX.Y+1.0`
- **Major releases** (breaking changes): `vX.Y.Z` → `vX+1.0.0`

```bash
# Example for a patch release
git tag v0.2.1
git push origin v0.2.1

# Example for a minor release
git tag v0.3.0
git push origin v0.3.0

# Example for a major release
git tag v1.0.0
git push origin v1.0.0
```

### 3. Monitor the Release Workflow

Once the tag is pushed, the release workflow will automatically:

1. Build the Python package (wheel and sdist)
2. Generate release notes based on commits since the last release
3. Create a GitHub Release with the generated notes
4. Upload the package files to the GitHub Release
5. Publish the package to PyPI
6. Update the documentation site

You can monitor the workflow's progress in the "Actions" tab of the GitHub repository.

### 4. Verify the Release

After the workflow completes successfully:

1. Check that the new version is available on PyPI:
   ```bash
   pip install dependency-risk-profiler==X.Y.Z
   ```

2. Verify the GitHub Release was created with the correct artifacts:
   - Visit the "Releases" page on GitHub
   - Ensure both the wheel and source distribution are attached

3. Confirm the documentation site has been updated:
   - Visit https://williamzujkowski.github.io/dependency-risk-profiler/
   - Check that any documentation changes are reflected

## Release Requirements

To perform releases, the following requirements must be met:

### PyPI Publishing

A PyPI API token must be stored as a repository secret named `PYPI_API_TOKEN`. This token should have permission to publish to the PyPI project.

To create a new token:
1. Log into PyPI
2. Go to Account Settings → API tokens
3. Create a new token with upload permissions for the `dependency-risk-profiler` project
4. Add the token as a repository secret in GitHub (Settings → Secrets → Actions → New repository secret)

### GitHub Permissions

The workflow requires write permission to:
- Repository contents (to create releases)
- GitHub Pages (to deploy documentation)

These permissions are configured in the workflow file and should not require additional setup.

## Handling Release Failures

If the release workflow fails:

1. Check the workflow logs to identify the issue
2. Fix the problem in a new PR to the `main` branch
3. If needed, delete the failed GitHub tag:
   ```bash
   git tag -d vX.Y.Z
   git push --delete origin vX.Y.Z
   ```
4. Try the release process again with the fixes in place

## Release Notes

Release notes are automatically generated from commit messages between the previous and new tag. To ensure high-quality release notes:

1. Use clear, descriptive commit messages
2. Follow the [Conventional Commits](https://www.conventionalcommits.org/) format when possible:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation changes
   - `chore:` for maintenance tasks
   - `refactor:` for code refactoring
   - `test:` for test additions or modifications

## Post-Release Tasks

After a successful release:

1. Announce the release in appropriate channels
2. Update the project roadmap or milestones, if applicable
3. Start planning the next release cycle