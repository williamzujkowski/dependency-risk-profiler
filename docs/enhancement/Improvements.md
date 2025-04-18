Improvements.md

Below are concise, copy‑and‑pasteable prompts you can feed into a code‑generation LLM to implement each of the recommended improvements:

---

### 1. Migrate to `pyproject.toml`  
```text
Prompt: Refactor the repository to consolidate all configuration into a single `pyproject.toml`.  
- Move package metadata from `setup.py`, `setup.cfg`, and `MANIFEST.in` into `[project]` or `[tool.poetry]` sections.  
- Add a `[build-system]` table specifying the build backend (e.g. `setuptools.build_meta` or `poetry.core.masonry.api`).  
- Include dev‑dependencies under `[project.optional-dependencies.dev]` (or `[tool.poetry.dev-dependencies]`).  
- Configure Black, isort, Flake8, and Mypy under `[tool.black]`, `[tool.isort]`, `[tool.flake8]`, and `[tool.mypy]`.  
```

---

### 2. Remove Legacy Configuration Files  
```text
Prompt: Delete obsolete packaging and config files now covered by `pyproject.toml`.  
- Remove `setup.py`, `setup.cfg`, `MANIFEST.in`.  
- Delete standalone `.flake8` and `mypy.ini`.  
- Archive or drop any `install.sh`/`install.bat` wrappers if installation is fully handled by `pip install .`.  
```

---

### 3. Add a GitHub Actions CI Workflow  
```text
Prompt: Create `.github/workflows/ci.yml` to run on every push and pull request on `main`.  
- Use `actions/checkout@v3` and `actions/setup-python@v4` to install Python 3.8–3.11.  
- Install dependencies with `pip install .[dev]`.  
- Run `pre-commit run --all-files`, `flake8 src/`, `mypy src/`, and `pytest --junitxml=report.xml --cov=src`.  
- Upload coverage report as an artifact.  
```


---

### 4. Configure Dependabot for Dependency Updates  
```text
Prompt: Add `.github/dependabot.yml` to enable automatic version updates.  
- Monitor `pip` ecosystem weekly.  
- Target directory `/`.  
- Auto‑merge patch-level updates.  
```


---

### 5. Enable Pre‑commit Hooks  
```text
Prompt: Define `.pre-commit-config.yaml` with hooks for Black, isort, Flake8, and Mypy.  
- Use `repo: psf/black`, `repo: pre-commit/mirrors-isort`, `repo: pycqa/flake8`, `repo: mypy/mypy`.  
- Enforce formatting and static checks before every commit.  
```


---

### 6. Integrate Coverage Reporting  
```text
Prompt: Update `pytest.ini` or `pyproject.toml` to include `pytest-cov` settings.  
- On test runs, generate HTML and XML coverage reports.  
- Fail CI if overall coverage falls below 90%.  
- Add a coverage badge to `README.md`.  
```


---

### 7. Add Bandit Security Scanning  
```text
Prompt: In the CI workflow, insert a step to run `bandit -r src/ -f html -o bandit.html`.  
- Configure `.bandit.yml` to adjust severity thresholds.  
- Fail the build on any high‑severity findings.  
```


---

### 8. Automate Releases via GitHub Actions  
```text
Prompt: Create `.github/workflows/release.yml` triggered on version tag pushes (`v*.*.*`).  
- Use `actions/create-release@v1`, build wheel and sdist, then `actions/upload-release-asset@v1`.  
- Publish to PyPI using `pypa/gh-action-pypi-publish@release-v1`.  
```


---

### 9. Generate a Changelog Automatically  
```text
Prompt: Add a step in `release.yml` to run `github-changelog-generator —future-release v$GITHUB_REF_NAME`.  
- Output to `CHANGELOG.md` before creating the GitHub release.  
```


---

### 10. (Optional) Adopt Poetry for Packaging  
```text
Prompt: Replace setuptools with Poetry:  
- Run `poetry init` to create `pyproject.toml`.  
- Define project dependencies and dev-dependencies.  
- Update CI to use `poetry install` and `poetry run`.  
```


