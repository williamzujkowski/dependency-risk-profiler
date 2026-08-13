# What everyone else measures, and what anyone has validated

**Status:** reference. Written because this project has spent ten studies
measuring its own instrument and had recorded only one comparable published
result. The question — *what do the other tools measure, what have they
deduced, and how does our work compare?* — turns out to have a sharper answer
than expected.

---

## 1. OWASP's two tools are not doing what this tool does

Worth stating first, because OWASP is the obvious place to look and it is the
wrong comparator.

| tool | what it actually measures |
|---|---|
| [**Dependency-Check**](https://owasp.org/www-project-dependency-check/) | Matches dependencies to CPE identifiers and reports the linked CVEs. Pure software composition analysis: *what known vulnerabilities are in here now.* No health, maintenance or forecast component at all. |
| [**Dependency-Track**](https://owasp.org/www-project-dependency-track/) | Continuous SBOM analysis. Its "Inherited Risk Score" is a weighted severity sum: `(critical×10) + (high×5) + (medium×3) + (low×1) + (unassigned×5)`. |

Both are **lagging indicators by construction.** They aggregate disclosed
vulnerabilities; neither attempts to say anything about a package with no
advisories against it. That is a different product from a maintenance-risk
forecast, and it is a much easier one to be right about.

Two details worth carrying:

- Dependency-Track's score is a severity aggregate, and its own maintainers
  describe it as closer to a weighted severity count than a risk model. There
  is a long-standing request in its tracker simply asking for the calculation
  to be **documented** ([issue #2475](https://github.com/DependencyTrack/dependency-track/issues/2475)).
  A published score whose formula is not written down is the same defect class
  this repo keeps finding in itself.
- `unassigned` severity is weighted **5** — equal to `high`. That is a
  defensible fail-closed choice and it is exactly the choice this tool makes
  when it counts a no-severity advisory at every threshold.

**So the leading-indicator space is occupied by Scorecard, Snyk Advisor,
Libraries.io and deps.dev — not by OWASP.**

---

## 2. What the actual comparators measure

| tool | inputs | output |
|---|---|---|
| [**OpenSSF Scorecard**](https://scorecard.dev/) | 20 checks (18 default, 2 experimental) over repository practice: branch protection, signed releases, CI tests, dependency update tooling, fuzzing, SAST, maintenance | 0–10 per check, aggregate 0–10 |
| **Snyk Advisor** | **Popularity** (downloads, stars), **Maintenance** (release cadence, commit frequency, last commit/release), **Security**, **Community** | 0–100, bucketed *healthy / sustainable / risky* |
| **Libraries.io SourceRank** | Repository presence, README, licence, releases, dependent counts, recency | integer rank |
| **deps.dev** | Dependency graph + Scorecard + advisories, cross-ecosystem | aggregate view |

Two observations that matter for this project.

**Snyk Advisor treats popularity as a first-class scoring component.** Downloads
and stars are one of its four pillars. This repo's central negative result is
that **download count beat its own composite on every outcome tried** —
including, most recently, at the bottom bucket (`what-this-tool-is.md` §3). On
that evidence Snyk's inclusion of popularity looks like the better modelling
choice, and this tool's decision to exclude it looks like the mistake.

**Scorecard's checks and this tool's repository-derived block are close to the
same list** — branch protection, signed commits, CI, dependency update tooling,
security policy. This repo retired `signed_commits` and `branch_protection`
(#394) after measuring that one was a merge-tooling detector and the other
could not observe the API property it was named for. Those findings are about
*this* implementation, but the checks are Scorecard's checks, so they are worth
reading as questions about the shared design rather than local bugs.

---

## 3. What anyone has actually validated

This is the short section, and that is the finding.

| study | what it tested | result |
|---|---|---|
| [Zahan et al., ICSE-SEIP 2023](https://arxiv.org/abs/2210.14884) | Scorecard practice scores vs reported vulnerability counts, 2,422 npm packages | **R² 0.09–0.12, and the sign was positive** — more good-practice indicators correlated with *more* reported vulnerabilities (~+0.5 per unit), attributed to popularity confounding |
| [SourceBroken (2025)](https://arxiv.org/pdf/2512.24400) | Libraries.io SourceRank vs known-malicious PyPI packages | Many malicious packages retained **high** SourceRank; the metric lacks discriminative validity |
| [Predicting Abandonment (2025)](https://arxiv.org/abs/2507.21678) | Behavioural/timeline features vs abandonment, 115,466 GitHub repos | **C-index 0.846** — but no popularity or download baseline reported |
| EPSS (exploit prediction) | Exploit probability vs observed exploitation | Fewer than 20% of CVEs exceeded a 50% predicted chance |

**What is conspicuously absent from the literature:** a *prospective*,
pre-registered validation of any shipped package health score against a future
outcome, with a popularity baseline. We could not find one.

The two negative results above are the closest analogues to this project's own,
and both point the same way: **published health scores, when tested, have not
held up.** Zahan's came out *backwards*; SourceBroken's failed to separate
malware from legitimate packages.

The abandonment paper is the interesting contrast. Its C-index of 0.846 is far
above anything measured here — but it uses rich repository-event history
(115k repos, timeline behavioural features) rather than registry metadata, and
**it reports no comparison against download count.** That is precisely the gap
this project fell into and then measured its way out of. A 0.846 without a
popularity baseline is not yet known to beat a free number.

---

## 4. How this project's work compares

**Where it is behind:** the composite loses to download count, and Snyk already
scores popularity directly. On present evidence a user is better served by the
free baseline than by this tool's ranking.

**Where it is genuinely distinctive**, and this is not self-flattery because
the distinctiveness is entirely about method rather than results:

1. **Pre-registered falsification lines, committed before the data.** Zahan's
   and SourceBroken's are post-hoc analyses of other people's scores. This
   project registers what would refute it and then publishes when the line
   fires — five times so far.
2. **A comparator on every claim.** The single most consequential discipline
   here has been forcing every result to beat download count. That is what
   killed the README's original thesis, the LOW-bucket claim, and the
   provenance signal. The literature above mostly does not do this.
3. **Negative results published in full**, including four self-corrections and
   a registry of withdrawn figures with a test that fails the build if a
   withdrawn number reappears unannotated.
4. **A prospective registration with a 2027-08 readout** — which, if the search
   above is right, will be the first of its kind for a shipped health score.

The honest summary: **this project's scores are not better than anyone else's.
Its evidence about its scores is better than anyone's evidence about theirs.**

---

## 5. The gap worth filling: cross-ecosystem computability

Every measurement in §3, and every measurement in this repo, is **single
ecosystem** — npm or PyPI. Nobody has published the cross-ecosystem version of
the most basic question:

> For what fraction of packages can these tools compute their score at all?

This repo has measured it for npm and the answer was uncomfortable
(`what-this-tool-is.md` §2): **42.45% declare no repository**, a further 9.9%
declare one that does not resolve, and full-instrument yield is **0.4640**.
Scorecard, Snyk and deps.dev all depend on the same repository link, so the
same ceiling applies to all of them — and none of them publishes it.

**This is worth doing, and it is cheap:**

- It needs **no outcome**, so none of the four requirements that closed the
  outcome landscape apply. It is descriptive and unfalsifiable-by-waiting.
- The tooling exists: eight analysers covering nine ecosystems, plus the
  harvest and clone machinery built for #385.
- It generalises a finding that is currently one ecosystem wide, and the
  cross-ecosystem *pattern* is the contribution — whether repository
  declaration rates differ by an order of magnitude between Maven and npm is
  not known, and it bounds what every repository-derived score can claim.

Tracked in #425.
