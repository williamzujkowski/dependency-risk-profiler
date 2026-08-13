# What deps.dev added: a measurable `transitive`, a real-packages cut, and Scorecard head-to-head

Free public REST API, no BigQuery, no authentication, no billing. 2,000-package
#385 cohort, 1,995 resolved. ~50 MB of JSON.

## 1. Coverage, and Scorecard covers half of what we do

| | share of a uniform npm draw |
|---|---:|
| resolved transitive graph | **0.985** |
| dependent count | 0.977 |
| **OpenSSF Scorecard** | **0.223** |
| *(this tool, full instrument, for comparison)* | *0.464* |

**Scorecard runs on 22.3% of a uniform npm draw — less than half this tool's
46.4%.** Both are bounded by the same declared-repository ceiling, and
Scorecard's additional requirements narrow it further.

`prior-art.md` said the computability bound applies to Scorecard, Snyk and
deps.dev as well as to us. It does, and for Scorecard it binds **harder**.

## 2. `transitive` is now measurable

It was one of only two signals still constant in the canonical record. A
resolved closure arrived for **1,970 of 2,000** packages:

| | |
|---|---:|
| median closure size | **4** |
| mean | 91.2 |
| max | 4,897 |
| packages with **no** dependencies | **36.4%** |

That leaves `version` as the single remaining constant — and it is structurally
inapplicable to a package-level cohort, so it cannot be fixed.

## 3. "Real packages": computability rises with use, and 82.5% of npm is used by nothing

**1,611 of 1,953 packages (82.5%) have zero dependents.**

| dependents | n | declares repo | **computable** | one-shot |
|---|---:|---:|---:|---:|
| 0 | 1,611 | 0.548 | **0.436** | 0.363 |
| 1–4 | 250 | 0.680 | **0.588** | 0.192 |
| 5–24 | 55 | 0.673 | 0.564 | 0.164 |
| 25–99 | 24 | 0.917 | **0.708** | 0.125 |
| 100+ | 13 | 0.923 | **0.769** | 0.231 |

Collapsed:

| | n | declares | **computable** |
|---|---:|---:|---:|
| **any dependent** | 342 | 0.705 | **0.599** |
| zero dependents | 1,611 | 0.548 | 0.436 |

**So the honest computability figure depends on which population you mean.**
Across all published npm names it is 46.4%; across packages something actually
depends on it is **59.9%**, rising to roughly three-quarters for packages with
25 or more dependents.

Both are true and they answer different questions. A tool pointed at a
dependency manifest sees the second population, so **59.9% is the number a user
should expect** — and it still means two packages in five cannot be fully
scored.

The confirmed-malware angle turned out to be the wrong lens: only 0.75% of the
cohort is an npm takeover. The mass that depresses the uniform figure is not
malicious, it is **unused** — one-shot publishes, experiments, squats.

## 4. This tool and Scorecard substantially agree — and that is not reassuring

445 packages carry both scores, above the registered floor of 300.

> **Spearman ρ = −0.6246**

Negative is **agreement**: this tool scores risk (higher is worse), Scorecard
scores health (higher is better). The convention was fixed in the protocol
before the number was computed, because the additive study had already shipped
one polarity error of this shape.

| registered line | threshold | result |
|---|---|---|
| 1. measuring different things | \|ρ\| < 0.2 | **did not fire** |
| 2. near-substitutes | ρ > 0.7 | did not fire |

**I predicted line 1 would fire and wrote that into the protocol.** It did not.
The instruments agree more than I expected — substantially, without being
interchangeable.

### What that means, and what it does not

Some of the agreement is **mechanical**: both read the same declared repository
and score overlapping properties, so on the 22.3% where both run, they are
partly reading the same bytes.

The part that matters is what it implies for the negative results. **Two
instruments that agree with each other at ρ = −0.62, and where the one with
published validation correlates *backwards* with vulnerability counts** (Zahan
et al., R² 0.09–0.12, positive sign), are not independent evidence of anything.

> Agreement is not correctness. This tool's failure to beat download count is
> more likely to generalise to Scorecard than to be a defect peculiar to this
> implementation.

That is a claim about the class of tool, and it is the most consequential thing
in this document. It is also, deliberately, a claim about *agreement* rather
than accuracy — neither instrument has a validated outcome on this cohort, and
#385 will not read out until 2027-08.
