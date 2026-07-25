# Experimental Rigor Standards for ML Evaluation + Security Measurement

**Report Date:** 2026-07-26  
**Scope:** Standards applicable to Project Sentinel's experimental protocol  
**Audience:** Small lab conducting ML security evaluations

---

## Executive Summary

This report synthesizes established standards from clinical trials, psychology, ML evaluation, security research, and reproducibility literature into concrete, checkable rules for Project Sentinel. Each standard is mapped to one or more of the lab's four documented failures, with explicit guidance on cheap (always-do) vs. expensive (load-bearing-only) rules. The report ends with a pre-flight checklist suitable for any new experiment.

---

## 1. Preregistration

### What It Is and Why It Matters

Preregistration is the public, timestamped specification of a study's research question, design, and analysis plan *before* data are collected or analyzed. It originated in clinical trials (mandatory since 1997 for FDA approval) and was adopted by psychology following the replication crisis (Collaboration et al., Open Science Collaboration 2015).

**Evidence of effectiveness:** Meta-analysis shows preregistered studies report smaller effect sizes and fewer false positives than non-preregistered work. A 2023 prospective replication study achieved 86% successful replication of preregistered findings (Collaboration et al., *Nature*).

**For small labs:** A full Stage 1 Registered Report is expensive (2+ months of peer review). Lightweight alternatives exist: OSF preregistration templates take 2–4 hours and provide 80% of the rigor benefit.

### Concrete Rules (CHEAP)

**Rule 1.1: Preregister before touching data**
- Use OSF (Open Science Framework: osf.io) with the "AsPredicted" 8-question template or "Registered Report Protocol"
- Questions to answer:
  1. Study hypothesis (exact prediction, not exploratory goal)
  2. How will you manipulate the independent variable (if any)?
  3. How will you measure the main result?
  4. Which transformations/exclusions will you apply to the data?
  5. How many observations will you collect?
  6. How will you determine statistical significance?
  7. Any other analysis you plan to report?
  8. Any expected issues?
- **Timestamp:** Must be dated before first look at evaluation data. OSF provides public timestamping.
- **Failure mode prevented:** Researcher degrees of freedom; p-hacking; after-the-fact hypothesis selection masquerading as prior theory.

**Rule 1.2: Separate primary and exploratory analysis**
- Mark which metrics/comparisons are primary (preregistered) vs. exploratory (not preregistered, descriptive).
- Report both separately; apply statistical corrections only to primary tests.
- **Failure mode prevented:** Implicit multiple comparisons inflating false positives.

### Contested Aspects

- **Flexibility:** Some argue strict preregistration discourages discovery. Current consensus: allow deviations if disclosed, but mark them as exploratory not confirmatory.
- **Burden for small teams:** OSF preregistration adds 3–4 hours per study. Some labs argue this overhead is unjustified for exploratory work. *Recommendation:* preregister only when making a claim to publish or when the result will drive decisions.

---

## 2. ML Evaluation Methodology

### 2.1 Train/Test Split and Data Leakage

**Core Principle:** The "firewall" — no data used to fit the model may be used to evaluate it.

#### Train / Validation / Test Sets

**Standard setup:**
- **Training set:** Fit all parameters (model weights, hyperparameters, preprocessing transforms).
- **Validation set:** Tune hyperparameters, select features, choose architecture. Do NOT fit preprocessing on validation data.
- **Test set:** Final, held-out evaluation. Touch only once.

**Critical mistake:** Applying preprocessing (scaling, imputation, encoding) to the full dataset before splitting. If you compute mean/stddev on all data, the test set has information from training—this is leakage.

**Concrete rule (CHEAP):**
- Split first, fit preprocessing only on training set, apply fitted transforms to validation/test.
- Document the exact order: `data.split() → preprocessing.fit(train) → preprocessing.transform(val/test)`.

#### Grouped/Hierarchical Data and Leave-One-Group-Out (LOCO)

**When it matters:** If data points are not independent—e.g., multiple rows from the same repository, multiple samples from the same vulnerability, multiple test runs on the same app—row-level splitting leaks information.

**Standard:** Leave-one-group-out (LOCO) cross-validation or stratified k-fold by natural groups.

**Example (from Sentinel's failure #1):**
- **Wrong:** Split rows randomly 80/20. Train on rows from Repo A + Repo B, test on rows from Repo A + Repo B. Result: model memorizes Repo A's patterns.
- **Right:** Split by repo. Train on Repos A–M, test on Repos N–Z. No repo appears in both sets.

**Concrete rule (CHEAP):**
- Identify the natural grouping unit: repo, application, vulnerability class, author, dataset source, data collection round.
- Verify no group appears in both train and test sets.
- Document the grouping variable and split strategy in methods.
- Use `scikit-learn.model_selection.GroupKFold` or `GroupShuffleSplit` rather than random split.

**Detection test (CHEAP):**
- List all group IDs in training set, all group IDs in test set. Intersection must be empty.

### 2.2 Statistical Significance vs. Practical Significance

**Standard:** Distinguish between statistical significance (p < 0.05) and effect size (how big is the difference?).

A large sample can make a 0.1% difference statistically significant but practically meaningless. Conversely, a small sample may miss a real effect.

**Concrete rules (CHEAP):**
- Report both p-values AND 95% confidence intervals or effect sizes.
- Interpret via effect size, not p-value alone.
- Example: "Tool X recalled 72% [95% CI: 68–76%], Tool Y recalled 71% [95% CI: 66–75%], difference 1 percentage point (not statistically significant, p=0.42, Cohen's d=0.05)." Do not claim superiority.

### 2.3 Multiple Comparison Correction

**Problem:** If you test 20 metrics, the expected number of false positives at p < 0.05 is 1 (5% × 20). Many papers run dozens of tests and report the few that are significant.

**Standard:** Adjust p-values for multiple comparisons. Common methods:
- **Bonferroni:** α / number_of_tests. Conservative but simple. Example: 20 tests → p < 0.0025.
- **False Discovery Rate (FDR / Benjamini-Hochberg):** Limits expected proportion of false positives among all positives. Less conservative, more powerful.
- **Holm:** Step-down Bonferroni. Less conservative than Bonferroni, simple to apply.

**Concrete rule (CHEAP, if running multiple tests):**
- If you report more than 3 statistical comparisons, apply correction.
- Use Holm or FDR (less loss of power than Bonferroni).
- Document method in methods section: "p-values were corrected using Holm's method."
- Recalculate any claim of significance after correction.

**Rule for ablation studies (see § 6):** Ablation tests often run 5+ variants. Apply correction.

### 2.4 Confidence Intervals and Bootstrap Methods

**Standard:** Report uncertainty ranges, not just point estimates. For small samples or non-normal distributions, bootstrap confidence intervals are more reliable than t-test intervals.

**Concrete rule (CHEAP, n < 100 or non-normal data):**
- Use bootstrap (resample with replacement 10,000× times, recompute statistic, take 2.5th/97.5th percentiles) to get 95% confidence intervals.
- Standard Python: `from scipy.stats import bootstrap; bootstrap((data,), np.mean)`.
- Report as: "Recall = 72% [95% CI: 68–76% via bootstrap]."

---

## 3. Benchmark Design and Contamination

### 3.1 Benchmark Contamination (LLM/Tool Training Data Leakage)

**Problem:** Public benchmarks used in model training artificially inflate evaluation scores. A model that "memorizes" Juice Shop or HackTheBox will seem skilled at vulnerability detection but has merely recalled training data.

**Standard:** Separate benchmark from model training data. Detect contamination if model was already trained.

#### Detection Methods

1. **String overlap (n-gram matching):** Extract test set, count exact overlaps in model's training data (if available). GPT-3 uses 13-grams, GPT-4 uses 40-grams.
   - Limitation: Requires access to full training data (often unavailable).
   - Cost: LOW if data is available, HIGH otherwise.

2. **Output distribution analysis (CDD):** Measure model's output probability distribution on test set. High confidence on specific answers → likely memorization.
   - Cost: LOW (model inference only).
   - Limitation: Not definitive; models can be confidently wrong.

3. **Activation pattern analysis (DICE):** Analyze neural network activations for fine-tuned models. Contaminated data shows distinct patterns.
   - Cost: MEDIUM (requires access to model internals).

4. **Token probability outliers:** Look for unnatural token probabilities (min-k prob detection). Very high or low probabilities on specific tokens suggest memorization.
   - Cost: LOW.

#### Mitigation Strategies

**Concrete rules (varies on cost):**

**Rule 3.1 (CHEAP): Use non-public or custom benchmarks**
- For LLM evaluation: Create custom test cases instead of using public benchmarks (OWASP Juice Shop, HackTheBox, CVE datasets).
- If public benchmark is necessary, verify release date of benchmark ≥ model's training data cutoff + 3 months.
- Document benchmark provenance in methods: "Test set was constructed on [date], model's training data includes data up to [date]."

**Rule 3.2 (CHEAP): Temporal separation**
- Never train on data from [date] and test on data from [date - 6 months]. Require [date_test] > [date_train] + 6 months.
- For LLMs: Check model card or documentation for training data cutoff.

**Rule 3.3 (MEDIUM-cost, if using public benchmark): Contamination check**
- If using a public benchmark, manually inspect top 100 samples for suspicious n-gram overlaps with known LLM training corpora (arXiv, GitHub, Common Crawl).
- Use token probability analysis: Run inference on test set, flag samples where model assigns >90% confidence to a single answer—these are high-contamination risk.
- Report: "X% of test samples showed high-confidence predictions suggesting possible memorization; results should be interpreted cautiously."

**Rule 3.4 (CHEAP): Rephrased/adversarial variants**
- If the benchmark is old or public, create rephrased versions (different wording, new examples, different context) and evaluate on those.
- The gap between performance on original vs. rephrased indicates memorization. Large gap = memorization, small gap = genuine skill.

### 3.2 Benchmark Class Coverage

**Problem:** Sentinel's failure #4 — "benchmark contained 0% of the target vulnerability class." A SAST tool trained to detect SQL injection will score highly on a SQL-injection benchmark but fail on XSS or RCE detection. Scores are not generalizable.

**Concrete rules (CHEAP):**

**Rule 3.5: Audit benchmark composition**
- Enumerate vulnerability classes / attack types in your benchmark.
- Calculate percentage for each class: count_class / total_samples.
- Ensure **all primary attack types are represented**. Minimum: ≥ 5% for each class, unless you explicitly pre-register that a class is out-of-scope.
- Document: "Benchmark contained X SQL injection, Y XSS, Z RCE, ..., total N samples."

**Rule 3.6: Stratified sampling**
- If subclasses are imbalanced, use stratified sampling to ensure test set mirrors training population.
- Example: If training has 60% SQLi / 30% XSS / 10% RCE, test should have similar proportions.

**Rule 3.7: Separate known vs. unknown vulnerabilities**
- If using CVE/NVD data: separately track vulnerabilities already known at benchmark creation (e.g., CVE-2024-1234) vs. novel ones.
- Evaluate separately. Known-only high scores are less interesting than novel-vulnerability detection.

---

## 4. Reproducibility Standards

### 4.1 NeurIPS/ICML Reproducibility Checklist

**Standard:** NeurIPS (2021+) and ICML (2024+) require a paper checklist covering:

1. **Availability of code and data:**
   - Are code and data publicly released?
   - If withheld, is the reason stated (privacy, IP)?

2. **Seed and randomness:**
   - Is the random seed documented?
   - Are stochastic sources (numpy, torch, random module) seeded?

3. **Computational requirements:**
   - What hardware was used (GPU model, RAM, CPU)?
   - Estimated runtime?

4. **Environment and dependencies:**
   - Package versions pinned?
   - Python/language version documented?

5. **Hyperparameters and training details:**
   - Learning rate, batch size, regularization, activation functions, all explicitly stated?
   - Hyperparameter selection method (grid search, random, Bayesian) documented?

### 4.2 Concrete Reproducibility Rules (CHEAP)

**Rule 4.1: Commit data version and environment**
- Tag data with version/checksum: `data_v1.2_sha256=abc123...`
- Use `requirements.txt` (Python) or `Dockerfile` with pinned versions (all packages, not ranges).
  - Wrong: `tensorflow >= 2.0`
  - Right: `tensorflow==2.14.0`
- For large datasets: use DVC (Data Version Control) or Zenodo DOI.

**Rule 4.2: Fix random seeds**
```python
import random, numpy as np, torch

def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)

set_seed(42)
```
- Document seed in methods and code.
- Run experiment 3× with different seeds to report mean ± stderr.

**Rule 4.3: Publish a README or Dockerfile**
- Include:
  - Exact command to run experiment
  - Expected output/metrics
  - Hardware used (GPU, RAM)
  - Estimated runtime
  - Contact email if code fails

**Rule 4.4: Log hyperparameters and configuration**
- Every run logs a config file (JSON or YAML):
  ```json
  {
    "model": "random_forest",
    "n_estimators": 100,
    "max_depth": 15,
    "data_seed": 42,
    "train_size": 0.8,
    "test_size": 0.2,
    "date": "2026-07-26"
  }
  ```
- Version config alongside code and results.

### 4.3 ACM Artifact Badging

**Standard:** ACM badges signal reproducibility level:
- **Artifacts Available:** Code/data are publicly accessible with documentation.
- **Artifacts Evaluated Functional:** Reviewers ran the code and it executed.
- **Artifacts Evaluated Reusable:** Code is well-documented and others could adapt it.
- **Results Reproduced:** Independent team successfully reproduced core results.

**For Sentinel:** Aim for "Artifacts Evaluated Functional" (one step easier than "Reusable").

**Concrete rule (MEDIUM-cost, for publication):**
- Clean up code for release: remove hardcoded paths, add documentation, add reproducibility checklist.
- Prepare a 5-minute "here's how to run this" guide.
- Submit to artifact review process (USENIX, ACM CCS, etc.) or publish on GitHub + Zenodo with DOI.

---

## 5. Measurement Validity in Security

### 5.1 Construct Validity: Are You Measuring What You Claim?

**Problem:** SAST tool reports 500 findings, but most are not real exploitable vulnerabilities. Counting "findings" ≠ counting "vulnerabilities."

**Example from literature:** Security research often uses issue counts from static analysis tools as a proxy for "actual vulnerabilities," conflating the two.

**Concrete rules (CHEAP):**

**Rule 5.1: Operationalize explicitly**
- Define: "What is a vulnerability in this study?"
  - Option A: "Any CWE-89 (SQL injection) in the code" (syntactic, easy).
  - Option B: "Exploitable SQL injection: attacker-controlled input reaches SQL query without sanitization AND attacker can observe response" (semantic, hard but valid).
- Adopt the definition from a published standard if possible (CWE, OWASP Top 10).
- Document choice and limitations.

**Rule 5.2: Use multiple metrics, not one**
- Report precision (% of findings that are real vulnerabilities), recall (% of real vulnerabilities found), and F1-score.
- Do NOT claim "90% accuracy" without precision/recall breakdown.

**Rule 5.3: Ground truth validation**
- For a sample of findings, manually verify ground truth (is this actually a vulnerability?).
- Minimum: 30 samples or 10% of findings, whichever is larger.
- Document inter-rater agreement (Cohen's kappa) if multiple reviewers validate.

### 5.2 Negative and Positive Controls

**Negative control:** A condition where you expect zero effect. Should produce no positives.  
**Positive control / Canary:** A condition where you expect strong signal. Should produce strong positives.

**Purpose:** Test that your measurement instrument works *at all* before claiming it detects subtleties.

**Example:**
- **Positive control:** Run SAST tool on code with a known, obvious SQL injection. Does tool detect it? If no, your measurement is broken.
- **Negative control:** Run SAST tool on safe code with no vulnerabilities. Does tool report false positives? If yes, your false positive rate is unacceptable.

**Concrete rules (CHEAP):**

**Rule 5.4: Instrument validation**
- For any new detection tool or metric:
  1. Create 10 samples with known vulnerabilities (positive control). Tool should find ≥ 90%.
  2. Create 10 samples with no vulnerabilities (negative control). Tool should report ≤ 10% false positives.
  3. If instrument fails either test, do not use it; fix it first.
- Document results in methods: "Positive control accuracy: X%, negative control false positive rate: Y%."

**Rule 5.5: Sanity checks before deployment**
- Before evaluating your main research question, run tool on a small pilot dataset (5–10 samples) and manually inspect every finding.
- Fix obvious bugs in the tool before running the full experiment.

### 5.3 Ablation Studies (Isolating Component Contribution)

**Problem:** Tool A + LLM layer scores 80%, Tool A alone scores 75%. Did the LLM add 5%? Not necessarily—there may be interactions, overfitting, or confounds.

**Standard:** Ablation study — systematically remove components and measure their individual contribution.

**Concrete rules (CHEAP to MEDIUM):**

**Rule 5.6: Establish a clear baseline**
- Define the fully-functional system (all components, default hyperparameters, trained on full training set).
- Report baseline score as reference: "Baseline (full system): 80% recall, 92% precision."

**Rule 5.7: Ablate one component at a time**
- Remove ONE component and re-run: "System without LLM layer: 75% recall, 93% precision."
- Keep all else constant: same data, same random seed, same hyperparameters.
- Interpret: "LLM layer contributes 5 percentage points recall."

**Rule 5.8: Order matters**
- If removing components can change the remaining system's behavior (e.g., class imbalance changes), report results for both orderings:
  - "Remove A then B" vs. "Remove B then A."
  - Interaction effects matter.

**Rule 5.9: Statistical test for ablation difference**
- Use a significance test (paired t-test, Wilcoxon signed-rank) to check if ablation change is real.
  - Example: "Removing LLM layer decreased recall by 5 points (p=0.03)."
  - If p > 0.05, the component's contribution is not statistically significant; state this clearly.
- Apply multiple-comparison correction if running ablations on 3+ components (see § 2.3).

---

## 6. Effect Size and Statistical Power

### 6.1 Concepts

**Effect size:** Magnitude of the difference/relationship, e.g., Cohen's d (standardized difference between means).  
**Power:** Probability of detecting a true effect of that size.  
**Sample size:** How many observations are needed to achieve 80% power?

**Standard:** Aim for **80% power** (80% chance of finding a true effect if it exists). This balances Type I and Type II error.

**Trade-off:** Large samples can detect tiny effects (high power, low effect size). Small samples miss real effects (low power). Always report effect size, not just significance.

### 6.2 Concrete Rules (CHEAP to MEDIUM)

**Rule 6.1: Preregister sample size**
- Before running an experiment, estimate the effect size you expect (from prior work or practical importance).
- Use a power calculator (G*Power software, or online calculator) to find n needed for 80% power.
- Preregister: "We plan to test 50 apps, expecting Cohen's d ≥ 0.5 (medium effect). This gives 85% power at p < 0.05."
- If budget/time prevents reaching planned n, state this and interpret results as exploratory/underpowered.

**Rule 6.2: Report effect sizes and confidence intervals**
- Never report p-values alone.
- Example report:
  - Wrong: "Tool X is significantly better (p = 0.02)."
  - Right: "Tool X recall: 75% [95% CI: 71–79%], Tool Y recall: 72% [95% CI: 68–76%], difference: 3 percentage points [95% CI: -1 to 7%], p = 0.12. Effect is not statistically significant but is consistent with a 3–4 point advantage."

**Rule 6.3: Honest reporting of underpowered studies**
- If n is small (< 30 per group) or effect size is tiny, state it upfront.
- Example: "This is a proof-of-concept study with n = 10; results are underpowered (33% power) and should be seen as exploratory, not confirmatory."
- Do not claim statistically significant results in underpowered studies.

---

## 7. Mapping Standards to Sentinel's Four Documented Failures

### Failure #1: Train/Test Split Leakage (Row-Split Instead of Leave-One-Repo-Out)

**Problem:** Random 80/20 row split allowed model to see patterns from Repo A in training, then "generalize" on Repo A in test.

**Standards that would have caught this:**
1. **ML Evaluation (§ 2.1):** Leave-one-group-out. "Identify natural grouping unit (repo). Verify no repo in both train and test."
2. **Measurement Validity (§ 5.1):** Construct validity. Define what you claim: "Model generalizes to new repositories." Test this claim by splitting by repo, not rows.
3. **Reproducibility (§ 4):** Document exact split strategy. If split details are explicit, the error becomes obvious.
4. **Preregistration (§ 1):** Preregister the split strategy. Changing it post-hoc becomes a red flag.

**Cheap preventative rule:** Rule 2.1 (grouped cross-validation) detects this immediately. Cost: 1 hour to restructure split logic.

---

### Failure #2: Label-Attribution Bug (61% Misattribution)

**Problem:** Ground truth labels were incorrect for 61% of samples, making training and evaluation unreliable.

**Standards that would have caught this:**
1. **Measurement Validity (§ 5.1-5.3):** Construct validity + ground truth validation (Rule 5.3). "Manually verify sample of labels; report inter-rater agreement."
   - If 3 reviewers independently label 30 random samples and Cohen's kappa = 0.39 (poor agreement), halt experiment.
2. **Ablation Studies (§ 5.3):** Ablate label source. Train on labels from source A vs. source B; large performance difference signals label quality issue.
3. **Negative Control (§ 5.2):** Create 10 hand-labeled examples, verify tool performs well on them. If model fails on human-agreed labels, label source is broken.
4. **Reproducibility (§ 4.1-4.2):** Version the ground truth data (Rule 4.1). Versioning makes it findable when the bug is discovered.

**Cheap preventative rule:** Rule 5.3 (ground truth validation) catches this. Manually label 30 samples, measure agreement. Cost: 2–4 hours per dataset.

---

### Failure #3: Prober Measured Around the Control, Not the Control Itself

**Problem:** A component was supposed to test whether an LLM detects a vulnerability, but instead measured something adjacent, making the contribution unmeasurable.

**Standards that would have caught this:**
1. **Construct Validity (§ 5.1):** Operationalize precisely. "We measure whether an LLM detects SQL injection." Run component in isolation on 10 known SQL injections. If accuracy ≠ ≥ 90%, the component is not measuring what it claims.
2. **Positive Control (§ 5.2):** Test the prober/component on known-vulnerable code. If it fails, the instrument is broken.
3. **Ablation Study (§ 5.3):** Ablate the LLM layer explicitly:
   - Full system (deterministic + LLM): score X.
   - Deterministic baseline only: score Y.
   - Difference: X - Y = LLM contribution.
   - If ablation shows no clear contribution, the component may be measuring incidentally, not its intended effect.
4. **Preregistration (§ 1):** Specify what each component should measure and pass positive controls before deploying.

**Cheap preventative rule:** Rule 5.4 (instrument validation on known examples) catches this. Cost: 3–4 hours per component.

---

### Failure #4: Benchmark Contained 0% of Target Vulnerability Class

**Problem:** Evaluated on SQL injection–only benchmark when goal was general vulnerability detection. Score is not generalizable.

**Standards that would have caught this:**
1. **Benchmark Design (§ 3.2):** Rule 3.5 (audit benchmark composition). Enumerate vulnerability classes in benchmark. If target class is absent, halt.
2. **Construct Validity (§ 5.1):** Define what you measure. "We measure SAST performance on all OWASP Top 10 vulnerability types." Verify benchmark contains all types.
3. **Stratified Sampling (§ 3.2, Rule 3.6):** Ensure test set mirrors vulnerability-class distribution of training/real-world data.
4. **Preregistration (§ 1):** Preregister benchmark composition. Changes after seeing data are red flags.

**Cheap preventative rule:** Rule 3.5 (audit benchmark composition). Cost: 30 minutes to list classes and percentages.

---

## Summary of Cheap vs. Expensive Rules

### Always-Do (Cheap, < 1 hour per experiment)
- Rule 1.1: Preregister (4 hours setup, then 30 min per experiment)
- Rule 1.2: Separate primary/exploratory
- Rule 2.1: Document split strategy; use `GroupKFold`
- Rule 2.2: Report effect size + CI
- Rule 3.5: Audit benchmark composition
- Rule 4.1: Pin versions; use requirements.txt
- Rule 4.2: Fix random seeds
- Rule 5.1: Operationalize constructs
- Rule 5.2: Use precision + recall + F1
- Rule 5.4: Sanity-check instrument on 10 known examples
- Rule 6.2: Report effect sizes, not p-values alone

### Do When Load-Bearing (Medium, 2–8 hours)
- Rule 2.3: Multiple-comparison correction (if >3 tests)
- Rule 2.4: Bootstrap confidence intervals (if n < 100)
- Rule 3.2–3.4: Contamination detection (if using public LLM or public benchmark)
- Rule 5.3: Ablation study (if claiming component contribution)
- Rule 5.4: Instrument validation (if using new metric)
- Rule 6.1: Power analysis (if claiming statistical significance)

### Optional (Expensive, 4+ hours or requires external review)
- Rule 4.3: ACM artifact badging (for publication)
- Full Registered Report Stage 1 (2+ months of peer review)

---

## Contested Issues in the Field

### 1. Preregistration vs. Exploratory Work
- **Concern:** Strict preregistration discourages serendipitous discovery.
- **Current consensus:** Preregister primary hypotheses; mark exploratory analyses separately. Both are valuable; exploration is valid if not claimed as confirmation.
- **Recommendation for Sentinel:** Preregister when publishing claims; exploratory work can skip it but should be framed as such.

### 2. Bonferroni vs. FDR Correction
- **Debate:** Bonferroni is overly conservative and reduces power to detect real effects. FDR (False Discovery Rate) is more powerful but allows more false positives.
- **Consensus:** Use FDR for exploratory work, Bonferroni for pre-registered confirmatory work.
- **Recommendation:** Use Holm (step-down Bonferroni) as a middle ground if uncertain.

### 3. Effect Size vs. p-Value
- **Debate:** Some argue p-values are outdated; others say they're useful for binary decisions.
- **Consensus:** Report both. P-values are useful for Yes/No decisions (does the effect exist?); effect size answers "How big is it?" Use both together.
- **Recommendation for Sentinel:** Always report [effect size, 95% CI, p-value].

### 4. Benchmark Contamination Detection Reliability
- **Issue:** Detecting contamination in large LLMs (GPT-4, Claude) is hard without access to training data.
- **Consensus:** Use multiple detection methods (n-gram, token probability, output distribution). High confidence only if multiple methods agree.
- **Recommendation:** For small lab, prefer creating custom benchmarks over detecting contamination in public LLMs.

---

## Proposed Pre-Flight Checklist for Sentinel Experiments

Use this checklist before starting any new experiment. Answer each as YES / NO / N/A. If any item is NO and the failure mode is critical for your claim, pause and fix it.

### A. Research Design (Answer Before Collecting Data)

1. **Hypothesis clarity:** Have you written a specific, falsifiable hypothesis (not just a research question)?
   - Failure mode: Vague hypothesis → p-hacking.
   - Cost: 30 min.

2. **Preregistration:** Have you registered the hypothesis, method, and analysis plan (OSF + timestamp)?
   - Failure mode: Researcher degrees of freedom.
   - Cost: 4 hours (first time), 30 min (subsequent).

3. **Sample size / power:** Have you estimated expected effect size and calculated required sample size for 80% power?
   - Failure mode: Underpowered study; cannot detect real effects.
   - Cost: 1 hour.

4. **Outcome definitions:** Have you operationalized your primary outcome (e.g., "recall on SQL injection samples > 70%")?
   - Failure mode: Construct validity; measuring wrong thing.
   - Cost: 1 hour.

### B. Data Preparation (Before Training/Evaluation)

5. **Grouping structure:** Have you identified the natural grouping unit (repo, app, author, class) and verified no group appears in both train and test?
   - Failure mode: Train/test leakage (Failure #1).
   - Cost: 1 hour.

6. **Data splitting:** Are train / validation / test sets disjoint by the grouping unit (repo, class, etc.)?
   - Failure mode: Leakage.
   - Cost: 30 min.

7. **Preprocessing order:** Have you split data FIRST, then fit preprocessing (scaling, imputation) on training set only?
   - Failure mode: Information leakage from validation/test into preprocessing.
   - Cost: 30 min.

8. **Ground truth validation:** Have you manually verified ≥ 10% of labels (or 30 samples, whichever is larger) and reported inter-rater agreement?
   - Failure mode: Label quality bug (Failure #2).
   - Cost: 2–4 hours.

9. **Data versioning:** Have you recorded data version (date, checksum, or DVC commit hash) and stored it in a versioned config file?
   - Failure mode: Cannot reproduce data later.
   - Cost: 30 min.

### C. Benchmark and Instruments (Before Evaluation)

10. **Benchmark composition audit:** Have you enumerated vulnerability classes/attack types in your benchmark and verified all primary classes are represented (≥ 5% each)?
    - Failure mode: Benchmark missing target class (Failure #4).
    - Cost: 30 min.

11. **Instrument validation:** Have you tested each new tool/metric on 10 hand-labeled positive examples and 10 negative examples, recording accuracy?
    - Failure mode: Measuring around the control, not the control (Failure #3).
    - Cost: 3–4 hours.

12. **Benchmark contamination check (if using public LLM or benchmark):** Have you recorded training data cutoff date for any pre-trained model and verified test set is not in training data?
    - Failure mode: Inflated scores due to memorization.
    - Cost: 1 hour (if data available); 3+ hours (if detection needed).

### D. Experiment Execution

13. **Random seed pinning:** Have you set fixed random seeds for all stochastic libraries (numpy, torch, random) and documented the seed?
    - Failure mode: Irreproducible results.
    - Cost: 15 min.

14. **Configuration logging:** Have you logged all hyperparameters, seeds, and data versions to a config file (JSON/YAML) committed with results?
    - Failure mode: Cannot recall exact settings; cannot reproduce.
    - Cost: 30 min.

15. **Ablation plan (if claiming component contribution):** Have you preregistered which components you will ablate and how you will isolate their contribution?
    - Failure mode: Measuring confounded effects (Failure #3).
    - Cost: 1 hour (planning).

16. **Statistical test plan:** Have you preregistered which metrics will be compared and which statistical tests will be used (e.g., paired t-test, Wilcoxon)?
    - Failure mode: Implicit p-hacking via test selection.
    - Cost: 30 min.

### E. Analysis and Reporting

17. **Multiple comparisons:** If you report > 3 statistical comparisons, have you applied multiple-comparison correction (Bonferroni, Holm, or FDR)?
    - Failure mode: Type I error inflation.
    - Cost: 30 min.

18. **Effect size and CI reporting:** Have you reported effect size + 95% CI (not just p-values) for all primary comparisons?
    - Failure mode: Inflated claims of significance; misinterpretation of practical importance.
    - Cost: 30 min.

19. **Primary vs. exploratory:** Have you clearly separated results into pre-registered primary claims and exploratory/post-hoc observations?
    - Failure mode: Implicit multiple comparisons.
    - Cost: 30 min.

20. **Ablation results interpretation:** If you ran ablations, have you applied statistical correction and checked for interaction effects (ablation order sensitivity)?
    - Failure mode: Overclaimed component contribution.
    - Cost: 1 hour.

### F. Reproducibility and Documentation

21. **Dependencies pinned:** Have you listed all Python packages with exact versions (not ranges) in requirements.txt or environment.yml?
    - Failure mode: Cannot reproduce; code breaks on different env.
    - Cost: 15 min.

22. **README and instructions:** Have you written a 5-minute "how to run this experiment" guide with expected output and hardware requirements?
    - Failure mode: Code is unusable; cannot share.
    - Cost: 1 hour.

23. **Code cleanliness:** Have you removed hardcoded paths, secrets, and debug prints? Is code ready for sharing?
    - Failure mode: Security issue; non-reproducible due to machine-specific paths.
    - Cost: 1 hour.

24. **Artifact archival:** Have you committed code, config, and results to a repository with a DOI (GitHub + Zenodo), or uploaded to OSF?
    - Failure mode: Results lost; cannot retrieve later.
    - Cost: 30 min.

---

## End-of-Report: Unresolved Questions

1. **Preregistration overhead for rapid iteration:** Should exploratory/proof-of-concept studies preregister? Current answer: only if the result will be published or drive decisions. Remains ambiguous for internal lab work.

2. **Contamination detection without training data access:** For closed-source LLMs (GPT-4, Claude), detecting contamination is hard. Is token-probability analysis reliable? Remains contested.

3. **Grouped splits for time-series data:** How to split if data is time-ordered (e.g., CVEs released over time)? Temporal train/test split is standard in forecasting but less common in security research. Worth a dedicated guideline?

4. **Ablation study statistical power:** How many variants (N ablations) do you need to achieve 80% power in ablation studies? No clear standard; depends on baseline effect size.

5. **Custom benchmark design:** When is a custom benchmark valid instead of using an established one? No formal guidance; depends on research question and resources.

---

**Report complete. See above for the Pre-Flight Checklist (items A–F) for immediate use.**

---

## Sources

**Preregistration and Replication:**
- [Improving evidence-based practice through preregistration](https://www.tandfonline.com/doi/full/10.1080/08989621.2021.1969233) — Wicherts et al., *Frontiers in Psychology* 2021
- [Preregistration and Credibility of Clinical Trials](https://www.researchgate.net/publication/371017588_Preregistration_and_Credibility_of_Clinical_Trials)
- [Are pre-registrations the solution to the replication crisis?](https://brainsidea.wordpress.com/2015/11/22/are-pre-registrations-the-solution-to-the-replication-crisis-in-psychology-not-really/)
- [Registered Reports: The Future of Publication](https://www.cos.io/initiatives/registered-reports) — Center for Open Science

**ML Evaluation and Data Leakage:**
- [Train/Validation/Test Splits and Data Leakage in Practice](https://gtracademy.org/train-validation-test-splits-and-data-leakage-in-practice/) — GTR Academy
- [Data splitting to avoid information leakage with DataSAIL](https://www.nature.com/articles/s41467-025-58606-8) — *Nature Communications* 2025
- [On the (Mis)Use of Machine Learning with Panel Data](https://arxiv.org/pdf/2411.09218) — arXiv
- [Inflation of test accuracy due to data leakage](https://www.nature.com/articles/s41597-022-01618-6) — *Scientific Data* 2022

**Grouped Cross-Validation:**
- [Leave-one-group-out cross-validation (LOCO)](https://www.emergentmind.com/topics/leave-one-complex-out-loco-cross-validation)
- [The problematic case of data leakage: A case for leave-profile-out cross-validation](https://www.sciencedirect.com/science/article/pii/S0016706125000618) — *Geoderma* 2025
- [Distributional bias compromises leave-one-out cross-validation](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11177965/) — bioRxiv
- [Experiencing a Data Leak With Leave-One-Out](https://medium.com/@uriitai/experiencing-a-data-leak-when-employing-the-leave-one-out-method-ee369e28691c) — Medium

**Benchmark Contamination:**
- [A Survey on Data Contamination for Large Language Models](https://arxiv.org/html/2502.14425v2) — arXiv 2025
- [Generalization or Memorization: Data Contamination and Trustworthy Evaluation for LLMs](https://aclanthology.org/2024.findings-acl.716/) — ACL 2024
- [Rethinking Benchmark and Contamination for Language Models with Rephrased Samples](https://arxiv.org/pdf/2311.04850) — arXiv
- [On The Fragility of Benchmark Contamination Detection](https://arxiv.org/pdf/2510.02386) — arXiv
- [Detecting Benchmark Contamination Through Watermarking](https://arxiv.org/pdf/2502.17259) — arXiv 2025

**Reproducibility Standards:**
- [Improving Reproducibility in Machine Learning Research](https://arxiv.org/pdf/2003.12206) — NeurIPS 2019 Reproducibility Program
- [NeurIPS Paper Checklist Guidelines](https://neurips.cc/public/guides/PaperChecklist)
- [ICML 2024 Paper Guidelines](https://icml.cc/Conferences/2024/PaperGuidelines)
- [Artifact Evaluation Guidelines](https://github.com/ctuning/artifact-evaluation/blob/master/docs/reviewing.md) — cTuning/ACM
- [Reproducibility in Computational Biology: ML Best Practices](https://www.technologynetworks.com/tn/articles/reproducibility-in-computational-biology-best-practices-for-ai-and-ml-workflows-414557) — Technology Networks
- [PyTorch Reproducibility: A Practical Guide](https://medium.com/@heyamit10/pytorch-reproducibility-a-practical-guide-d6f573cba679) — Medium
- [How to Pin Package Versions in Dockerfiles](https://oneuptime.com/blog/post/2026-02-08-how-to-pin-package-versions-in-dockerfiles-for-reproducible-builds/view) — Oneuptime

**Measurement Validity in Security:**
- [Security Incentivization: An Empirical Study](https://arxiv.org/pdf/2605.13100) — arXiv
- [Construct Validity](https://www.sciencedirect.com/topics/computer-science/construct-validity) — ScienceDirect
- [Where Do Smart Contract Security Analyzers Fall Short?](https://arxiv.org/pdf/2603.00890) — arXiv
- [VulEval: Towards Repository-Level Evaluation of Vulnerability Detection](https://arxiv.org/pdf/2404.15596) — arXiv
- [RealVuln: Benchmarking SAST and LLM Scanners](https://arxiv.org/pdf/2604.13764) — arXiv
- [Large Language Models vs. Static Code Analysis Tools](https://arxiv.org/pdf/2508.04448) — arXiv

**Ablation Studies:**
- [ABLATOR: Robust Horizontal-Scaling of Ablation Experiments](https://proceedings.mlr.press/v224/fostiropoulos23a/fostiropoulos23a.pdf) — *PMLR* 2023
- [What Is an Ablation Study in Machine Learning?](https://biologyinsights.com/what-is-an-ablation-study-in-machine-learning/) — Biology Insights

**Statistical Power and Effect Size:**
- [Evaluation of sample size in machine learning applications](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC9926644/) — *PLoS ONE* 2023
- [Components of Power Analysis: Alpha, Beta, Effect Size](https://www.statisticssolutions.com/components-of-power-analysis/)
- [Power Analysis and Sample Size Calculation](https://medium.com/@data.science.enthusiast/power-analysis-and-sample-size-calculation-in-experimental-studies-aa5bf4cd5032) — Medium

**Multiple Comparisons:**
- [Bonferroni Correction](https://en.wikipedia.org/wiki/Bonferroni_correction) — Wikipedia
- [How to Use Bonferroni Correction](https://www.statsig.com/perspectives/bonferroni-correction-multiple-testing) — Statsig
- [Multiple Comparisons: Bonferroni and FDR](https://physiology.med.cornell.edu/people/banfelder/qbio/resources_2008/1.5_Bonferroni_FDR.pdf) — Cornell Physiology
- [To Adjust or Not to Adjust for Multiple Comparisons](https://www.sciencedirect.com/science/article/pii/S0895435625000216) — ScienceDirect 2025

**Bootstrap and Confidence Intervals:**
- [Statistical Inference Using Bootstrap Confidence Intervals](https://rss.onlinelibrary.wiley.com/doi/full/10.1111/j.1740-9713.2004.00067.x) — *Significance* 2004
- [Bootstrap Confidence Intervals: A Comparative Simulation Study](https://arxiv.org/pdf/2404.12967) — arXiv
- [Bootstrap Confidence Intervals](https://library.virginia.edu/data/articles/bootstrap-estimates-of-confidence-intervals) — UVA Library

**Preregistration Templates:**
- [Choosing the Right Preregistration Template](https://www.cos.io/blog/choosing-preregistration-template-guide-for-researchers) — Center for Open Science
- [Registered Reports: Structure, Format, Checklist](https://www.editage.com/blog/registered-report-structure-checklist-examples/) — Editage
- [OSF Preregistration Step-by-Step](https://casrai.org/guides/osf-preregistration) — CASRAI

**Precision and Recall in Security Tools:**
- [Precision & Recall: When Conventional Fraud Metrics Fall Short](https://kount.com/blog/precision-recall-when-conventional-fraud-metrics-fall-short) — Kount
- [Confusion Matrix, Precision, Recall](https://www.blog.trainindata.com/confusion-matrix-precision-and-recall/) — Train in Data
