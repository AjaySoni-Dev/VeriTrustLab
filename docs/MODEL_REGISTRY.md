# Model Registry

## MailGuard

**Purpose:** phishing/content specialist for email/message evidence.

The deployed model contract is immutable and must be resolved from the configured contract registry. The repository's qualified baseline has used `ealvaradob/bert-finetuned-phishing` at a pinned revision. Runtime output is schema-validated and model failure is not converted to a benign result.

MailGuard is only one evidence source. Deterministic content observations and Gateway correlation remain separate.

## Swift

**Purpose:** malicious/suspicious URL specialist.

The qualified baseline has used `kmack/malicious-url-detection` at a pinned revision. Swift is combined with deterministic URL observations by the Link Intelligence subsystem; a model probability is not presented as product accuracy.

## Cortex

Cortex is non-authoritative semantic extraction when a qualified contract is available. It must not independently return the final safety verdict or authoritative risk probability.

## Model-performance claims

VeriTrust currently does not publish a controlled product accuracy, precision, recall or F1 benchmark. The model-performance page must continue to state this until a reproducible evaluation with documented datasets, labels, thresholds and revisions exists.

## Revision policy

Production model contracts should use immutable revisions. Floating provider defaults or `main` revisions must not silently change a qualified model in deployment.
