# Security Policy

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Use GitHub's private security advisory feature for this repository and include:

- the affected route or component;
- reproduction steps with sensitive values removed;
- the security impact;
- any suggested mitigation.

Do not test against accounts, workspaces, files, or infrastructure you do not own or have explicit permission to assess.

## Supported version

This snapshot documents the security expectations of the supplied source. Deployment operators should apply security fixes to the source they actually deploy and verify the resulting environment; this repository snapshot does not independently attest to the state of any live deployment.

## Secrets

If a credential may have been exposed, revoke or rotate it first, then remove it from the repository history and deployment environment. Deleting only the visible file is not sufficient.

## Model supply chain

Do not commit model weights, unsafe pickle artifacts, ad hoc conversions, or provider-response captures. Pin approved artifacts to immutable revisions, record their checksums and license evidence, and use a reviewed private mirror or artifact registry before deployment. Document the evaluation, licensing, rollback, and rollout gates for every production model change.
