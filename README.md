# NAS Deploy Toolkit

A small, reusable delivery channel for Alex's NAS-hosted services.

It intentionally owns only the common deployment boundary:

- verify CI-tested images and publish immutable `build-<commit>` GHCR references;
- build a digest-pinned deployment manifest from caller-owned Compose files;
- establish a temporary WireGuard connection and use a service-specific restricted SSH account;
- submit the manifest to the NAS executor and retain a sanitized deployment receipt.

Each application repository retains its own tests, Dockerfiles, Compose templates, service policy, backup hooks, persistent-data compatibility work, and release acceptance criteria.

## Security model

The caller pins this repository in two places to the same reviewed, full 40-character commit SHA:

1. checkout used for `infra/deploy/publish.py`;
2. the reusable `.github/workflows/deploy-nas.yml` reference and its `toolkit_ref` input.

The NAS independently verifies that the submitted manifest came from the caller repository's allowed `main` workflow, required successful jobs, expected image repositories, and an unchanged Compose baseline. Images must be immutable `@sha256:` references.

This repository does not contain production service policies, NAS credentials, private runtime configuration, or application-specific hooks.
