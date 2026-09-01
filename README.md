# Application-Level Routing Experiments — Archived

> **Status: public development discontinued.**
>
> This repository is kept only as a historical record of an experimental Windows networking study. The current implementation, operational configuration, deployment infrastructure, build artifacts and application-specific routing rules are **not published in this repository**.

## About the project

This project started as a proof of concept to study whether a desktop application could use more than one network path at the same time without changing the system-wide default route.

The experiments covered topics such as:

- application-level selective routing;
- TCP/UDP path separation;
- Windows process and network lifecycle;
- connection observability and diagnostics;
- fail-safe cleanup and process supervision;
- packaging Python applications for Windows.

The proof of concept reached its research goal, and public development in this repository has been discontinued.

## Public snapshot

To keep this repository focused on the learning/research aspect, this snapshot intentionally does **not** contain:

- current operational routing logic;
- application-specific destinations or rules;
- relay discovery or selection logic;
- production authentication/infrastructure configuration;
- current build pipeline or distributable binaries;
- step-by-step usage instructions.

The remaining files are only placeholders/documentation for the archived public repository.

## Support

No public builds, setup support or operational instructions are provided from this repository.

## Why keep it public?

The repository remains available as a record of the engineering study and of the topics explored during development. Future or private iterations are outside the scope of this public archive.
