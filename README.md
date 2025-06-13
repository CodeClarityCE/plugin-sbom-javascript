<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
  <img alt="codeclarity-logo" src="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
</picture>
<br>
<br>

Secure your software empower your team.

[![License](https://img.shields.io/github/license/codeclarityce/codeclarity-dev)](LICENSE.txt)

<details open="open">
<summary>Table of Contents</summary>

- [CodeClarity Plugin - SBOM](#codeclarity-plugin---sbom)
  - [Contributing](#contributing)
  - [Reporting Issues](#reporting-issues)
  - [Purpose](#purpose)
  - [Current Features](#current-features)
  - [Future Features](#future-features)
  - [Dev Usage](#dev-usage)


</details>

---

# CodeClarity Plugin - SBOM

## Contributing

If you'd like to contribute code or documentation, please see [CONTRIBUTING.md](https://github.com/CodeClarityCE/codeclarity-dev/blob/main/CONTRIBUTING.md) for guidelines on how to do so.

## Reporting Issues

Please report any issues with the setup process or other problems encountered while using this repository by opening a new issue in this project's GitHub page.

## Purpose

The sbom service creates an inventory of dependencies of an application's source code directory.

<br> It is the first stage of the Software Composition Analysis process.

1. Identify dependencies (SBOM)
2. Identify known vulnerabile dependencies (This service)
3. Identify licenses & license compliance
4. Compute and verify upgrades to the application

<br>

## Current Features

1. Identifies package-managed dependencies

<br>

## Future Features

1. Identify self-managed dependencies (script tags, library files, etc...)

<br>

## Dev Usage

To execute this service for development purposes, two paramters need to be supplied to the IDE or terminal:

```
Usage of sbom-js:
  -output-file string
    	Absolute Path to the output file (Required)
  -source-code-directory string
    	Absolute Path to the source code directory (Required)
```
<br>