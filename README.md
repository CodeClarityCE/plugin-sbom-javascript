# Service - SBOM (JS)

<br>

<div align="center">
    <img src="https://user-images.githubusercontent.com/124595411/233356880-fdc7ea8a-8b1d-4991-8726-67b47e91df9e.svg" width="400px" />
</div>

<br>

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