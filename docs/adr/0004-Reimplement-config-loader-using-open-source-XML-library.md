# Reimplement config loader using open source XML library

* Status: proposed
* Deciders: Kevin Sheldrake, Alex Mihaiuc
* Date: 2020-11-11

## Context and Problem Statement

The existing configuration loader uses the MSXML API that only exists on
Windows.

## Considered Options

* Reimplement config loader using open source XML library and apply top both
  versions
* Build new config loader for Linux version using open source XML library, but
  retain existing Windows MSXML code

## Decision Outcome

Chosen option: "Reimplement", because:
* Reimplmenting and applying to both versions increases code sharing and
  therefore reduces maintenance burden.
* Multiple open source libraries exist that can read XML and are available for
  both platforms.

