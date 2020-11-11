# Refactor and use existing filtering

* Status: proposed
* Deciders: Kevin Sheldrake, Alex Mihaiuc
* Date: 2020-11-11

## Context and Problem Statement

The existing filtering is contained in the rules.cpp source file. This file
also contains code specific to the Windows driver. The rules within it operate
on the internal data structures built by the configuation loader.
Do we want to use the existing filtering code or reimplement?

## Considered Options

* Refactor and use existing filtering code
* Reimplement filtering code for Linux version
* Reimplement filtering code for both versions

## Decision Outcome

Chosen option: "Refactor and use existing filtering", because:
* Existing filtering code works.
* The expected refactoring work - to split the Windows driver-specific code
  from the filtering code - is expected to be low compared to the work
  required to reimplement.
* Reimplementing the filtering just for the Linux version will result in code
  divergance, increasing the maintenance burden.
* Reimplementing for both versions introduces risk of changing how the rules
  are interpreted, leading to bugs and/or user issues.

