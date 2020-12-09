# Derisk XML library

* Status: proposed
* Deciders: Kevin Sheldrake, Alex Mihaiuc
* Date: 2020-11-11

## Context and Problem Statement

There are a number of open source libraries that implement reading XML
documents. Some are optimised for performance, others for ease of use, some
for completeness, and others as a balance between these requirements.
Do we want to derisk our choice of XML library by building a prototype first?

## Considered Options

* Derisk XML library by building prototype that can read the configuration
  option for "Process Create" events
* Choose XML library based on features and reimplement xml.cpp directly

## Decision Outcome

Chosen option: "Derisk XML library", because:
* Reimplementing xml.cpp will require significant development work plus the
  development of tests to confirm correctness.
* Choice of XML library is tricky as it is only though developing with them
  that important API and completeness limitations are discovered.
* Prototype development is minimal effort and can confirm XML library choice.
* Failure to prototype could lead to unsuitability of XML library only being
  identified after significant development effort has been expended.

