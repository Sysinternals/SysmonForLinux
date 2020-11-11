# Use Sysmon Text Translate approach to specifying config schemas

* Status: proposed
* Deciders: Kevin Sheldrake, Alex Mihaiuc, Luke Kim
* Date: 2020-11-11

## Context and Problem Statement

Sysmon specifies the configuration schemas in the manifest.xml and manifest.tt
files, using Text Translate to generate C++ header files from these inputs.
Do we want to use the same approach on Linux?

## Considered Options

* Use Text Translate from dotnet, monodevelop or other source on Linux to
  generate headers from manifest files
* Reimplement Text Translate on Linux to acheive same result but with native
  code
* Abandon current Text Translate approach and build alternative

## Decision Outcome

Chosen option: "Use Text Translate", because:
* Text Translate works on Linux and generates 99% of files required.
* Remaining header file can be generated with simple python script.
* Reimplementing Text Translate will be costly, and difficult to test.
* Building an alternative solution will require either maintaining two systems
  of specifying configuration schemas (additional maintenance burden), or the
  new solution reworked back into the Windows version (additional development
  burden).


