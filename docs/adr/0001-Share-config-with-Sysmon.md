# Share config with Sysmon

* Status: accepted
* Deciders: Mark Russinovich, Luke Kim
* Date: 2020-10-28

## Context and Problem Statement

Do we want to use the same configuration format as Sysmon on Windows or create
a separate project that shares the name?

## Considered Options

* Share config with Windows version
* Create new config for Linux version
* Create new config for both versions, continue to support Windows config

## Decision Outcome

Chosen option: "Share config with Windows version", because:
* Users already familiar with Windows config
* Makes Sysmon cross-platform as opposed to two tools sharing a name
* Availability of existing configs (Swift on Security, for ex) makes staying
  with existing config sensible

