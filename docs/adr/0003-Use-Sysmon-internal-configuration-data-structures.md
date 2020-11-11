# Use Sysmon internal configuration data structures

* Status: proposed
* Deciders: Kevin Sheldrake, Alex Mihaiuc
* Date: 2020-11-11

## Context and Problem Statement

Sysmon stores the loaded configuration in a packed binary format, which makes
it easier for the service to send it to the Windows driver.  An alternative
format might be easier to navigate and improve code readability.
Do we want to use the same internal data structures or invent new ones?

## Considered Options

* Use Sysmon data structures
* Invent new data structures

## Decision Outcome

Chosen option: "Use Sysmon data structures", because:
* The Windows version will retain the existing data structures regardless to
  support the continuing requirement to send the config to the Windows driver.
* Implementing a new data structure for Linux version will result in the code
  diverging resulting in additional dev and testing burdens.
* It will be possible (if not already existing) to build an API on top of the
  existing data structures to ease use of it.
* The existing filtering code is built on the existing data structures.

