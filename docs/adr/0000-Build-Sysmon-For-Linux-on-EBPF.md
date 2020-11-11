# Build Sysmon For Linux on eBPF

* Status: accepted
* Deciders: Mark Russinovich
* Date: 2020-07-14

Technical Story: https://twitter.com/markrussinovich/status/1283039153920368651

## Context and Problem Statement

We want to build a version of Sysmon that will run on Linux.
What underlying telemetry technology should it use?

## Considered Options

* [eBPF](https://ebpf.io) - eBPF is no longer an acronym
* kaudit - The Linux auditing subsystem
* Bespoke kernel module

## Decision Outcome

Chosen option: "eBPF", because ProcMon For Linux was built on eBPF.

