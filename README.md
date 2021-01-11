# confine

Dynamic threat detection sandbox

## Introduction

__confine__ is a lightweight app sandbox that helps triage suspicious executables. It's aimed to be a useful tool for any detection
engineer or malware analyst / reverser to dynamically analyze the behavior of varying samples, and empower other systems and infrastructure pipelines
that help automate the process of host-based detection.

## Features

### Detection

__confine__ operates as an elevated version of `strace`, containerizing traces and digging out various capabilities that
are detected in these traces for the analyst to further reason with.

```
$ confine -- ./suspicious_bin
```

### Mitigation

__confine__ supports mitigation by acting almost as a host-based firewall, allowing analysts to test detection policies in YAML against samples with ease, in
order to aid in the engineering of protective signatures and detection of IOCs.

```
$ confine --policy config.yml -- ./suspicious_bin
```

## Usage

```
$ cargo install
$ confine -h
```

## License

[MIT License](https://codemuch.tech/docs/license.txt)
