<div align="center">
    <h1>confine</h1>
    <p>Containers, but for dynamic malware analysis</p>
</div>

__confine__ is a light container runtime for dynamically analyzing suspicious executables.
It's like Docker, but for threat analysts!

## Features

TODO

## Usage

### Installing 

To install `confine`, use `cargo`:

```
$ cargo install confine
```

### Analysis

To dynamically analyze a sample, we must first create a workspace with a `Confinement` policy to
specify how our containerized environment will be provisioned.

```
$ mkdir workspace/
$ touch workspace/Confinement
```

Having a workspace is good for compartmentalizing other necessary dependencies that is used in the
container, whether its a locally built rootfs, source code, configurations, etc.

A `Confinement` is __confine__'s version of a `Dockerfile`, but for provisioning 
container environments for tracing an executable. It is written in a YAML format that contains
the following:

```
sample:
    name: My sample name
    description: Some info about the sample
    url: https://optional-url-for-sample.xyz/sample.zip

execution
    - name: Unpack
      trace: false
      description: First, we need to decompress the sample
      command: ["unzip", "-P", "infected", "sample.zip']

    - name: Execute
      trace: true
      description: We can now run and trace it
      command: ["./sample"]
```

TODO: enforcement and blocking

## License

[MIT License](https://codemuch.tech/docs/license.txt)
