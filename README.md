# Bazel Python Snyk SBOM Generator

This repository provides a tool to generate a Software Bill of Materials (SBOM) in the CycloneDX format from a Bazel dependency graph. The tool parses Bazel's XML output to extract dependencies and generates a CycloneDX SBOM, which can be used for software supply chain security and compliance purposes.

## Features

- Parses Bazel dependency graphs to extract dependencies.
- Generates a CycloneDX SBOM in JSON format.
- Supports transitive dependency resolution if dependencies are installed.
- Validates the generated SBOM against the CycloneDX schema.

## Requirements

To run this tool, you need the following:

- Python 3.10.14 or higher
- Python dependencies specified in requirements.txt
- bazel dependency graph file

```bash
pip install -r requirements.txt
```
The following command outputs the dependencies in XML format for a given bazel target, that we can further process to be consumed by Snyk.

```
bazel query "deps(//app/package:target)" --noimplicit_deps --output xml > bazel_deps.xml
```

## Usage

The tool is designed to be run from the command line. It takes a Bazel dependency graph file as input and outputs a CycloneDX SBOM in JSON format.

### Command Line Options

- `input_file`: Path to the Bazel dependency graph file (XML format).
- `output_file`: Path where the generated SBOM will be saved (JSON format).

### Example

To convert a Bazel dependency graph to a CycloneDX SBOM, use the following command:

```bash

python index.py convert path/to/bazel_deps.xml path/to/output_sbom.json
```

This will generate a CycloneDX SBOM in JSON format and save it to the specified output file.
