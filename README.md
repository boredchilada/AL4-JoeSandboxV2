# JoeSandboxV2 Service for Assemblyline

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Assemblyline 4](https://img.shields.io/badge/assemblyline-4.0+-blue.svg)](https://cybercentrecanada.github.io/assemblyline4_docs/)

`docker pull ghcr.io/boredchilada/al4-joesandbox:latest`

## Overview

JoeSandboxV2 is an Assemblyline service that retrieves and displays existing Joe Sandbox analysis results in IRJsonFixed format. This service searches for existing analyses by file hash and presents the results in Assemblyline.

[Joe Sandbox](https://www.joesecurity.org/) is a deep malware analysis platform that detects and analyzes potential malicious files, URLs, and other artifacts. This service allows you to leverage existing Joe Sandbox analyses within your Assemblyline workflow.

## Features

- Searches for existing Joe Sandbox analyses by file hash
- Retrieves detailed analysis information
- Downloads and processes IRJsonFixed reports
- Displays results in Assemblyline with scoring
- Extracts key information such as:
  - Detection verdict and score
  - Network indicators (domains, IPs, URLs)
  - Behavior information
  - Dropped files

## Project Structure

The service is organized into a modular structure for better maintainability:

- `joesandbox.py`: Main entry point for the service
- `joesandboxv2/`: Package containing the service modules
  - `__init__.py`: Package initialization
  - `service.py`: Main service class
  - `api_client.py`: Client for interacting with the Joe Sandbox API
  - `report_processor.py`: Coordinator for processing reports
  - `processors/`: Package containing specialized processors
    - `__init__.py`: Package initialization
    - `ontology_processor.py`: Processor for creating and managing ontology
    - `signature_processor.py`: Processor for handling signatures
    - `network_processor.py`: Processor for network-related data
    - `file_processor.py`: Processor for file-related data

## Configuration

The service requires the following configuration:

- `api_key`: Your Joe Sandbox API key
- `api_url`: Joe Sandbox API URL (default: https://www.joesandbox.com/api/)

## Installation

Paste the service_manifest.yml into your "Add service" button

### Environment Variables

- `JBX_API_KEY`: Your Joe Sandbox API key

## Usage

The service accepts any file type and will:

1. Extract the SHA256 hash from the file
2. Search Joe Sandbox for analyses matching the hash
3. If found, retrieve the most recent analysis details
4. Download and process the IRJsonFixed report
5. Display the results in Assemblyline

## Heuristics

The service uses the following heuristics:

- Heuristic 1: Joe Sandbox detected the file as malicious (Score: 1000)
- Heuristic 2: Joe Sandbox detected the file as suspicious (Score: 500)
- Heuristic 3: Joe Sandbox detected the file as clean or unknown (Score: 0)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- [Joe Security](https://www.joesecurity.org/) for providing the Joe Sandbox platform
- [Assemblyline](https://cybercentrecanada.github.io/assemblyline4_docs/) team for the service framework and help they provided!
