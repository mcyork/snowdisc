# SnowDisc

SnowDisc is a YAML-driven file processing tool designed for flexible data manipulation and transformation tasks.

[![Build Windows Executable](https://github.com/mcyork/snowdisc/actions/workflows/build.yml/badge.svg)](https://github.com/mcyork/snowdisc/actions/workflows/build.yml)

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Learning Opportunities](#learning-opportunities)
- [Use Cases](#use-cases)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Configuration](#configuration)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Overview

SnowDisc is a versatile file processing application that demonstrates the power of YAML-driven configuration for file manipulation tasks. This project serves as both a practical tool and a learning exercise in Python development and GitHub workflow automation.

## Features

- YAML-based configuration for flexible file processing
- Ability to load, map, and combine various file types
- Customizable output generation

## Learning Opportunities

This project provided valuable experience in:

1. Python file I/O operations
2. YAML parsing and configuration management
3. PyInstaller for creating standalone executables
4. GitHub Actions for automated builds and CI/CD

## Use Cases

SnowDisc can be useful for:

- Data transformation and aggregation
- File format conversion
- Automated report generation

## Getting Started

The SnowDisc application is designed to be run from the command line. It requires a YAML configuration file to define the file processing rules.

### Prerequisites

- Python 3.7 or later
- YAML configuration file

### Installation

1. Clone the repository:
    ```
    git clone https://github.com/mcyork/snowdisc.git
    ```
2. Navigate to the project directory:
    ```
    cd snowdisc
    ```
3. Install the dependencies:
    ```
    pip install -r requirements.txt
    ```

### Usage

To run the application, use the following command:
```
python snowdisc.py
```
### Configuration

The application uses a YAML configuration file to define the file processing rules. The configuration file should be named `template_config.yaml` and placed in the root of the project directory.

See the `template_config.yaml` file for an example of the configuration file.

## Development

To set up the development environment:

1. Clone the repository:
   ```
   git clone https://github.com/mcyork/snowdisc.git
   ```
2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```
3. Install development dependencies:
   ```
   pip install -r requirements-dev.txt
   ```
## Contributing

Contributions to SnowDisc are welcome! If you'd like to contribute:

1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Make your changes and commit them with clear, descriptive messages
4. Push your changes to your fork
5. Submit a pull request to the main repository

Please ensure your code adheres to the project's coding standards.

## TODO

- output file type/name
- whatever comes up :)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

SnowDisc makes use of the following open-source libraries:
- PyYAML for YAML parsing
- Pandas for data manipulation
- PyInstaller for creating standalone executables

