# Python-Static-Code-Analyzer

This simple static analyzer tool finds common stylistic issues in Python code. I built this tool to help me learn more about static analysis and regular expressions. It is not meant to be a replacement for a full-fledged static analysis tool like Pylint or Pyflakes.

This is part of a [JetBrains Academy](https://hyperskill.org/projects/112) project.

## Requirements

-   Python 3

_No external libraries are required._

## Installation

1. Clone the repository

```shell
git clone https://github.com/dan-koller/Python-Generating-Randomness
```

2. Create a virtual environment\*

```shell
python3 -m venv venv
```

3. Run the app\*

```shell
python3 main.py <path to file>
```

_\*) You might need to use `python` and `pip` instead of `python3` and `pip3` depending on your system._

## Usage

Run the app with the path to a Python file or a directory containing Python files.

```shell
python3 main.py <path to file or directory>
```

## Example

```shell
python3 main.py test.py
```

```shell
test.py: Line 1: S001 Too long
test.py: Line 2: Unnecessary semicolon after a statement
test.py: Line 2: S006 More than two blank lines preceding a code line
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
