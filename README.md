# Static Analysis Tool

This project is a static code analysis tool designed to detect security vulnerabilities, particularly SQL injection points, in Python scripts by matching patterns. It parses Python code to identify potentially harmful data flows based on predefined patterns.

## Getting Started

To analyze a file, use the following command:
```
python ./py_analyser.py <script_to_analyze> <patterns_file>
```
For example:
```
python ./py_analyser.py slice_1.py my_patterns.json
```

- **script_to_analyze**: Python script to be checked for vulnerabilities.
- **patterns_file**: JSON file containing vulnerability patterns to match in the code.

## Project Structure

### Main Components

- **py_analyser.py**: The main script, which:
  - Parses the target script into an abstract syntax tree (AST).
  - Traverses the AST to detect patterns based on sources, sinks, sanitizers, and labels.
  - Matches detected patterns against the provided JSON configuration to identify vulnerabilities.

### Supporting Modules

- **Pattern.py**: Defines `Pattern` class for managing vulnerability patterns. Patterns specify data flows that pose security risks.
- **Policy.py**: Provides rules and policies for analysis based on specific vulnerabilities.
- **Label.py** and **Multilabel.py**: Handle labeling of AST nodes to track data flow.
- **Sanitizer.py**: Manages sanitization checks, marking variables as sanitized where appropriate.
- **Source.py** and **Sink.py**: Define sources (e.g., user inputs) and sinks (e.g., database operations) where data is ingested or outputted.
- **Vulnerabilities.py**: Manages vulnerability types and tracks detected vulnerabilities during the analysis.
- **auxiliary.py**: Contains helper functions for AST traversal, pattern matching, and logging.

### Data Files

- **patterns.json**: Contains predefined vulnerability patterns, specifying sources, sinks, and sanitization rules.
- **slices/**: This folder includes various Python slices used as examples to test the analyzer’s detection capabilities. Each example has associated pattern files and outputs.

### Output

Results of the analysis are saved in JSON format, detailing detected vulnerabilities and their locations in the source file. The outputs can be found in the `output/` folder.

---

This tool is intended for educational use in analyzing and detecting common security vulnerabilities in Python code.

