#!/bin/bash

# List of all example files
examples=(
    "1a-basic-flow"
    "1b-basic-flow"
    "2-expr-binary-ops"
    "3a-expr-func-calls"
    "3b-expr-func-calls"
    "5a-loops-unfolding"
    "5b-loops-unfolding"
    "6a-sanitization"
    "6b-sanitization"

    # Add other examples as needed
)

#"3c-expr-attributes"
# Iterate through each example
for example in "${examples[@]}"; do
    echo "Running example: $example"

    # Run the Python script for the current example
    python3 py_analyser.py "slices/$example.py" "slices/$example.patterns.json" > "slices/$example.generated.json"

    # Check diff between generated output and expected output
    diff "slices/$example.output.json" "slices/$example.generated.json" > /dev/null

    # Check the result of the diff command
    echo "*Intended output*"
    cat "slices/$example.output.json"
    echo "*Our output*"
    cat "slices/$example.generated.json"

    echo "-------------------------------------------"
    echo "-------------------------------------------"
done
