import ast
import astexport.export
import json
import sys
import os

def check_arguments_number(arguments):
    if len(arguments) < 3:
        print("Error: Check the number of arguments, LESS than expected!")
        print("Usage: python3 script_name.py file_name.json")
        sys.exit(1)
        
    elif len(arguments) > 3:
        print("Error: Check the number of arguments, MORE than expected!")
        print("Usage: python3 script_name.py file_name.json")
        sys.exit(1)

def parse_python(python_file):
    try:
        if not python_file.endswith('.py'):
            raise ValueError(f"Error: '{python_file}' is not a Python file (does not have a .py extension)!")

        # Read the content of the file
        with open(python_file, "r") as file:
            python_content = file.read()

        # Parse Python code into AST
        parsed_code = ast.parse(python_content)

        # Convert AST to a dictionary-like representation
        ast_dict = astexport.export.export_dict(parsed_code)

        # Convert the AST dictionary to a JSON-like string
        #ast_json_like_string = json.dumps(ast_dict, indent=4)
        #ast_json = json.dumps(ast_dict, indent=4)
        
        return ast_dict

    except FileNotFoundError:
        print("Error: File not found!")
        sys.exit(1)

    except ValueError as ve:
        print(ve)
        sys.exit(1)
    
    except PermissionError:
        print("Error: Permission denied to read the file!")
        sys.exit(1)

    except SyntaxError as e:
        print(f"Error: Syntax error in the Python code - {e}")
        sys.exit(1)

    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


"""
    Read and parse JSON data from a file.

    Parameters:
    - file (str): Path to the JSON file.

    Returns:
    - dict: Parsed JSON data.

    Raises:
    - FileNotFoundError: If the specified file is not found.
    - IsADirectoryError: If the specified file is a directory.
    - PermissionError: If the user has insufficient permissions to read the file.
    - json.JSONDecodeError: If the file is not in valid JSON format.
    - Exception: For other unexpected errors.
"""
def read_json_file(json_file):
    try:
        with open(json_file, "r") as input_file:
             return json.load(input_file)

    except FileNotFoundError:
        print(f"Error: The file '{json_file}' doesn't exist!")
        sys.exit(1)

    except IsADirectoryError:
        print(f"Error: '{json_file}' is a directory, not a file!")
        sys.exit(1)

    except PermissionError:
        print(f"Error: Permission denied to read '{json_file}'!")
        sys.exit(1)

    except json.JSONDecodeError:
        print(f"Error: The file '{json_file}' is not in valid JSON format!")
        sys.exit(1)

    except Exception as e:
        print(f"Unexpected error while reading '{json_file}': {e}")
        sys.exit(1)

"""
    Extract the base filename from a file path.

    Parameters:
    - file_path (str): The file path.

    Returns:
    - str: The base filename without the path and extension.
"""
def extract_filename(python_input):
    return os.path.splitext(os.path.basename(python_input))[0]

def write_output(data, filename):
    # Ensure the file path is in the 'output' directory
    file_path = os.path.join("output", f"{filename}.output.json")

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    # Writing the JSON-formatted string to the file
    with open(file_path, "w") as file:
        file.write(data)



