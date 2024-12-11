import os
import readline

def complete_path(text, state):
    """Autocomplete file paths."""
    line = readline.get_line_buffer()
    dir_path = os.path.dirname(line) if os.path.dirname(line) else "."
    filenames = [f for f in os.listdir(dir_path) if f.startswith(text)]
    return filenames[state] if state < len(filenames) else None

# Enable autocomplete for file paths
readline.set_completer_delims(" \t\n;")
readline.parse_and_bind("tab: complete")
readline.set_completer(complete_path)

# Prompt the user for the file path
file_path = input("Enter the path to your text file: ")

try:
    # Open the file for reading
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Add "/" to the beginning of each line
    updated_lines = [f"/{line}" for line in lines]

    # Write the updated lines back to the file
    with open(file_path, 'w') as file:
        file.writelines(updated_lines)

    print("Slashes added to each line successfully.")
except FileNotFoundError:
    print("Error: The file was not found. Please check the file path and try again.")
except Exception as e:
    print(f"An error occurred: {e}")
