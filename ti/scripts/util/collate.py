import os
import csv
import subprocess
import re

def extract_functions_from_object_file(obj_file):
    """
    Uses 'nm' to extract function symbols from object file.
    Only considers symbols of type 'T' or 't' (text section = functions).
    """
    function_names = set()
    try:
        result = subprocess.run(['nm', obj_file], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) == 3:
                address, symbol_type, name = parts
                if symbol_type in ('T', 't'):
                    function_names.add(name)
    except Exception as e:
        print(f"Warning: Failed to parse {obj_file} - {e}")
    return function_names

def is_real_func(name):
    # Real C function names are valid identifiers: start with letter/underscore, then letters/digits/underscores
    return re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name) is not None

def main():
    ref_bins_dir = '../ref_bins'
    nist_database_dir = '../nist_database'
    output_csv = os.path.join(nist_database_dir, 'function_database.csv')

    all_function_names = set()
    for file in os.listdir(ref_bins_dir):
        if file.endswith('.o'):
            path = os.path.join(ref_bins_dir, file)
            names = extract_functions_from_object_file(path)
            all_function_names.update(names)

    # Filter only "real" functions
    real_funcs = sorted(fn for fn in all_function_names if is_real_func(fn))

    os.makedirs(nist_database_dir, exist_ok=True)
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['function_name'])
        for name in real_funcs:
            writer.writerow([name])

    print(f"Done! Extracted {len(real_funcs)} real functions into {output_csv}")

if __name__ == '__main__':
    main()

