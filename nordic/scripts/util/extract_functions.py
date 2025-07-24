import re
import sys
import os
import json
import glob

def parse_params(param_str):
    params = []
    if param_str.strip() and param_str.strip() != "void":
        # Split params by comma outside parentheses (rare nested cases unlikely here)
        param_list = [p.strip() for p in param_str.split(',') if p.strip()]
        for param in param_list:
            # Split on last space to separate type and name (e.g. 'uint16_t conn_handle')
            parts = param.rsplit(' ', 1)
            if len(parts) == 2:
                ptype, pname = parts
            else:
                # Only type, no name? (e.g. void)
                ptype = parts[0]
                pname = ""
            params.append({"type": ptype.strip(), "name": pname.strip()})
    return params

def extract_svcall_functions_from_code(code):
    # Remove comments to avoid confusion inside macro's text
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)

    # Regex for matching SVCALL macro invocations
    # Format: SVCALL(SVC_NUM, return_type, func_name(params));
    svcall_re = re.compile(
        r'SVCALL\s*\(\s*[^,]+,\s*'          # SVC number (ignored)
        r'([^,]+),\s*'                      # return type (group 1)
        r'(\w+)\s*'                        # function name (group 2)
        r'\(\s*([^)]*)\s*\)\s*\)',          # params inside parentheses (group 3)
        re.MULTILINE | re.DOTALL
    )

    functions = []
    for match in svcall_re.finditer(code):
        ret_type = match.group(1).strip()
        name = match.group(2).strip()
        params_str = match.group(3).strip()
        params = parse_params(params_str)
        func = {
            "name": name,
            "return_type": ret_type,
            "params": params
        }
        functions.append(func)
    return functions

def extract_svcall_functions_from_files(directory):
    all_functions = []
    seen_names = set()  # To track function names already added
    for root, dirs, files in os.walk(directory):
        for fname in files:
            if fname.endswith('.c') or fname.endswith('.h'):
                path = os.path.join(root, fname)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    funcs = extract_svcall_functions_from_code(code)
                    for func in funcs:
                        if func["name"] not in seen_names:
                            seen_names.add(func["name"])
                            all_functions.append(func)
                except Exception as e:
                    print(f"Error reading {path}: {e}", file=sys.stderr)
    return all_functions


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <source_directory> <output_json_file>")
        sys.exit(1)

    src_dir = sys.argv[1]
    out_file = sys.argv[2]

    if not os.path.isdir(src_dir):
        print(f"Error: {src_dir} is not a directory or does not exist.")
        sys.exit(1)

    functions = extract_svcall_functions_from_files(src_dir)

    with open(out_file, 'w', encoding='utf-8') as jf:
        json.dump(functions, jf, indent=2)

    print(f"Extracted {len(functions)} SVCALL function signatures to {out_file}")

if __name__ == "__main__":
    main()

