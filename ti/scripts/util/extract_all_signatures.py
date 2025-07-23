import sys, re, json
from pathlib import Path

# Improved regex patterns
FUNC_SIG_RE = re.compile(r'''
    ^\s*((?:[a-zA-Z_]\w*\s+)+?)  # return type (one or more words)
    ([a-zA-Z_]\w*)\s*            # function name
    \(([^;{}]*)\)\s*            # parameter list
    (;|\{)                      # ends with ; or {
''', re.MULTILINE | re.VERBOSE)

COMMENT_RE = re.compile(
    r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
    re.DOTALL | re.MULTILINE
)

def remove_comments(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return ' '  # replace comment with space to preserve line numbers
        return s
    return COMMENT_RE.sub(replacer, text)

def split_params(param_str):
    params, buf, depth = [], '', 0
    for ch in param_str:
        if ch == ',' and depth == 0:
            params.append(buf.strip())
            buf = ''
        else:
            if ch in '([{': depth += 1
            elif ch in ')]}': depth -= 1
            buf += ch
    if buf.strip(): params.append(buf.strip())
    if params == ['void']: return []
    return params

def parse_param(param_str):
    param_str = param_str.strip()
    if not param_str:
        return ("", "")
    
    # Handle function pointers
    if '(' in param_str and '*' in param_str:
        ptr_match = re.match(r'^(.*?\( *\*+ *)(\w*)( *\).*)$', param_str)
        if ptr_match:
            base = ptr_match.group(1).strip()
            name = ptr_match.group(2).strip()
            rest = ptr_match.group(3).strip()
            return (f"{base}){rest}", name if name else 'func_ptr')
    
    # Handle regular parameters
    m = re.match(r'^(.*?[^\s*])\s+(\**[\w\[\]]+)$', param_str)
    if m:
        typ, name = m.group(1), m.group(2)
        ptr_count = name.count('*')
        name = name.lstrip('*')
        typ = typ.strip() + (' *' * ptr_count) if ptr_count else typ.strip()
        return (typ, name)
    
    # Fallback
    parts = re.split(r'\s+', param_str)
    if len(parts) > 1:
        return (' '.join(parts[:-1]), parts[-1])
    return (param_str, 'param')

def is_valid_function_entry(entry):
    if not isinstance(entry, dict):
        return False

    required_keys = {'name', 'type', 'params'}
    if not all(k in entry for k in required_keys):
        return False

    name = entry['name']
    rtype = entry['type']
    params = entry['params']

    # Validate name
    if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z_]\w*', name):
        return False

    # Validate return type
    if not isinstance(rtype, str) or not rtype.strip():
        return False
    if len(rtype) > 50 or re.search(r'[^a-zA-Z0-9_*\s]', rtype.strip()):
        return False

    # Validate params
    if not isinstance(params, list):
        return False
    
    for p in params:
        if not isinstance(p, dict) or 'name' not in p or 'type' not in p:
            return False
        
        pname, ptype = p['name'], p['type']
        
        # Check parameter name
        if not isinstance(pname, str) or not pname.strip():
            return False
        if not re.fullmatch(r'[a-zA-Z_]\w*(\[\d*\])?', pname.split('[')[0]):
            return False
        
        # Check parameter type
        if not isinstance(ptype, str) or not ptype.strip():
            return False
        if len(ptype) > 50 or re.search(r'[^a-zA-Z0-9_*\s]', ptype.strip()):
            return False
        
        # Check for balanced parentheses in type (for function pointers)
        if ptype.count('(') != ptype.count(')'):
            return False

    return True

def extract_signatures(files):
    functions = {}
    for path in files:
        try:
            text = Path(path).read_text(errors='ignore')
            text = remove_comments(text)  # Remove comments first
        except Exception as e:
            print(f"[WARN] Could not read {path}: {e}")
            continue
            
        for match in FUNC_SIG_RE.finditer(text):
            ret, name, params_raw = match.group(1), match.group(2), match.group(3)
            if name in functions: 
                continue
                
            params = []
            for i, p in enumerate(split_params(params_raw)):
                typ, pname = parse_param(p)
                if not pname: 
                    pname = f"param_{i}"
                params.append({'name': pname, 'type': typ})
                
            if ret.strip():
                functions[name] = {
                    'name': name,
                    'type': ret.strip(),
                    'params': params
                }
    return list(functions.values())

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 extract_signatures.py <src_dir> <output.json>")
        sys.exit(1)
        
    src_dir, out_json = sys.argv[1], sys.argv[2]
    files = list(Path(src_dir).rglob('*.c')) + list(Path(src_dir).rglob('*.h'))
    sigs = extract_signatures(files)
    valid_funcs = [func for func in sigs if is_valid_function_entry(func)]
    
    with open(out_json, 'w') as f:
        json.dump(valid_funcs, f, indent=2)
        
    print(f"[INFO] Extracted {len(valid_funcs)} valid signatures (from {len(sigs)} raw matches).")