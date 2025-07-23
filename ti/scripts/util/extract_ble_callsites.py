# Ghidra Python (Jython) script: extract_ble_callsites.py
# Usage: analyzeHeadless ... -postScript extract_ble_callsites.py <func_json_in> <json_out>
# Input: matched_functions_enriched.json (list of function dicts with "name")
# Output: JSON file, same functions, now with a "callsites" list (address, literal arg list)

import json
import sys
from ghidra.program.model.symbol import RefType

def load_functions(path):
    with open(path, 'r') as f:
        return json.load(f)

def save_functions(data, path):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def get_func_by_name(name, function_manager):
    for f in function_manager.getFunctions(True):
        if f.getName() == name:
            return f
    return None

def get_call_references(function):
    ref_mgr = currentProgram.getReferenceManager()
    refs = ref_mgr.getReferencesTo(function.getEntryPoint())
    return [ref for ref in refs if ref.getReferenceType().isCall()]

def extract_literal_args(instruction):
    vals = []
    try:
        ops = instruction.getOpObjects(1)
        for op in ops:
            val = None
            if hasattr(op, "getValue"):
                val = op.getValue()
            elif hasattr(op, "getOffset"):
                val = hex(op.getOffset())
            else:
                val = str(op)
            vals.append(val)
    except:
        pass
    return vals

def main():
# Inside extract_ble_callsites.py

    args = getScriptArgs()

    if len(args) != 2:
        print("Usage: <this_script.py> <input_json> <output_json>")
        exit()

    json_in, json_out = args

    func_list = load_functions(json_in)
    fm = currentProgram.getFunctionManager()

    for entry in func_list:
        fn_name = entry.get('name')
        gfunc = get_func_by_name(fn_name, fm)
        callsites = []
        if gfunc is not None:
            for ref in get_call_references(gfunc):
                from_addr = ref.getFromAddress()
                insn = currentProgram.getListing().getInstructionAt(from_addr)
                param_vals = extract_literal_args(insn) if insn else []
                callsites.append({
                    "address": str(from_addr),
                    "param-vals": param_vals
                })
        entry['callsites'] = callsites

    save_functions(func_list, json_out)
    print("Done. Wrote callsite-enriched JSON to", json_out)

main()

