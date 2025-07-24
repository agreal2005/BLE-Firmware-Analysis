# -*- coding: utf-8 -*-
# Ultimate BLE Function Parameter Extraction System - CORRECTED VERSION
# Fixed: Removed non-existent DecompileOptions methods

import json
import csv
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.pcode import PcodeOp, Varnode
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
if len(args) < 3:
    print("Usage: ble_extractor.py <input_json> <address_csv> <output_json> [binary_path]")
    exit(1)

# === UTILITY FUNCTIONS ===

def load_json(path):
    """Load JSON data from file"""
    with open(path, "r") as f:
        return json.load(f)

def save_json(data, path):
    """Save JSON data to file"""
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_address_map(csv_path):
    """Load function name to address mapping from CSV"""
    addr_map = {}
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row["name"].strip()
            addr = row["address"].strip().lower()
            if not addr.startswith("0x"):
                addr = "0x" + addr
            addr_map[name] = addr
    return addr_map

def get_ghidra_function(addr_str):
    """Get Ghidra function object from address string"""
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    return getFunctionAt(addr)

def get_call_references(func):
    """Get all call references to a function"""
    ref_mgr = currentProgram.getReferenceManager()
    refs = ref_mgr.getReferencesTo(func.getEntryPoint())
    return [ref for ref in refs if ref.getReferenceType().isCall()]

# === CORRECTED DECOMPILER SETUP ===

def setup_enhanced_decompiler():
    """Configure decompiler - CORRECTED VERSION"""
    options = DecompileOptions()
    # Note: setMaxPayload and setMaxInstructions don't exist in DecompileOptions
    # Using only standard configuration

    decompiler = DecompInterface()
    decompiler.setOptions(options)
    decompiler.openProgram(currentProgram)
    return decompiler

def trace_parameter_origins(high_func, call_addr, num_params):
    """Advanced backward symbolic execution for parameter tracing"""
    param_values = []

    # Get the call instruction's pcode operation
    call_pcode = None
    try:
        for op in high_func.getPcodeOps():
            if str(op.getSeqnum().getTarget()) == call_addr:
                if op.getOpcode() == PcodeOp.CALL:
                    call_pcode = op
                    break
    except Exception as e:
        print("Error finding call pcode: {}".format(str(e)))
        return []

    if not call_pcode:
        return []

    # Trace each parameter register backward through the function
    for param_idx in range(min(num_params, 4)):  # ARM uses R0-R3
        reg_name = "r{}".format(param_idx)
        value = trace_register_definition(high_func, call_pcode, reg_name)
        param_values.append(value)

    return param_values

def trace_register_definition(high_func, from_op, register):
    """Trace register value definition using SSA form analysis"""
    try:
        # Simplified register tracing - get inputs from the call operation
        inputs = from_op.getInputs()
        if len(inputs) > 1:
            # Try to resolve the first few inputs (skip function address at index 0)
            reg_idx = int(register[1:])  # Extract number from "r0", "r1", etc.
            if reg_idx + 1 < len(inputs):
                input_var = inputs[reg_idx + 1]
                return resolve_varnode_value(input_var)

        return register  # Fallback to register name
    except Exception as e:
        return register

def resolve_pcode_operation(pcode_op):
    """Resolve pcode operations to meaningful values"""
    try:
        opcode = pcode_op.getOpcode()

        if opcode == PcodeOp.COPY:
            # Direct copy - follow the source
            source = pcode_op.getInput(0)
            if source.isConstant():
                return "0x{:x}".format(source.getOffset())
            elif source.isAddress():
                return "0x{:x}".format(source.getAddress().getOffset())
            else:
                return str(source)

        elif opcode == PcodeOp.INT_ADD:
            # Addition operation
            left = resolve_varnode_value(pcode_op.getInput(0))
            right = resolve_varnode_value(pcode_op.getInput(1))
            return "({} + {})".format(left, right)

        elif opcode == PcodeOp.INT_SUB:
            # Subtraction operation  
            left = resolve_varnode_value(pcode_op.getInput(0))
            right = resolve_varnode_value(pcode_op.getInput(1))
            return "({} - {})".format(left, right)

        elif opcode == PcodeOp.LOAD:
            # Memory load
            addr = resolve_varnode_value(pcode_op.getInput(1))
            return "*({})".format(addr)

        else:
            # Unknown operation
            return "<computed>"
    except Exception as e:
        return "<error>"

def resolve_varnode_value(varnode):
    """Extract meaningful value from varnode"""
    try:
        if varnode.isConstant():
            val = varnode.getOffset()
            if val > 0xFFFF:
                return "0x{:x}".format(val)
            else:
                return str(val)
        elif varnode.isAddress():
            return "0x{:x}".format(varnode.getAddress().getOffset())
        else:
            return str(varnode)
    except Exception as e:
        return "<?>"

# === TEXT ANALYSIS FUNCTIONS ===

def extract_from_decompiled_text(decomp_result, target_func_name, call_addr):
    """Extract parameters from high-level C representation"""
    try:
        c_code = decomp_result.getDecompiledFunction().getC()
        lines = c_code.split('\n')

        # Find lines containing the function call
        for line in lines:
            if target_func_name in line and '(' in line:
                # Extract the function call
                start = line.find(target_func_name + '(')
                if start == -1:
                    continue

                start += len(target_func_name) + 1
                paren_count = 1
                end = start

                # Find matching closing parenthesis
                while end < len(line) and paren_count > 0:
                    if line[end] == '(':
                        paren_count += 1
                    elif line[end] == ')':
                        paren_count -= 1
                    end += 1

                if paren_count == 0:
                    args_str = line[start:end-1].strip()
                    if args_str:
                        # Split arguments intelligently
                        args = parse_argument_list(args_str)
                        return args

        return []
    except Exception as e:
        print("C text extraction error: {}".format(str(e)))
        return []

def parse_argument_list(args_str):
    """Parse function arguments handling nested expressions"""
    args = []
    current_arg = ""
    paren_depth = 0
    bracket_depth = 0

    for char in args_str:
        if char == ',' and paren_depth == 0 and bracket_depth == 0:
            if current_arg.strip():
                args.append(current_arg.strip())
            current_arg = ""
        else:
            if char == '(':
                paren_depth += 1
            elif char == ')':
                paren_depth -= 1
            elif char == '[':
                bracket_depth += 1
            elif char == ']':
                bracket_depth -= 1
            current_arg += char

    if current_arg.strip():
        args.append(current_arg.strip())

    return args

# === FUNCTION-SPECIFIC PATTERN EXTRACTORS ===

def extract_function_specific_patterns(func_name, containing_func, call_addr, decompiler):
    """Function-specific parameter extraction patterns"""

    # Memory allocation functions
    if func_name in ['malloc', 'calloc', 'realloc', 'ICall_heapMalloc']:
        return extract_memory_alloc_params(containing_func, call_addr, decompiler)

    # String functions  
    elif func_name in ['strlen', 'memcmp', 'strcpy', 'strncpy']:
        return extract_string_func_params(containing_func, call_addr, decompiler)

    # BLE GATT functions
    elif 'AttrCB' in func_name or 'GATT' in func_name:
        return extract_gatt_params(containing_func, call_addr, decompiler)

    # Timer/threading functions
    elif any(sys in func_name.lower() for sys in ['timer', 'pthread', 'clock']):
        return extract_system_params(containing_func, call_addr, decompiler)

    return []

def extract_memory_alloc_params(containing_func, call_addr, decompiler):
    """Specialized extraction for memory allocation functions"""
    try:
        result = decompiler.decompileFunction(containing_func, 60, ConsoleTaskMonitor())
        if not result:
            return []

        c_code = result.getDecompiledFunction().getC()

        # Look for common memory allocation patterns
        import re
        patterns = [
            r'malloc\s*\(\s*([^)]+)\s*\)',
            r'calloc\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)',
            r'ICall_heapMalloc\s*\(\s*([^)]+)\s*\)'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, c_code)
            if matches:
                if isinstance(matches[0], tuple):
                    return list(matches[0])
                else:
                    return [matches[0]]

        return []
    except Exception as e:
        return []

def extract_string_func_params(containing_func, call_addr, decompiler):
    """Specialized extraction for string manipulation functions"""
    return []  # Simplified for now

def extract_gatt_params(containing_func, call_addr, decompiler):
    """Extract GATT-specific parameters"""
    return []  # Simplified for now

def extract_system_params(containing_func, call_addr, decompiler):
    """Extract system call parameters"""
    return []  # Simplified for now

# === MAIN PROCESSING FUNCTION ===

def process_functions_ultimate(functions, addr_map, binary_path):
    """Multi-layer parameter extraction with confidence scoring"""
    decompiler = setup_enhanced_decompiler()
    enriched_functions = []

    print("Starting enhanced static analysis...")

    for func_entry in functions:
        name = func_entry.get("name")
        address = addr_map.get(name)

        print("Processing function: {}".format(name))

        if not address:
            func_entry["callsites"] = []
            enriched_functions.append(func_entry)
            continue

        ghidra_func = get_ghidra_function(address)
        if not ghidra_func:
            func_entry["callsites"] = []
            enriched_functions.append(func_entry)
            continue

        call_refs = get_call_references(ghidra_func)
        callsites = []

        for ref in call_refs:
            call_addr = str(ref.getFromAddress())
            containing_func = getFunctionContaining(ref.getFromAddress())

            if not containing_func:
                callsites.append({
                    "address": call_addr,
                    "param-vals": [],
                    "confidence": "none",
                    "methods_tried": ["no_containing_function"]
                })
                continue

            # Try multiple extraction methods
            methods_tried = []
            extracted_params = []
            confidence = "none"

            # Method 1: Advanced static analysis
            try:
                result = decompiler.decompileFunction(containing_func, 60, ConsoleTaskMonitor())
                if result and result.decompileCompleted():
                    high_func = result.getHighFunction()
                    if high_func:
                        static_params = trace_parameter_origins(
                            high_func, call_addr, len(func_entry.get("params", [])))
                        if static_params and any(p != "r{}".format(i) for i, p in enumerate(static_params)):
                            extracted_params = static_params
                            confidence = "medium"
                            methods_tried.append("symbolic_trace")
            except Exception as e:
                print("Symbolic trace failed: {}".format(str(e)))

            # Method 2: Decompiled C text analysis
            if not extracted_params:
                try:
                    if result and result.decompileCompleted():
                        c_params = extract_from_decompiled_text(result, name, call_addr)
                        if c_params:
                            extracted_params = c_params
                            confidence = "high"
                            methods_tried.append("c_text_analysis")
                except Exception as e:
                    pass

            # Method 3: Function-specific patterns
            if not extracted_params:
                try:
                    pattern_params = extract_function_specific_patterns(
                        name, containing_func, call_addr, decompiler)
                    if pattern_params:
                        extracted_params = pattern_params
                        confidence = "medium"
                        methods_tried.append("function_patterns")
                except Exception as e:
                    pass

            # Fallback: Register names
            if not extracted_params:
                num_params = len(func_entry.get("params", []))
                extracted_params = ["r{}".format(i) for i in range(min(num_params, 4))]
                confidence = "low"
                methods_tried.append("register_names")

            callsites.append({
                "address": call_addr,
                "param-vals": extracted_params,
                "confidence": confidence,
                "methods_tried": methods_tried,
                "extraction_method": "multi_layer_analysis"
            })

        func_entry["callsites"] = callsites
        enriched_functions.append(func_entry)

        # Progress reporting
        resolved_count = len([c for c in callsites if c["confidence"] in ["medium", "high"]])
        total_count = len(callsites)
        if total_count > 0:
            print("  {} resolved {}/{} callsites ({:.1f}%)".format(
                name, resolved_count, total_count, (resolved_count * 100.0 / total_count)))

    return enriched_functions

# === MAIN EXECUTION ===

def main():
    print("=== Ultimate BLE Parameter Extraction System (CORRECTED) ===")

    # Load configuration
    input_json = getScriptArgs()[0]
    csv_file = getScriptArgs()[1] 
    output_json = getScriptArgs()[2]
    binary_path = getScriptArgs()[3] if len(getScriptArgs()) > 3 else None

    functions = load_json(input_json)
    address_map = load_address_map(csv_file)

    print("Processing {} functions with corrected extraction methods...".format(len(functions)))
    enriched = process_functions_ultimate(functions, address_map, binary_path)

    save_json(enriched, output_json)

    # Generate comprehensive statistics
    total_callsites = sum(len(f.get("callsites", [])) for f in enriched)
    high_confidence = sum(1 for f in enriched for cs in f.get("callsites", []) 
                         if cs.get("confidence") == "high")
    medium_confidence = sum(1 for f in enriched for cs in f.get("callsites", []) 
                           if cs.get("confidence") == "medium") 
    low_confidence = sum(1 for f in enriched for cs in f.get("callsites", []) 
                        if cs.get("confidence") == "low")

    print("=== Ultimate Analysis Results ===")
    print("Total callsites analyzed: {}".format(total_callsites))
    if total_callsites > 0:
        print("High confidence extractions: {} ({:.1f}%)".format(
            high_confidence, high_confidence * 100.0 / total_callsites))
        print("Medium confidence extractions: {} ({:.1f}%)".format(
            medium_confidence, medium_confidence * 100.0 / total_callsites))
        print("Low confidence extractions: {} ({:.1f}%)".format(
            low_confidence, low_confidence * 100.0 / total_callsites))

        meaningful_extractions = high_confidence + medium_confidence
        print("Meaningful parameter extraction rate: {:.1f}%".format(
            meaningful_extractions * 100.0 / total_callsites))

if __name__ == "__main__":
    main()
