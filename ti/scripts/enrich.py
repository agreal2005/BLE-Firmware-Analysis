#!/usr/bin/env python3
"""
Enhanced NIST-compliant BLE function security analysis tool.
Analyzes function signatures and provides comprehensive security guidance
based on NIST SP 800-121r2, SP 800-53, and BLE security best practices.
"""

import json
import re
import argparse
import sys

# Enhanced security pattern definitions
CRYPTO_OPERATIONS = re.compile(r"(aes|encrypt|decrypt|ccm|ctr|cmac|ecc|p256|dh|ecdh|hmac|hash|sha|md5|cipher)", re.I)
CRYPTO_KEYS = re.compile(r"(key|ltk|irk|csrk|tk|stk|dhkey|publickey|privatekey|keymat)", re.I)
RNG_FUNCTIONS = re.compile(r"(rand|random|trng|prng|seed|entropy|nonce)", re.I)
MEMORY_FUNCTIONS = re.compile(r"(malloc|calloc|realloc|free|alloc|pool|heap|bget|brel)", re.I)
BUFFER_OPERATIONS = re.compile(r"(buf|buffer|data|payload|copy|move|set|cmp|mem)", re.I)
SIZE_PARAMS = re.compile(r"(len|length|size|count|max|min|offset|bound|limit)", re.I)
SECURITY_IDS = re.compile(r"(handle|id|conn|session|auth|bond|pair|addr|role|task)", re.I)
BLE_GATT = re.compile(r"(gatt|attr|service|char|desc|uuid|ccc|indication|notification)", re.I)
BLE_GAP = re.compile(r"(gap|adv|scan|connect|discover|white|accept|resolve)", re.I)
BLE_SMP = re.compile(r"(smp|pair|bond|ltk|irk|csrk|oob|passkey|numeric)", re.I)
UNSAFE_FUNCTIONS = re.compile(r"(strcpy|strcat|sprintf|gets|scanf|mktemp|system|exec|memcpy|strncpy)", re.I)
AUTH_FUNCTIONS = re.compile(r"(auth|verify|validate|check|confirm|approve)", re.I)
INIT_FUNCTIONS = re.compile(r"(init|initialize|setup|config|register|create)", re.I)

def nist_function_comment(fn):
    """Enhanced NIST-compliant function analysis."""
    name = fn["name"].lower()
    
    # Critical security violations
    if UNSAFE_FUNCTIONS.search(name):
        return ("NIST SP 800-53 SI-10: CRITICAL - Deprecated unsafe function. "
                "Replace with bounds-checked alternatives (strncpy, snprintf, etc.). "
                "High risk of buffer overflow, code injection, and memory corruption.")
    
    # Cryptographic operations
    if CRYPTO_OPERATIONS.search(name):
        if "aes" in name:
            return ("NIST SP 800-121r2 4.1: AES cryptographic function. "
                    "MUST use FIPS 140-2 approved implementation with >= 128-bit keys. "
                    "Validate key derivation, IV/nonce uniqueness, and secure key storage. "
                    "For BLE: Use AES-CCM for encryption/authentication.")
        elif "ecc" in name or "p256" in name:
            return ("NIST SP 800-121r2 4.2: ECC cryptographic function. "
                    "MUST use NIST P-256 curve minimum. Validate point operations, "
                    "secure random number generation, and side-channel protection.")
        elif "hash" in name or "sha" in name:
            return ("NIST SP 800-121r2: Cryptographic hash function. "
                    "Use SHA-256 minimum. Validate input length, prevent length extension attacks.")
        else:
            return ("NIST SP 800-121r2: Cryptographic operation. "
                    "Ensure FIPS 140-2 compliance, secure key management, and proper algorithm usage.")
    
    # Random number generation
    if RNG_FUNCTIONS.search(name):
        return ("NIST SP 800-121r2 4.3: Random number generation. "
                "MUST use hardware TRNG or NIST SP 800-90A approved DRBG. "
                "NEVER use predictable PRNGs for cryptographic material. "
                "Ensure sufficient entropy and proper seeding.")
    
    # Memory management
    if MEMORY_FUNCTIONS.search(name):
        return ("NIST SP 800-53 SI-10: Memory management function. "
                "Validate allocation size, check return values, prevent integer overflow. "
                "Clear sensitive data before deallocation. Implement double-free protection.")
    
    # BLE GATT operations
    if BLE_GATT.search(name):
        return ("NIST SP 800-121r2 5.7: BLE GATT operation. "
                "Enforce attribute permissions, validate handle ranges, sanitize input data. "
                "Implement proper access controls and prevent information disclosure.")
    
    # BLE GAP operations
    if BLE_GAP.search(name):
        return ("NIST SP 800-121r2 5.2: BLE GAP operation. "
                "Use LE Secure Connections, implement privacy features, validate address types. "
                "Enforce connection parameter limits and prevent tracking attacks.")
    
    # BLE SMP/Security operations
    if BLE_SMP.search(name):
        return ("NIST SP 800-121r2 5.8: BLE Security Manager operation. "
                "Use LE Secure Connections with ECDH, avoid 'Just Works' pairing. "
                "Implement OOB authentication where possible, secure key storage required.")
    
    # Authentication functions
    if AUTH_FUNCTIONS.search(name):
        return ("NIST SP 800-53 IA-2: Authentication function. "
                "Implement multi-factor authentication, prevent replay attacks, "
                "validate credentials securely, implement account lockout policies.")
    
    # Initialization functions
    if INIT_FUNCTIONS.search(name):
        return ("NIST SP 800-121r2: Initialization function. "
                "Validate all configuration parameters, disable unused features, "
                "apply principle of least privilege, implement secure defaults.")
    
    # Buffer operations
    if BUFFER_OPERATIONS.search(name):
        return ("NIST SP 800-53 SI-10: Buffer operation. "
                "Validate buffer bounds, prevent overflow/underflow, "
                "sanitize input data, implement length checks.")
    
    # Default guidance
    return ("NIST SP 800-53: Security control implementation required. "
            "Validate inputs, implement error handling, apply least privilege principle, "
            "ensure secure coding practices per NIST guidelines.")

def nist_param_comment(param):
    """Enhanced parameter-level security analysis."""
    name = param["name"].lower()
    ptype = param["type"].lower()
    
    # Cryptographic keys and sensitive data
    if CRYPTO_KEYS.search(name):
        if "key" in name:
            return ("Cryptographic key material. MUST be >=128 bits, randomly generated, "
                    "securely stored, and cleared after use. Implement key rotation policies.")
        elif "ltk" in name or "irk" in name:
            return ("BLE long-term key material. MUST be 128-bit, derived from ECDH, "
                    "stored in secure storage, never transmitted in plaintext.")
        else:
            return ("Sensitive cryptographic material. Protect confidentiality, "
                    "implement secure lifecycle management, validate before use.")
    
    # Random values and nonces
    if RNG_FUNCTIONS.search(name):
        return ("Random/entropy parameter. MUST be cryptographically secure, "
                "unpredictable, and have sufficient entropy. Never reuse nonces.")
    
    # Size and length parameters
    if SIZE_PARAMS.search(name):
        return ("Size/length parameter. MUST validate against buffer bounds, "
                "check for integer overflow, ensure non-negative values, "
                "implement maximum size limits to prevent DoS attacks.")
    
    # Pointer parameters
    if "*" in ptype:
        if BUFFER_OPERATIONS.search(name):
            return ("Buffer pointer. MUST validate non-NULL, check bounds against length parameter, "
                    "sanitize input data, prevent buffer overflow/underflow attacks.")
        elif CRYPTO_KEYS.search(name):
            return ("Cryptographic data pointer. MUST validate non-NULL, "
                    "implement secure memory handling, clear after use.")
        else:
            return ("Pointer parameter. MUST validate non-NULL, check memory access bounds, "
                    "prevent use-after-free and double-free vulnerabilities.")
    
    # Handle and ID parameters
    if SECURITY_IDS.search(name):
        return ("Security identifier/handle. MUST validate as active/authorized, "
                "implement session management, prevent handle reuse attacks, "
                "enforce access control policies.")
    
    # Authentication parameters
    if AUTH_FUNCTIONS.search(name) or "auth" in name:
        return ("Authentication parameter. Implement secure comparison, "
                "prevent timing attacks, validate credential format, "
                "implement rate limiting and account lockout.")
    
    # Integer types
    if any(t in ptype for t in ["int", "uint", "size_t"]):
        return ("Integer parameter. Validate range limits, check for overflow/underflow, "
                "ensure consistent sign handling, implement bounds checking.")
    
    # Default parameter guidance
    return ("Parameter requires validation. Check range/format, sanitize input, "
            "implement proper error handling per NIST security guidelines.")

def enrich_function_json(input_file, output_file):
    """Main enrichment function with enhanced NIST analysis."""
    try:
        with open(input_file, "r") as f:
            functions = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}")
        sys.exit(1)
    
    enriched_functions = []
    
    for fn in functions:
        enriched_fn = {
            "name": fn.get("name"),
            "return_type": fn.get("return_type", fn.get("type")),  # Handle both formats
            "params": [],
            "nist_comment": nist_function_comment(fn),
            "security_level": assess_security_level(fn),
            "compliance_tags": generate_compliance_tags(fn)
        }
        
        for param in fn.get("params", []):
            param_enriched = dict(param)
            param_enriched["comment"] = nist_param_comment(param)
            param_enriched["security_risk"] = assess_param_risk(param)
            enriched_fn["params"].append(param_enriched)
        
        enriched_functions.append(enriched_fn)
    
    try:
        with open(output_file, "w") as f:
            json.dump(enriched_functions, f, indent=2, ensure_ascii=False)
        print(f"Enhanced NIST-enriched analysis written to {output_file}")
        print(f"Analyzed {len(enriched_functions)} functions with comprehensive security guidance.")
    except IOError as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)

def assess_security_level(fn):
    """Assess overall security criticality of function."""
    name = fn["name"].lower()
    
    if UNSAFE_FUNCTIONS.search(name):
        return "CRITICAL"
    elif CRYPTO_OPERATIONS.search(name) or CRYPTO_KEYS.search(name):
        return "HIGH"
    elif BLE_SMP.search(name) or AUTH_FUNCTIONS.search(name):
        return "HIGH"
    elif MEMORY_FUNCTIONS.search(name) or BUFFER_OPERATIONS.search(name):
        return "MEDIUM"
    elif BLE_GATT.search(name) or BLE_GAP.search(name):
        return "MEDIUM"
    else:
        return "LOW"

def generate_compliance_tags(fn):
    """Generate relevant compliance framework tags."""
    name = fn["name"].lower()
    tags = ["NIST-SP-800-53"]
    
    if any(pattern.search(name) for pattern in [BLE_GATT, BLE_GAP, BLE_SMP]):
        tags.append("NIST-SP-800-121r2")
    
    if CRYPTO_OPERATIONS.search(name):
        tags.extend(["FIPS-140-2", "NIST-SP-800-57"])
    
    if RNG_FUNCTIONS.search(name):
        tags.append("NIST-SP-800-90A")
    
    if UNSAFE_FUNCTIONS.search(name):
        tags.append("CWE-119")  # Buffer overflow
    
    return tags

def assess_param_risk(param):
    """Assess parameter-specific security risk level."""
    name = param["name"].lower()
    ptype = param["type"].lower()
    
    if CRYPTO_KEYS.search(name):
        return "CRITICAL"
    elif "*" in ptype and BUFFER_OPERATIONS.search(name):
        return "HIGH"
    elif SIZE_PARAMS.search(name):
        return "MEDIUM"
    elif SECURITY_IDS.search(name):
        return "MEDIUM"
    else:
        return "LOW"

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced NIST-compliant BLE function security analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 enrich.py all_signs.json enriched_output.json
  python3 enrich.py -i functions.json -o secure_analysis.json
        """
    )
    
    parser.add_argument("input_file", nargs="?", 
                       help="Input JSON file containing function signatures")
    parser.add_argument("output_file", nargs="?",
                       help="Output JSON file for enriched analysis")
    parser.add_argument("-i", "--input", dest="input_alt",
                       help="Alternative input file specification")
    parser.add_argument("-o", "--output", dest="output_alt", 
                       help="Alternative output file specification")
    parser.add_argument("--version", action="version", version="Enhanced NIST BLE Analyzer v2.0")
    
    args = parser.parse_args()
    
    # Determine input and output files
    input_file = args.input_file or args.input_alt
    output_file = args.output_file or args.output_alt
    
    if not input_file or not output_file:
        parser.error("Both input and output files must be specified")
    
    print(f"Enhanced NIST BLE Security Analysis")
    print(f"Input: {input_file}")
    print(f"Output: {output_file}")
    print("-" * 50)
    
    enrich_function_json(input_file, output_file)

if __name__ == "__main__":
    main()

