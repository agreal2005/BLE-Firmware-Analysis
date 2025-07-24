#!/usr/bin/env python3
"""
nordic_enrich.py

NIST-style enrichment of Nordic BLE function signatures.

USAGE
    python3 nordic_enrich.py <input_json> <output_json>

EXAMPLE
    python3 nordic_enrich.py all_signs.json all_signs_enriched_nordic.json
"""

import argparse
import json
import re
import sys

# ==============================  REGEX LIBRARY  ==============================

CRYPTO_OPERATIONS   = re.compile(r"(aes|ccm|e(?:cc|cdh)|p256|sha|hash|cipher|hmac)", re.I)
CRYPTO_KEYS         = re.compile(r"(key|ltk|irk|csrk|stk|dhkey|secret)", re.I)
RNG_FUNCTIONS       = re.compile(r"(rand|trng|prng|nonce|entropy)", re.I)
MEMORY_FUNCTIONS    = re.compile(r"(malloc|calloc|realloc|free|alloc|pool|heap|bget|brel)", re.I)
BUFFER_OPERATIONS   = re.compile(r"(buf|buffer|data|payload|memcpy|memset|memmove|cmp)", re.I)
SIZE_PARAMS         = re.compile(r"(len|length|size|count|max|min|offset|bound|limit)", re.I)
SECURITY_IDS        = re.compile(r"(handle|id|conn|session|auth|bond|pair|addr|role|task)", re.I)

BLE_GATT            = re.compile(r"(gatt|attr|service|char|desc|uuid|ccc|indication|notification)", re.I)
BLE_GAP             = re.compile(r"(gap|adv|scan|connect|discover|white|accept|resolve)", re.I)
BLE_SMP             = re.compile(r"(smp|pair|bond|ltk|irk|csrk|oob|passkey|numeric)", re.I)

UNSAFE_FUNCTIONS    = re.compile(r"(strcpy|strcat|sprintf|gets|scanf|mktemp|system|exec)", re.I)
AUTH_FUNCTIONS      = re.compile(r"(auth|verify|validate|check|confirm|approve)", re.I)
INIT_FUNCTIONS      = re.compile(r"(init|initialize|setup|config|register|create)", re.I)

# ============================  COMMENT GENERATORS  ===========================

def nist_function_comment(fn: dict) -> str:
    """Return NIST-style function-level guidance."""
    name = fn["name"].lower()

    if UNSAFE_FUNCTIONS.search(name):
        return ("NIST SP 800-53 SI-10: CRITICAL || Deprecated unsafe routine. "
                "Replace with bounds-checked alternatives (e.g., strncpy, snprintf).")

    if CRYPTO_OPERATIONS.search(name):
        if "aes" in name:
            return ("NIST SP 800-121r2 4.1: AES cryptographic function. "
                    "Use FIPS-validated AES-CCM (≥128-bit keys); "
                    "secure key storage and IV uniqueness mandatory.")
        if "ecc" in name or "p256" in name:
            return ("NIST SP 800-121r2 4.2: ECC routine. "
                    "Use NIST P-256; validate public keys and ensure RNG strength.")
        if "sha" in name or "hash" in name:
            return ("NIST SP 800-121r2: Hash function. "
                    "Prefer SHA-256 or stronger; protect against length-extension attacks.")
        return ("NIST SP 800-121r2: Cryptographic primitive. "
                "Verify FIPS 140-3 validation and correct algorithm use.")

    if RNG_FUNCTIONS.search(name):
        return ("NIST SP 800-90A: Random number generation. "
                "Use approved DRBG or on-chip TRNG; never reuse nonces.")

    if MEMORY_FUNCTIONS.search(name):
        return ("NIST SP 800-53 SI-10: Memory management. "
                "Validate allocation size; clear sensitive buffers before free.")

    if BLE_GATT.search(name):
        return ("NIST SP 800-121r2 5.7: GATT operation. "
                "Enforce attribute permissions and sanitize input lengths.")

    if BLE_GAP.search(name):
        return ("NIST SP 800-121r2 5.2: GAP operation. "
                "Require LE Secure Connections and privacy-enabled addresses.")

    if BLE_SMP.search(name):
        return ("NIST SP 800-121r2 5.8: SMP routine. "
                "Use authenticated LE Secure Connections (ECDH) and protect key material.")

    if AUTH_FUNCTIONS.search(name):
        return ("NIST SP 800-53 IA-2: Authentication. "
                "Implement mutual authentication and replay protection.")

    if INIT_FUNCTIONS.search(name):
        return ("NIST SP 800-121r2: Initialization. "
                "Apply secure defaults and least-privilege configuration.")

    if BUFFER_OPERATIONS.search(name):
        return ("NIST SP 800-53 SI-10: Buffer handling. "
                "Perform strict bounds checking and input validation.")

    # Default
    return ("NIST SP 800-53: Validate inputs, handle errors, and follow secure coding practices.")

def nist_param_comment(param: dict) -> str:
    """Return NIST-style parameter-level guidance."""
    name, ptype = param["name"].lower(), param["type"].lower()

    if CRYPTO_KEYS.search(name):
        return ("Cryptographic key material. Store securely, wipe after use, "
                "and rotate per NIST SP 800-57.")

    if RNG_FUNCTIONS.search(name):
        return ("Nonce/entropy input. Must be unpredictable and never reused.")

    if SIZE_PARAMS.search(name):
        return ("Length/size field. Validate against buffer size; check for integer overflow.")

    if "*" in ptype:
        return ("Pointer parameter. Verify non-NULL, ensure bounds, and protect from UAF.")

    if SECURITY_IDS.search(name):
        return ("Identifier/handle. Confirm validity and enforce session access control.")

    if AUTH_FUNCTIONS.search(name):
        return ("Auth data. Protect against timing attacks and ensure secure comparison.")

    if any(t in ptype for t in ("int", "uint", "size_t")):
        return ("Integer parameter. Validate range and handle signedness correctly.")

    return "Parameter requires validation and error handling per NIST guidelines."

# ===========================  RISK & TAG FUNCTIONS  ==========================

def assess_security_level(fn: dict) -> str:
    n = fn["name"].lower()
    if UNSAFE_FUNCTIONS.search(n):        return "CRITICAL"
    if CRYPTO_OPERATIONS.search(n):       return "HIGH"
    if BLE_SMP.search(n) or AUTH_FUNCTIONS.search(n): return "HIGH"
    if MEMORY_FUNCTIONS.search(n) or BUFFER_OPERATIONS.search(n): return "MEDIUM"
    if BLE_GATT.search(n) or BLE_GAP.search(n):       return "MEDIUM"
    return "LOW"

def compliance_tags(fn: dict):
    tags = ["NIST-SP-800-53"]
    n = fn["name"].lower()
    if CRYPTO_OPERATIONS.search(n):
        tags += ["FIPS-140-3", "NIST-SP-800-57"]
    if BLE_GATT.search(n) or BLE_GAP.search(n) or BLE_SMP.search(n):
        tags.append("NIST-SP-800-121r2")
    if RNG_FUNCTIONS.search(n):
        tags.append("NIST-SP-800-90A")
    if UNSAFE_FUNCTIONS.search(n):
        tags.append("CWE-119")
    return tags

def param_risk(param):
    name = param["name"].lower()
    ptype = param["type"].lower()
    if CRYPTO_KEYS.search(name):                              return "CRITICAL"
    if "*" in ptype and BUFFER_OPERATIONS.search(name):       return "HIGH"
    if SIZE_PARAMS.search(name):                              return "MEDIUM"
    if SECURITY_IDS.search(name):                             return "MEDIUM"
    return "LOW"

# ==============================  MAIN LOGIC  ==============================

def enrich_file(in_path, out_path):
    try:
        with open(in_path, "r", encoding="utf-8") as f:
            funcs = json.load(f)
    except Exception as e:
        sys.exit(f"Error reading {in_path}: {e}")

    enriched = []
    for fn in funcs:
        fn_out = {
            "name": fn["name"],
            "return_type": fn.get("return_type", fn.get("type", "")),
            "params": [],
            "nist_comment": nist_function_comment(fn),
            "security_level": assess_security_level(fn),
            "compliance_tags": compliance_tags(fn),
        }
        for p in fn.get("params", []):
            new_p = dict(p)
            new_p["comment"] = nist_param_comment(p)
            new_p["security_risk"] = param_risk(p)
            fn_out["params"].append(new_p)
        enriched.append(fn_out)

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(enriched, f, indent=2, ensure_ascii=False)
        print(f"Enriched {len(enriched)} functions => {out_path}")
    except Exception as e:
        sys.exit(f"Error writing {out_path}: {e}")

# ================================  CLI  ====================================

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Enrich Nordic BLE function JSON with NIST guidance")
    ap.add_argument("input_json",  help="Input file (e.g., all_signs.json)")
    ap.add_argument("output_json", help="Output file (e.g., all_signs_enriched_nordic.json)")
    args = ap.parse_args()
    enrich_file(args.input_json, args.output_json)

