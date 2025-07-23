import json
import re

# Patterns for NIST BLE-relevant risk categories from SP 800-121r2
CRYPTO_KEYS = re.compile(r"(aes|key|encrypt|decrypt|ccm|ctr|cmac|ssp|ecc)", re.I)
BUFFER = re.compile(r"(buf|data|value|dest|src|p[A-Z])", re.I)
LEN_SIZE = re.compile(r"(len|size|count|cnt|ndigit|max|min|offset)", re.I)
HANDLE_ID = re.compile(r"(handle|id|task|conn|addr|role|index|event|opcode|flags)", re.I)
RAND = re.compile(r"(rand|random|trng|seed)", re.I)
GATT = re.compile(r"(readattrcb|writeattrcb|getparameter|setparameter|gatt|service|profile)", re.I)
MEMORY_FN = re.compile(r"(malloc|calloc|realloc|alloca|free|bget|brel|bpool)", re.I)
UNSAFE_FN = re.compile(
    r"(strcpy|strcat|sprintf|gets|scanf|mktemp|system|exec|memcpy|strncpy|strncat|strtok|strdup|bcopy|bzero)",
    re.I,
)

# NIST 800-121r2 and 800-53 highlights for automated comments
def nist_function_comment(fn):
    name = fn["name"].lower()
    # High-risk C stdlib/text functions
    if UNSAFE_FN.search(name):
        return "NIST: DEPRECATED function. Avoid unsafe and legacy C interfaces (buffer overflows, code injection)."
    if CRYPTO_KEYS.search(name):
        return (
            "NIST 800-121r2: Ensure use of FIPS-approved cryptography (e.g., AES-CCM, P-256). "
            "Keys must be 128+ bits, generated securely, never reused or leaked. "
            "Validate key storage and IV/nonce uniqueness."
        )
    if RAND.search(name):
        return (
            "NIST 800-121r2: Do NOT use weak or predictable PRNG/RNG for keys or pairing. "
            "Use hardware or OS-approved TRNG only."
        )
    if MEMORY_FN.search(name):
        return (
            "NIST 800-53, SI-10: Always check return values. Validate allocation size, "
            "avoid integer overflow, double-free, or use-after-free. Zero sensitive memory before release."
        )
    if GATT.search(name):
        return (
            "NIST 800-121r2 §5.7: Attribute/protocol handler. Enforce access controls. "
            "Validate buffers and ensure no leakage of sensitive data."
        )
    if "init" in name or "register" in name:
        return (
            "NIST 800-121r2: Initialization or registration; "
            "verify all user/provisioned values, disable legacy/unused features, and apply least-privilege."
        )
    if "pool" in name or "heap" in name or "alloc" in name:
        return (
            "NIST 800-53 SI-10: Memory management interface — verify pointer/context, "
            "track resource lifecycles, and defend against exhaustion attacks."
        )
    if "pair" in name or "bond" in name:
        return (
            "NIST 800-121r2 §5.8: Pairing/bonding. Use LE Secure Connections. "
            "Avoid 'Just Works' wherever feasible. Never store keys in plaintext."
        )
    if "callback" in name or "cb" in name:
        return (
            "NIST 800-121r2: Callback registration; "
            "defend against function pointer or logic hijacking. Validate pointer and intended trust boundary."
        )
    return "NIST: Review function for secure input validation, code injection, and correct BLE security posture."

def nist_param_comment(param):
    name, typ = param["name"].lower(), param["type"].lower()
    # Key/crypto calls
    if CRYPTO_KEYS.search(name):
        return "Cryptographic key material. Must be FIPS-approved length, never NULL, cleared after use."
    if RAND.search(name):
        return "Randomness/seed. Must be hardware-true or OS-secure random source; NEVER fixed or user predictable."
    if LEN_SIZE.search(name):
        return (
            "Length/count/offset. Must be >=0, within buffer bounds, and validated against actual allocation size."
        )
    if BUFFER.search(name):
        if "*" in typ:
            return (
                "Pointer to buffer/data. Must not be NULL. Size and bounds must be validated against 'len', 'size', or protocol spec. For output, must be pre-allocated."
            )
        else:
            return "Buffer/array/data. Validate maximum size and bounds. Defend against out-of-bounds access."
    if HANDLE_ID.search(name):
        return (
            "Connection/descriptor/task handle or index. Must be validated as live/unique/within current session."
        )
    if "callback" in name or "cb" in name:
        return (
            "Callback pointer. Check it is non-NULL, registered with correct function and security context."
        )
    return "Validate parameter for range, meaning, and NIST BLE/secure coding guidance."

def enrich_fn_json(infile, outfile):
    with open(infile, "r") as f:
        all_fns = json.load(f)
    enriched = []
    for fn in all_fns:
        enriched_fn = {
            "name": fn.get("name"),
            "type": fn.get("type"),
            "params": [],
            "nist_comment": nist_function_comment(fn),
        }
        for p in fn.get("params", []):
            param_ann = dict(p)
            param_ann["comment"] = nist_param_comment(p)
            enriched_fn["params"].append(param_ann)
        enriched.append(enriched_fn)
    with open(outfile, "w") as f:
        json.dump(enriched, f, indent=2)
    print(f"NIST-enriched JSON written to {outfile}")

if __name__ == "__main__":
    # Input should be your extracted function JSON (as from your all_functions.json/output_new.json)
    enrich_fn_json("./matched_functions.json", "./matched_functions_enriched.json")

