import csv
import re

# Define category keywords and patterns
categories = {
    "pairing_and_auth": [
        r'pair', r'auth', r'SM_', r'sm', r'bond', r'passcode', r'_pair', r'_auth'
    ],
    "encryption": [
        r'encrypt', r'decrypt', r'AES', r'crypto', r'ccm', r'cipher', r'_ltk', r'_ltk_', r'ltk_', r'ltk$', r'_key$', r'_key_', r'key_', r'SR', r'E0'
    ],
    "key_management": [
        r'key', r'ltk', r'irk', r'csrk', r'generate.*key', r'KeyCB', r'random', r'secure_connection', r'dhkey', r'p256'
    ],
    "privacy": [
        r'privacy', r'irk', r'_addr', r'rpa', r'identity', r'_private', r'_resolve'
    ],
    "device_role_handlers": [
        r'role', r'central', r'peripheral', r'master', r'slave', r'isCentral', r'isPeripheral', r'_role', r'setRole'
    ],
    "service_level_security": [
        r'access', r'authorize', r'security', r'permission', r'acl', r'attr', r'profile', r'Service', r'_ReadAttrCB', r'_WriteAttrCB'
    ]
}

def classify_function(fname):
    labels = []
    for cat, patterns in categories.items():
        for p in patterns:
            if re.search(p, fname, re.IGNORECASE):
                labels.append(cat)
                break
    if not labels:
        labels.append('None')
    return labels

input_file = '../nist_database/function_database.csv'     # Update with your path
output_file = '../nist_database/function_database_classified.csv'

with open(input_file, newline='') as csvfile, open(output_file, 'w', newline='') as outfile:
    reader = csv.DictReader(csvfile)
    writer = csv.writer(outfile)
    writer.writerow(['function_name', 'categories'])
    for row in reader:
        fname = row['function_name']
        cats = classify_function(fname)
        writer.writerow([fname, '; '.join(cats)])

print(f'Function classification written to {output_file}')

