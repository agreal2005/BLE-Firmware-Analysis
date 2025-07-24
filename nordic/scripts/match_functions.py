import re
import csv
import sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <input.results> <output.csv>")
    sys.exit(1)

results_file = sys.argv[1]
output_csv = sys.argv[2]

# Pattern: captures primary_addr, secondary_addr, similarity, ...function names
pattern = re.compile(
    r'^([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9.]+)\s+[^\n]*function:.*?"([^"]+)"\s+"([^"]+)"'
)

with open(results_file, "r", encoding="utf-8") as infile, \
     open(output_csv, "w", newline='', encoding="utf-8") as outfile:
    writer = csv.writer(outfile)
    writer.writerow([
        "primary_addr",
        "secondary_addr",
        "similarity",
        "primary_name",
        "secondary_name"
    ])
    for line in infile:
        match = pattern.match(line)
        if match:
            primary_addr, secondary_addr, similarity, primary_name, secondary_name = match.groups()
            writer.writerow([
                f"'{primary_addr}",  # Prepend ' to prevent Excel scientific notation
                f"'{secondary_addr}",
                similarity,
                primary_name,
                secondary_name
            ])

print(f"Matched functions with similarity written to: {output_csv}")
