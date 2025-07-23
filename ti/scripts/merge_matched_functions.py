import os
import sys
import pandas as pd

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <csv_directory>")
    sys.exit(1)

# Directory containing the CSV files (change '.' if needed)
csv_dir = sys.argv[1]

if not os.path.isdir(csv_dir):
    print(f"Error: '{csv_dir}' is not a directory.")
    sys.exit(1)

# List all CSV files in the directory
csv_files = [f for f in os.listdir(csv_dir) if f.endswith('.csv')]

# Initialize an empty DataFrame to hold the merged results
merged_dict = {}

for csv_file in csv_files:
    file_path = os.path.join(csv_dir, csv_file)
    try:
        df = pd.read_csv(file_path, dtype={'secondary_addr': str})
        if df.empty or not {'secondary_addr', 'similarity', 'primary_name', 'secondary_name'}.issubset(df.columns):
            continue
        for _, row in df.iterrows():
            sec_addr = row['secondary_addr']
            sim = float(row['similarity'])
            if sec_addr not in merged_dict or sim > merged_dict[sec_addr][0]:
                merged_dict[sec_addr] = (sim, row['primary_name'], row['secondary_name'])
    except Exception:
        continue

# Convert to DataFrame
merged_df = pd.DataFrame(
    [
        {'secondary_addr': addr, 'similarity': sim, 'primary_name': prim, 'secondary_name': sec}
        for addr, (sim, prim, sec) in merged_dict.items()
    ]
)

# Sort and save
merged_df = merged_df.sort_values(by='secondary_addr').reset_index(drop=True)
output_file = os.path.join(csv_dir, 'complete_matched_functions.csv')
merged_df.to_csv(output_file, index=False)
print(f"Merged file saved as: {output_file}")
