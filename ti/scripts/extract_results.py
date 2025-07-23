import sys
import pandas as pd

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <input_csv> <output_csv>")
    sys.exit(1)

input_csv = sys.argv[1]
output_csv = sys.argv[2]

try:
    # Read necessary columns
    df = pd.read_csv(input_csv, usecols=['secondary_addr', 'primary_name', 'secondary_name'])

    # Normalize addresses
    df['secondary_addr'] = (
        df['secondary_addr']
        .astype(str)
        .str.replace("'", "0x")
        .apply(lambda x: x[2:].zfill(8))
    )

    # Filter rows where primary_name matches secondary_name exactly
    df = df[df['primary_name'] == df['secondary_name']]

except pd.errors.EmptyDataError:
    df = pd.DataFrame(columns=['address', 'name'])
except Exception as e:
    print(f"Error reading CSV: {e}")
    sys.exit(1)

# Rename and subset the final output
df = df.rename(columns={'secondary_addr': 'address', 'primary_name': 'name'})
df = df[['address', 'name']]

# Write the output
df.to_csv(output_csv, index=False, header=True)
print(f"Filtered matched functions saved to: {output_csv}")
