#!/bin/bash

[ -z "${GHIDRA_DIR}" ] && export GHIDRA_DIR="/mnt/c/ghidra_10.4_PUBLIC_20230928/ghidra_10.4_PUBLIC"
GHIDRA_HEADLESS_DIR="$GHIDRA_DIR/support/"

TMP_PROJ="/tmp/ghidra_projects"
mkdir -p $TMP_PROJ

BINEXPORT_DIR="./src"
DEBUG=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)
            DEBUG=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
else
    echo "Error: Python3 is not installed." >&2
    exit 1
fi

for file in "$BINEXPORT_DIR"/*.BinExport; do
    filename=$(basename -- "$file")
    firmware_name="${filename%.BinExport}"

    results_dir="./results/${firmware_name}_results"
    mkdir -p "$results_dir"
    rm -rf "${results_dir:?}/"*

    for REF_BIN in ./ref_bins/*.BinExport; do
        ref_filename=$(basename -- "$REF_BIN")
        ref_name="${ref_filename%.BinExport}"

        bindiff --primary "$REF_BIN" --secondary "$file" --output_dir "$results_dir" --output_format log

        $PYTHON_BIN ./scripts/match_functions.py "${results_dir}/${ref_name}_vs_${firmware_name}.results" "./${results_dir}/matched_functions_${ref_name}.csv"
    done

    $PYTHON_BIN ./scripts/merge_matched_functions.py "${results_dir}"

    $PYTHON_BIN ./scripts/extract_results.py "${results_dir}/complete_matched_functions.csv" "./results/${firmware_name}_identified_functions.csv"

    $PYTHON_BIN ./scripts/extract_comments.py "./results/${firmware_name}_identified_functions.csv" "./ref_headers/all_signs_enriched.json" "./${results_dir}/matched_output.json"

    $GHIDRA_HEADLESS_DIR/analyzeHeadless $TMP_PROJ temp_project -import ./src/$firmware_name -overwrite -loader BinaryLoader -processor ARM:LE:32:Cortex -cspec default -analysisTimeoutPerFile 600 -scriptPath "./scripts/" -postScript ble_extractor.py "./${results_dir}/matched_output.json" "./results/${firmware_name}_identified_functions.csv" "./results/${firmware_name}_matched_final.json"

done

if [ "$DEBUG" = false ]; then
    rm -rf ./results/*_results/
    echo "Cleaned up results directories."
else
    echo "Debug mode: keeping results directories."
fi