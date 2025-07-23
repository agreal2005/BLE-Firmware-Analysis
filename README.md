# BLE-Firmware-Analysis
Tool that analyzes stripped Bluetooth Low Energy Firmware (from vendors: TI &amp; Nordic). Functions are identified and are commented based on NIST recommendations.

## For TI Firmware (go to /ti directory)
Ensure the following:
1. Place the firmware binary/binaries in the src folder. For each binary, also place its corresponding BinExport file in the same directory. [See more on generating BinExport file below]
2. In the terminal session you're running, ensure that `GHIDRA_DIR` contains the path to your ghidra installation. If not, then either export `GHIDRA_DIR` with this path, or for permanent changes, modify the `GHIDRA_DIR` variable in the `run.sh` script.
3. Ensure you have `python3` installed in your system. Also ensure that you have `bindiff` installed. [See more about BinDiff below]
4. Ensure that run.sh has executing privilege.
5. To view intermediate results, run with: ```./run.sh --debug```
6. Final results are stored in the ./results directory, with a csv that holds the mapping of address to the matched function names, and a json that contains commented information for BLE focused functions matched, on the basis of NIST recommendations.

For reference, there are example binaries located in /example_firmware_binexported/ with the binaries in the bin folder and the corresponding BinExports in the binexport folder. You can use these in case the BinExport-ing part is a bit cumbersome. However, do ensure that BinDiff is properly installed in your system.

## Regarding BinExport and BinDiff
It is preferred to use [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip) 10.4, and [BinExport](https://github.com/google/binexport/releases/download/v12-20230515-ghidra_10.3/ghidra_BinExport.zip) for 10.3+ Ghidra versions, as these are known to be compatible with each other. 

Also, install [Bindiff 8](https://github.com/google/bindiff/releases) and verify its successful installation from the command line.

To install and use BinExport in Ghidra's GUI, you need to first of all open Ghidra GUI, and create a new project. Then go to File and select "Install Extensions...". From there, locate and select the zip folder of BinExport that you've just downloaded.
Now, import the binary and click anywhere on the code window. Press O to open the Export Program As dialogue box, and select BinExport. Alternatively locate this option from the File menu.
Once the BinExport is ready, place this along with the actual binary in the folder specified above, for running of the scripts.
