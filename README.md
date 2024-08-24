# Command Line Spoofing Tool

## Overview
This tool allows execution of Windows processes with modified command line arguments, designed specifically to bypass logging-based detection systems like SIEM.

### How It Works
1. **Create Suspended Process**: The tool initiates the target executable in a suspended state, preventing it from running any code before modifications are made.
2. **Modify Process's PEB**: It accesses the Process Environment Block (PEB) of the suspended process. The command line information stored in the PEB is then altered to reflect the spoofed arguments, while the actual command line used by the process remains unchanged.
3. **Resume Process**: After the modifications, the process is resumed. This action allows the process to start normally, but with the command line as viewed by system monitors being different from what is actually executed, effectively bypassing command line logging mechanisms used by many security systems.detection.

## Usage
```bash
ArgsSpoof.exe <targetExecutable> [--input or <spoofedCommand>]
```


## Example
```bash
ArgsSpoof.exe "C:\Path\Executable.exe" "spoofArg1 spoofArg2"
ArgsSpoof.exe "C:\Path\Executable.exe" --input
```


