# NPM Compromise Scanner for macOS

This project provides shell scripts to scan macOS devices for compromised npm packages. It is designed to be run manually or deployed via MDM (Mobile Device Management) solutions like Jamf, Kandji, or Intune.

## Features

- **Scope**: Scans global node modules, user-specific global roots (nvm, asdf), and project `node_modules` in the console user's home directory.
- **Deep Scan**: Checks `package.json` files and lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`).
- **Detection**: Identifies compromised packages based on name and version.
- **Output**: Generates reports in CSV and JSON formats at `/Library/Logs/`.

## Scripts

### 1. `npm_scanner_remote_ioc.sh` (Recommended)
This script fetches the latest list of Indicators of Compromise (IOCs) from a remote source (e.g., a GitHub repository containing known bad packages) at runtime.
- **Pros**: Always up-to-date without needing script updates.
- **Cons**: Requires internet access to fetch the IOC list.

### 2. `npm_scanner_static_ioc.sh`
This script uses a hardcoded list of IOCs embedded within the script itself.
- **Pros**: Works offline; no external dependencies.
- **Cons**: Must be manually updated to add new IOCs.

## Usage

### Option A: Direct Execution (Manual)

1.  Open Terminal.
2.  Navigate to the script directory.
3.  Run the scanner with `sudo` (required to access `/Library/Logs` and scan all directories):

    ```bash
    sudo ./npm_scanner_remote_ioc.sh
    ```

4.  Check the results:
    - **CSV**: `/Library/Logs/npm_compromise_scan.csv`
    - **JSON**: `/Library/Logs/npm_compromise_scan.json`

    **Exit Codes**:
    - `0`: No compromised packages found.
    - `1`: Compromised packages detected.

### Option B: MDM Deployment

1.  **Upload**: Upload `npm_scanner_remote_ioc.sh` to your MDM console as a script.
2.  **Configuration**:
    - **Run As**: Root (System).
    - **Trigger**: Once per day, or on a schedule.
3.  **Logs**: Configure your MDM to collect logs from `/Library/Logs/npm_compromise_scan.csv` or monitor the script's exit code.
    - If the script exits with `1`, it indicates a positive detection.

## Testing

A test setup script is provided to verify the scanner's functionality by creating a safe, simulated compromised environment.

1.  Run the setup script:
    ```bash
    ./tests/setup_test_env.sh
    ```
    This creates a directory `~/test_compromise_env` with simulated compromised packages (e.g., `02-echo` v`0.0.7`).

2.  Run the scanner:
    ```bash
    sudo ./npm_scanner_remote_ioc.sh
    ```

3.  Verify that the scanner reports findings in `/Library/Logs/npm_compromise_scan.csv`.

4.  **Cleanup**: Remove the test environment when done:
    ```bash
    rm -rf ~/test_compromise_env
    ```
