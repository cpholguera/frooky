# Development / Local Testing

This document describes how to set up a local development environment and run tests for the repository on macOS.

## Prerequisites

- Python 3+ (use `python3`)
- Node.js (LTS) and `npm` or `pnpm` for JS tooling (optional)
- Frida tools for runtime testing: `frida-tools` (`pip install frida-tools`)
- A physical device or emulator with `frida-server` running (for dynamic tests)

## Running the CLI locally

1. Create a new Python virtual environment and activate it:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

2. Install the CLI:

    ```bash
    pip install -e .
    ```

3. Ensure which CLI version you're running:

    ```bash
    pwd frooky
    ```
   
   The output must be within the VENV directory ending at `[..]/venv/bin/frooky`. If not, a different version might be used instead, such as a global installation.