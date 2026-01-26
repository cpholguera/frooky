# Development / Local Testing

This document describes how to set up a local development environment for the repository on macOS.

## Prerequisites

- Python 3+ (use `python3`)
- Node.js (LTS) and `npm` or `pnpm` for JS tooling (optional)
- A physical device or emulator with `frida-server` or an app with an embedded frida gadget running (for dynamic tests)

## Running the CLI locally

1. Create a new Python virtual environment and activate it:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```


2. Compiling the frooky agent:

    ```bash
    ./compileAgent.sh --dev
    ```

3. Install the CLI for development:

    ```bash
    pip install -e .
    ```

4. Ensure which CLI version you're running:

    ```bash
    which frooky
    ```
   
   The output must be a path within the VENV directory, typically ending with `venv/bin/frooky`. If not, a different version might be used instead, such as a global installation.
   