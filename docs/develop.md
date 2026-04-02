# Development / Local Testing

This document describes how to set up a local development environment for the repository on macOS.

## Prerequisites

- Python 3+ (use `python3`)
- Node.js (LTS) and `npm` or `pnpm` for JS tooling (optional)
- A physical device or emulator with `frida-server` or an app with an embedded frida gadget running (for dynamic tests)

## Running the CLI locally

1. **Create a new Python virtual environment and activate it**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```


2. **Compiling the frooky agent**

    ```bash
    ./compileAgent.sh --dev
    ```

3. **Install the CLI for development**

    ```bash
    pip install -e .
    ```

4. **Ensure which CLI version you're running**

    ```bash
    which frooky
    ```
   
   The output must be a path within the VENV directory, typically ending with `venv/bin/frooky`. If not, a different version might be used instead, such as a global installation.


## Compile And Run the frooky Standalone Agent

If you want to work on the frooky agent itself, you can also use [`frida`](https://frida.re/) as host.

Follow these steps to do that:

1. **Install all dependencies**

    ```sh
    npm install
    ```

2. **Compile the development standalone client**

    ```sh
    npm run watch-android hook.yaml
    npm run watch-ios hook.yaml
    ```

    You can specify one or more `hook.yaml` files. Pattern expansion (`glob`) is supported.

    This will compile a development build of the frooky agent, watch for changes in its source code and all `hook.yaml` files, and keep the compiled agents in the `./dist` folder up to date.

3. **Start Frida with the compiled agent**
   
    For Android:

    ```sh
    frida -U -f org.owasp.mytargetapp dist/agent-android.js
    ```

    For iOS:

    ```sh
    frida -U -f org.owasp.mytargetapp dist/agent-ios.js
    ```
