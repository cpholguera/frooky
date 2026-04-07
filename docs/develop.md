# Development / Local Testing

This document describes how to set up a local development environment for the repository on macOS.

## Prerequisites

- Python 3+ (use `python3`)
- Node.js (LTS) and `npm` or `pnpm` for JS tooling (optional)
- A physical device or emulator with `frida-server` for rooted testing (common for Android)
- Frida Gadget only for jailed/non-root scenarios

## Running the CLI locally

1. **Create a new Python virtual environment and activate it**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

2. Compiling the frooky agent:

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

## Testing

The project consists of two testable components: a Frida agent written in TypeScript and a Python host.

The agent has its own dedicated unit tests that run directly on a target device, as the agent's functionality is  tied to the runtime environment Frida operates in.

The host, on the other hand, serves as an integration test for the full application.

The following chapters describe how to write tests and target apps the tests should run against.

### Building Target App

Tests usually require a target app which implements the feature that should be tested.

You find them in the folder `tests/target-apps`, together with [instructions](../tests/target-apps/README.md) how to build them.

### Installing the Target App

After building, the app must be installed manually on the device or simulator before running tests. This command will install and launch the app:

```bash
cd tests/target-apps/<android|ios>
make install
```

> [!NOTE]
> Before proceeding, make sure Frida is available on the target device (Android) or on the local machine (iOS Simulator).

### Running Agent Tests

The Frida agent has its own test suite that runs inside a live Frida session (on a real device, simulator, or emulator). Tests are written in TypeScript and live under `frooky/agent/tests/`.

All test commands must be run from the `frooky/agent/` directory with Node.js dependencies installed:

```bash
cd frooky/agent
npm ci
```

You only need to do this once (or after updating `package-lock.json`).

In general, you need to have either the PID (attach), bundle-id (spawn then attach), or app name (attach by name).

#### Option A: USB Device (Android and iOS)

Use this when the app is running on a device connected over USB with `frida-server` running on the device (or with a Frida gadget embedded in the app).

```bash
# Examples: Target is an physical or emulated Android:
npm run test:android -i org.owasp.mastestapp
npm run test:android -i MASTestApp
npm run test:android -i 4926

# Examples: Target is a physical iOS USB device mode:
npm run test:ios:usb -i org.owasp.mastestapp.MASTestApp-iOS
npm run test:ios:usb -i MASTestApp
npm run test:ios:usb -i 23452
```

#### Option B: Local (iOS Simulator only)

Use this when targeting an **iOS Simulator** on your Mac via the local device.

Compared to option A, this differs, because the target app in an iOS simulator is running as local process on the host system. This means, that there is no need to start a dedicated Frida server.

Use the following commands to test against the running simulator:

```bash
# Examples: Target is an physical or emulated Android:
npm run test:android:usb -i org.owasp.mastestapp
npm run test:android:usb -i MASTestApp
npm run test:android:usb -i 4926

# Examples: Target is a iOS simulator:
npm run test:ios:local -i org.owasp.mastestapp.MASTestApp-iOS
npm run test:ios:local -i MASTestApp
npm run test:ios:local -i 23452
```

### What the Tests Do

Each test script:

1. Builds the agent and the test agent bundle (`dist/agent-test-{platform}.js`).
2. Attaches to (or spawns) the target app via Frida.
3. Injects the test bundle into the live process.
4. The bundle runs all registered `test(...)` cases inside the process and sends results back.
5. Results are printed to the terminal; the process exits with code `0` (all pass) or `1` (any failure).

### Test File Structure

```sh
frooky/agent/tests/
├── agent-test-framework.ts   # Minimal test runner (test/expect API)
├── target-apps/              # Folder of apps in the form of MASTG-DEMO apps
├── android/
│   ├── agent-runner.ts       # Entry point injected into the Android app
│   └── test-*.ts             # Tests
└── ios/
    ├── agent-runner.ts       # Entry point injected into the iOS app
    └── test-*.ts             # Tests
```

To add a new test, create a `test-*.ts` file in the relevant platform folder and import it in `agent-runner.ts`.
