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

Tests usually require a target app which implements the feature that should be tested. For example, type decoders should be tested against real implementations on Android or iOS.

These apps are located in the folder `tests/target-apps/<android|ios>/`. They must be in the form of a [MASTG-DEMO app](https://mas.owasp.org/MASTG/demos/#) Hence, the app identifier for the Android app is `org.owasp.mastestapp` and for the iOS app `org.owasp.mastestapp.MASTestApp-iOS`.

To compile them, run `make build APP_DIR=<app-dir>` in the directory `tests/target-apps/<android|ios>/`.

`app-dir` is the folder where the demo app is. If no `APP_DIR` is provided, an empty [`mas-app-ios`](https://github.com/cpholguera/mas-app-ios) or [`mas-app-android`](https://github.com/cpholguera/mas-app-android) app is built.

**Examples 1:** Building an empty `mas-app-ios` app:

```sh
cd tests/target-apps/ios
make build
```

This will compile the app and store it in `tests/target-apps/ios/dist/MASTestApp.app`.

**Examples 2:** Building a custom for parameter testing

```sh
cd tests/target-apps/android
make build APP_DIR=./basic-parameter
```

This will compile the app and store it in `tests/target-apps/android/dist/MASTestApp.apk`.

> [!NOTE]
> At the moment, there is no automation to start the app.
> This means, the developer is responsible that the right target app is running on the device and that Frida is available.
> Agent tests will always just start the target app based on the app identifier.

### Running Agent Tests

The Frida agent has its own test suite that runs inside a live Frida session (on a real device, simulator, or emulator). Tests are written in TypeScript and live under `frooky/agent/tests/`.

All test commands must be run from the `frooky/agent/` directory with Node.js dependencies installed:

```bash
cd frooky/agent
npm ci
```

You only need to do this once (or after updating `package-lock.json`).

### Key Syntax Rule

When passing arguments to an npm script, you **must** use `--` to separate npm's own flags from the script's flags. Without it, npm intercepts the flags and never forwards them to the underlying script.

```bash
npm run test:ios:local -- --appIdentifier <value>
```

### iOS Tests

There are two test modes depending on where the app is running.

#### Option A: USB Device

Use this when the app is running on a **physical iOS device** connected over USB with `frida-server` running on the device (or with a Frida gadget embedded in the app).

```bash
# From frooky/agent/
npm run test:ios:usb -- --appIdentifier <pid|bundle-id|app-name>

# Examples:
npm run test:ios:usb -- --appIdentifier org.owasp.mastestapp.MASTestApp-iOS
npm run test:ios:usb -- --appIdentifier 12345
npm run test:ios:usb -- --appIdentifier MASTestApp
```

For `test:ios:usb`, `--appIdentifier` supports PID (attach), bundle-id (spawn then attach), or app name (attach by name).

#### Option B: Local (iOS Simulator)

Use this when targeting an **iOS Simulator** on your Mac via the local device.

For `test:ios:local`, `--appIdentifier` supports:

- numeric PID (attach)
- bundle identifier (spawn then attach)
- app/process name (attach by name; app must already be running)

```bash
# Option 1: use PID
# 1. Launch the app in the simulator first, then find its PID:
ps aux | grep -i <app-name>
# Or use: frida-ps -D <simulator-udid>
npm run test:ios:local -- --appIdentifier 12345

# Option 2: use bundle id (spawn)
npm run test:ios:local -- --appIdentifier org.owasp.mastestapp.MASTestApp-iOS

# Option 3: use process name (attach)
npm run test:ios:local -- --appIdentifier MASTestApp
```

### Android Tests

Use this when the app is running on a **physical Android device** or emulator connected over USB with `frida-server` running.

`test:android` supports `--appIdentifier <pid|package-id|app-name>`.

```bash
# package-id (spawn)
npm run test:android -- --appIdentifier org.owasp.mastestapp

# pid (attach)
npm run test:android -- --appIdentifier 4926

# app-name (attach by name)
npm run test:android -- --appIdentifier MASTestApp
```

On Android emulators, SELinux can block `spawn`. In that case, use PID or app-name attach:

```bash
# Find the app's PID
adb shell ps -A | grep mastestapp
# or:
frida-ps -U | grep -i mast

# Run tests by attaching to the existing process
npm run test:android -- --appIdentifier <PID>

# Example:
npm run test:android -- --appIdentifier 4926
```

`run-tests.js` first tries spawn for string identifiers, then falls back to attach-by-name if spawn fails.

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
├── android/
│   ├── target-apps           # Folder of apps in the form of MASTG-DEMO app's
│   ├── agent-runner.ts       # Entry point injected into the Android app
│   ├── test-*.ts             # Tests 
└── ios/
    ├── target-apps           # Folder of apps in the form of MASTG-DEMO app's
    ├── agent-runner.ts       # Entry point injected into the iOS app
    └── test-*.ts             # Tests 
```

To add a new test, create a `test-*.ts` file in the relevant platform folder and import it in `agent-runner.ts`.

### Troubleshooting

#### `Need Gadget to attach on jailed Android`

This message is a generic Frida error and may appear even when you are **not** using Frida Gadget.

If you are using `frida-server`, this error almost always means one of:

1. **frida-server not running** — even if the binary exists, confirm it's actually running:

    ```bash
    frida-ps -U   # should list processes; if it fails, frida-server isn't up
    ```

    Start it with: `adb root && adb shell /data/local/tmp/frida-server &`

2. **Version mismatch** — the `frida` Node package used by `run-tests.js` and the `frida-server` binary on the device must be the **exact same version**. Even a minor version difference causes this error.

   ```bash
   # Check the frida-server version on the device
   adb shell /data/local/tmp/frida-server --version

   # Check the frida Node package version (from frooky/agent/)
   npm list frida
   ```

   If they differ, download the matching `frida-server` binary from the [Frida releases page](https://github.com/frida/frida/releases) and push it to the device, then update the `frida` version pinned in `package.json` to match and run `npm ci`.

   > **Note**: `frida` must be listed as a direct `devDependency` in `package.json` (not just a transitive dependency of `frida-compile`) so that its native bindings are reliably installed. If it is missing, add it with the exact matching version and re-run `npm ci`.

3. **frida-server not running as root** — Frida needs root to inject into other processes. Verify:

   ```bash
   adb shell ps -A | grep frida-server   # UID should be root (or 0)
   ```

   If it's not running as root, restart it with `adb root` or via a root shell on the device.

4. **spawn blocked on emulator/SELinux** — process listing may work but spawning can still fail.

    Workaround: run the app first, then pass a numeric PID so tests attach instead of spawn:

    ```bash
    adb shell ps -A | grep mastestapp
    npm run test:android -- --appIdentifier <PID>
    ```

