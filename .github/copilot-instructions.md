# Copilot Instructions for Frooky

## Project Overview

**Frooky** is a Frida-powered dynamic instrumentation tool for mobile app security testing on Android and iOS. It allows security testers to hook Java/Kotlin methods and native C/C++ functions using simple JSON configuration files.

### Key Technologies

- **Languages**: Python (CLI; see `requires-python` in [`pyproject.toml`](../pyproject.toml)), TypeScript/JavaScript (Frida agent)
- **Frameworks**: Frida (dynamic instrumentation), setuptools (Python packaging)
- **Build Tools**: npm/Node.js (for agent compilation), Python build module
- **Package Management**: pip (Python), npm (Node.js)

## Project Structure

```bash
frooky/
├── frooky/                          # Main Python package
│   ├── __init__.py                 # Package initialization
│   ├── cli.py                      # Command-line interface entry point
│   ├── frida_runner.py             # Core Frida execution logic
│   └── agent/                      # Frida agent (TypeScript/JavaScript)
│       ├── package.json            # Node.js dependencies
│       ├── tsconfig.json           # TypeScript configuration
│       ├── build.js                # Custom build script
│       ├── android/                # Android-specific agent code
│       ├── ios/                    # iOS-specific agent code
│       └── dist/                   # Compiled agent artifacts (git-ignored)
│           ├── agent-android.js    # Built Android agent
│           ├── agent-ios.js        # Built iOS agent
│           └── version.json        # Version metadata
├── docs/                            # Documentation
│   ├── develop.md                  # Development setup guide
│   ├── usage.md                    # Usage documentation
│   └── examples/                   # Example hook configurations
├── .github/
│   └── workflows/                  # CI/CD pipelines
│       ├── build.yml               # Package build workflow (reusable)
│       ├── test-build.yml          # PR/push verification
│       ├── publish.yml             # PyPI publishing
│       └── sync-labels.yml         # Label management
├── pyproject.toml                  # Python project configuration
├── compileAgent.sh                 # Agent build helper script
└── README.md                       # Main project documentation
```

## Build System & Workflow

### Two-Stage Build Process

Frooky uses a **two-stage build** that must be executed in order:

1. **Agent Compilation** (TypeScript → JavaScript):

   ```bash
   ./compileAgent.sh --prod    # Production build (minified)
   ./compileAgent.sh --dev     # Development build (unminified)
   ```
    - Runs inside [`frooky/agent/`](../frooky/agent/) directory
    - Executes `npm ci` to install dependencies
    - Compiles TypeScript sources from [`frooky/agent/android/`](../frooky/agent/android/) and [`frooky/agent/ios/`](../frooky/agent/ios/) subdirectories
    - Outputs to [`frooky/agent/dist/`](../frooky/agent/dist/) as `agent-{android,ios}.js`
    - **CRITICAL**: Agent artifacts MUST exist before Python package build

2. **Python Package Build**:

   ```bash
   python -m build
   ```
    - Packages the Python CLI and includes pre-built agent artifacts
    - Uses `setuptools-scm` for versioning from git tags
    - Outputs wheel (`.whl`) and source tarball (`.tar.gz`) to [`dist/`](../dist/)

### Development Setup

To set up a local development environment:

```bash
# 1. Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Compile Frida agents
./compileAgent.sh --dev

# 3. Install CLI in editable mode
pip install -e .

# 4. Verify installation
which frooky  # Should point to venv/bin/frooky
frooky --help
```

### Watch Mode for Active Development

For iterative agent development, use watch mode:

```bash
cd frooky/agent
npm run watch-android   # Auto-recompile on Android agent changes
npm run watch-ios       # Auto-recompile on iOS agent changes
```

Note: Use `watch-android` and/or `watch-ios` depending on which platform you're working on.

## Testing & CI/CD

### Test Infrastructure

- **No unit tests currently exist** - the project only does CI verification at the moment, but testing of the codebase is in planning
- **CI Verification** ([`.github/workflows/test-build.yml`](workflows/test-build.yml)):
    - Builds the package (agent + Python wheel)
    - Verifies wheel can be installed
    - Checks that `frooky --help` runs successfully
    - Validates agent artifacts are included in wheel: [`frooky/agent/dist/agent-android.js`](../frooky/agent/dist/agent-android.js) and [`frooky/agent/dist/agent-ios.js`](../frooky/agent/dist/agent-ios.js)

### Running CI Checks Locally

```bash
# Full build verification (mimics CI)
./compileAgent.sh --prod
python -m build
python -m pip install dist/*.whl
frooky --help

# Verify agent artifacts in wheel
unzip -l dist/*.whl | grep "frooky/agent/dist/agent-android.js"
unzip -l dist/*.whl | grep "frooky/agent/dist/agent-ios.js"
```

## Important Gotchas & Considerations

### 1. **Agent Artifacts Must Be Built First**

- **ALWAYS** run `./compileAgent.sh` before `python -m build`
- Python packaging will fail or produce incomplete artifacts if agents are missing
- The [`compileAgent.sh`](../compileAgent.sh) script must be executable (`chmod +x compileAgent.sh`)

### 2. **Version Management**

- Version is determined by `setuptools-scm` from git tags and commits
- Requires full git history: `git clone` without depth restrictions or fetch with `fetch-depth: 0` in CI
- Generated version file: [`frooky/_version.py`](../frooky/_version.py) (git-ignored, auto-created during build)
- **Do not manually edit version numbers**

### 3. **Node.js Environment**

- Node.js version is pinned in CI (see `actions/setup-node` in [`.github/workflows/build.yml`](workflows/build.yml))
- Use `npm ci` (not `npm install`) for consistent dependency installation
- Package lock file is at [`frooky/agent/package-lock.json`](../frooky/agent/package-lock.json)

### 4. **Python Version Compatibility**

- Minimum supported Python is defined by `requires-python` in [`pyproject.toml`](../pyproject.toml)
- The set of versions exercised in CI is defined in [`.github/workflows/`](workflows/) (see `actions/setup-python` steps)
- Uses modern Python features (e.g., `from __future__ import annotations`)

### 5. **Frida Dependencies**

- Frida dependency constraints are defined in [`pyproject.toml`](../pyproject.toml) under `project.dependencies`
- These are system-dependent native packages that may take time to install

### 6. **Output Files**

- Default output: [`output.json`](../output.json) (git-ignored)
- Output format: JSON Lines (NDJSON) - one JSON object per line
- Use `jq . output.json` to pretty-print

### 7. **Git Pager Issues**

- **ALWAYS** use `git --no-pager` when running git commands programmatically
- Example: `git --no-pager status`, `git --no-pager diff`

## Common Tasks

### Modifying the frooky 

1. Edit TypeScript files in [`frooky/agent/android/`](../frooky/agent/android/) or [`frooky/agent/ios/`](../frooky/agent/ios/)
2. Recompile: `cd frooky/agent && npm run dev-{android|ios}`
3. Test locally with `pip install -e .` and run `frooky` commands
4. Run `frooky --help` to make sure the agent scripts are properly compiled

### Modifying Python CLI

1. Edit [`frooky/cli.py`](../frooky/cli.py) or [`frooky/frida_runner.py`](../frooky/frida_runner.py)
2. Changes are immediately available with `pip install -e .`
3. Test with `frooky --help` or relevant commands

### Adding Dependencies

- **Python**: Add to `dependencies` array in [`pyproject.toml`](../pyproject.toml)
- **Node.js**: Run `cd frooky/agent && npm install --save-dev <package>`

### Documentation Updates

- Main docs are in [`docs/`](../docs/) directory
- README.md provides quick start and examples
- Usage guide: [`docs/usage.md`](../docs/usage.md)
- Development guide: [`docs/develop.md`](../docs/develop.md)

### Adding Examples

- Main examples are in [`docs/examples`](../docs/examples/) directory
- Add new examples to demonstrate a new feature

### Modifying Examples

- Main examples are in [`docs/examples`](../docs/examples/) directory
- Modify existing examples if a feature or the public API changes

## Key Files to Understand

### Python Side

- **[`frooky/cli.py`](../frooky/cli.py)**: Argument parsing, CLI entry point
- **[`frooky/frida_runner.py`](../frooky/frida_runner.py)**: Core logic for loading hooks, attaching to processes, injecting agents
- **[`pyproject.toml`](../pyproject.toml)**: Project metadata, dependencies, build configuration

### Agent Side

- **[`frooky/agent/build.js`](../frooky/agent/build.js)**: Custom build orchestrator (handles TypeScript compilation, file watching)
- **[`frooky/agent/android/`](../frooky/agent/android/)**: Android-specific hook implementations
- **[`frooky/agent/ios/`](../frooky/agent/ios/)**: iOS-specific hook implementations
- **[`frooky/agent/package.json`](../frooky/agent/package.json)**: Frida bridge dependencies, build scripts

## Workflow for Code Changes

1. **Identify scope**: Python CLI, Android agent, iOS agent, docs or examples?
2. **Set up dev environment**: Virtual env + compile agents
3. **Make changes**: Edit relevant files
4. **Rebuild as needed**:
    - Android agent changes: `cd frooky/agent && npm run dev-android`
    - iOS agent changes: `cd frooky/agent && npm run dev-ios`
    - Python changes: No rebuild needed with `pip install -e .`
5. **Test manually**: Run `frooky` commands against test apps/hooks
6. **Verify CI would pass**: Run full build + install verification locally
7. **Update docs** if user-facing behavior changes
8. **Update examples** if an example exists or it makes sense to make one for a new feature
9. **Update Copilot instructions** in [`.github/copilot-instructions.md`](copilot-instructions.md) if needed

## Platform-Specific Notes

### Android

- Hooks Java/Kotlin methods using Frida's Java bridge (`frida-java-bride`)
- Class names use Java notation: `android.security.keystore.KeyGenParameterSpec$Builder`
- Can hook constructors with `$init` method name

### iOS

- Hooks Objective-C and Swift methods
- Uses Frida's ObjC and Swift bridges (`frida-objc-bridge` and `frida-swift-bridge`)
- Method syntax differs from Android (see [`docs/usage.md`](../docs/usage.md))

## Debugging Tips

- **Agent not loading**: Check that [`frooky/agent/dist/`](../frooky/agent/dist/) contains `agent-{platform}.js` and is recent
- **Import errors**: Ensure you're using the venv Python (`which python`)
- **Frida connection issues**: Verify target device has `frida-server` running
- **Build failures**: Check Node.js version (needs 24+), ensure [`compileAgent.sh`](../compileAgent.sh) is executable

## Security Considerations

This is a security testing tool, so:

- Be mindful of sensitive data in logs/output files
- Output files ([`output.json`](../output.json), `*.jsonl`) are git-ignored by default
- Agent code runs with elevated privileges inside target applications
- Always test on authorized/owned devices and applications

## Known Warnings & Issues

### Build Warnings (Non-Critical)

When building the package, you may encounter these warnings that can be safely ignored:

- **setuptools-scm shallow repository warning**: Occurs when git history is incomplete. The build still succeeds.
- **License format deprecation warnings**: The project uses an older license format in [`pyproject.toml`](../pyproject.toml) that setuptools recommends updating. This is cosmetic and doesn't affect functionality.

### Errors Encountered During Onboarding

During the creation of this instructions file, the following steps were validated:

1. **Agent compilation** (`./compileAgent.sh --prod`): ✅ Succeeded without errors
2. **Python package build** (`python -m build`): ✅ Succeeded with deprecation warnings (see above)
3. **Build artifacts verification**: ✅ Both `.whl` and `.tar.gz` created successfully
4. **Agent inclusion**: ✅ Both `agent-android.js` and `agent-ios.js` included in package

No critical errors were encountered, and the build system works as documented.

---

**Last Updated**: 2026-01-29
**Repository**: https://github.com/cpholguera/frooky
