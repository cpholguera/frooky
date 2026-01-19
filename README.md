# Frooky

```txt
   ___    ____           
  / __\  / _  |    _     _    _  _   _   _
 / _\   | (_) |  / _ \ / _ \ | / /  | | | |
/ /     / / | | | (_) | (_) ||  <   | |_| |
\/     /_/  |_|  \___/ \___/ |_|\_\  \__, |
                                     |___/
```

`frooky` is a [Frida](https://www.frida.re/)-based dynamic analysis tool for Android and iOS apps based on JSON hook files.

[![PyPi](https://badge.fury.io/py/frooky.svg)](https://pypi.python.org/pypi/frooky)

- Hook Java/Kotlin methods and native C/C++ functions
- Simple JSON hook file format
- Support for method overloads and stack trace capturing
- Argument capturing with various data types
- Filtering hooks by argument values or stack trace patterns
- Output events in JSON Lines format for easy processing

See more in [docs/usage.md](docs/usage.md).

## Installation

Simply install via pip and you'll get the `frooky` CLI tool:

```bash
pip3 install frooky
```

## Usage

Create a hook file (e.g., `hooks.json`) as described in [docs/usage.md](docs/usage.md), then run `frooky` with the desired options:

```bash
# Attach by app name
frooky -U -n "My App" --platform android hooks.json

# Spawn and add multiple hook files (hooks are merged)
frooky -U -f com.example.app --platform android storage.json crypto.json
```

See `frooky -h` for more options.

## Example

We'll use the OWASP MAS [MASTG-DEMO-0072](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0072/MASTG-DEMO-0072/) app to demonstrate hooking a cryptographic key generation method.

First you need to create a hook file, e.g., `crypto.json`:

```json
{
  "category": "CRYPTO",
  "hooks": [
    {
      "class": "android.security.keystore.KeyGenParameterSpec$Builder",
      "method": "$init",
      "maxFrames": 10
    }
  ]
}
```

Then run `frooky` with the hook file against your target app:

```bash
frooky -U -n "MASTestApp" --platform android crypto.json
```

Output (pretty-printed for readability):

> Events are written to the output file in JSON Lines format (one JSON object per line, known as NDJSON). You can easily pretty-print it e.g. using `jq . output.json`.

```json
{
  "id": "14535033-08ea-4063-897c-eacd4a885d8b",
  "type": "hook",
  "category": "CRYPTO",
  "time": "2026-01-14T16:02:21.782Z",
  "class": "android.security.keystore.KeyGenParameterSpec$Builder",
  "method": "$init",
  "instanceId": 35486102,
  "stackTrace": [
    "android.security.keystore.KeyGenParameterSpec$Builder.<init>(Native Method)",
    "org.owasp.mastestapp.MastgTest.generateKey(MastgTest.kt:97)",
    "org.owasp.mastestapp.MastgTest.mastgTest(MastgTest.kt:41)",
    "org.owasp.mastestapp.MainActivityKt.MainScreen$lambda$12$lambda$11(MainActivity.kt:101)",
    "org.owasp.mastestapp.MainActivityKt.$r8$lambda$Pm6AsbKBmypP53K-UABM21E_Xxk(Unknown Source:0)",
    "org.owasp.mastestapp.MainActivityKt$$ExternalSyntheticLambda3.run(D8$$SyntheticClass:0)",
    "java.lang.Thread.run(Thread.java:1012)"
  ],
  "inputParameters": [
    {
      "declaredType": "java.lang.String",
      "value": "MultiPurposeKey"
    },
    {
      "declaredType": "int",
      "value": 15
    }
  ],
  "returnValue": [
    {
      "declaredType": "void",
      "value": "void"
    }
  ]
}
```

See more in [docs/usage.md](docs/usage.md) and see a full example in [docs/examples/example.md](docs/examples/example.md).
