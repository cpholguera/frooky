# Frooky

```txt
   ___    ____           
  / __\  / _  |    _     _    _  _   _   _
 / _\   | (_) |  / _ \ / _ \ | / /  | | | |
/ /     / / | | | (_) | (_) ||  <   | |_| |
\/     /_/  |_|  \___/ \___/ |_|\_\  \__, |
                                     |___/
```

`frooky` is a [Frida](https://www.frida.re/)-based dynamic analysis tool for Android and iOS apps based on YAML hook files.

![PyPI - Version](https://img.shields.io/pypi/v/frooky?color=fuchsia) [![Test](https://github.com/cpholguera/frooky/actions/workflows/test.yml/badge.svg)](https://github.com/cpholguera/frooky/actions/workflows/test.yml)

- Hook Java/Kotlin methods and native C/C++ functions
- Simple YAML hook file format
- Support for method overloads and stack trace capture
- Argument capture with various data types
- Return value capture with various data types
- Filter hooks by argument values or stack trace patterns
- Output events in JSON Lines format for easy processing

Use it, if you **know what you want to hook** but you don't want to write custom Frida scripts or copy and paste them together. For example you can use it to quickly hook functions or methods based on public API documentation and quickly get insight about them. 

> [!NOTE]
>
> This documentation describes the intended feature set for [frooky 1.0](https://github.com/cpholguera/frooky/milestone/1). At the time of writing this document, not all described features may have been fully implemented and there may be breaking changes to the hook file API until the release of frooky 1.0. 
> 
> [Feedback](https://github.com/cpholguera/frooky/discussions) is always welcome. 
 

## Installation

Simply install via pip to get the `frooky` CLI tool:

```bash
pip3 install frooky
```


## Usage

Create a hook file (e.g., `hooks.yaml`) with the functions and/or methods you want to hook. 

If you are already familiar with Frida and function hooking, we recommend using the documented examples as a quick starting point. You find them in the folder [docs/examples/](./docs/examples/).

For more information, read all about the structure in chapter [Structure of a Hook File](#structure-of-a-hook-file).

After you created the desired hook file, run `frooky`:

```bash
# Attach by app name
frooky -U -n org.owasp.mastestapp --platform android hooks.yaml

# Spawn and add multiple hook files (hooks are merged)
frooky -U -f org.owasp.mastestapp --platform android storage.yaml crypto.yaml

# Spawn and add multiple hook files using globs (hooks are merged)
frooky -U -f org.owasp.mastestapp --platform android hooks_*.yaml
```

See `frooky -h` for more options.


## Structure of a Hook File

frooky uses structured YAML files to declare which methods or functions will be hooked. These are called _hook files_.

A hook file consists of optional metadata and a list of _hook declarations_. The following YAML file describes the basic structure:

```yaml
metadata:                         # All metadata are optional
  name: <name>                    # Name of the hook collection
  platform: Android|iOS           # Target platform (hooks must be platform-specific)
  description: <description>      # Description of what the hook collection does
  category: <category>            # Category of the hook collection
  author: <author>                # Your name or organization
  version: <version>              # Semantic version (e.g., v1)

hooks:                            # Collection of hook declarations
  - <hook_declaration>
```

**Example:**

The following hook file hooks all RNG initialization methods and functions on an Android device, capturing their arguments, return values, and stack trace. This information can be used to detect insecure RNG.
 
```yaml
metadata:
  name: RNG initialization
  platform: Android
  description: Hooks all RNG initialization methods on Android (Java, kotlin, native)
  masCategory: CRYPTOGRAPHY
  author: frooky dev team
  version: v1

hooks:
  - <hook_declaration> 
```

## Hook Declaration

Now, let's look the `<hook_declaration>` itself. Depending on the platform, the hook declaration may look different. Please read the linked documentation to learn how to write hooks for the platform you are interested in.

frooky currently supports three types of hooks:

| Hook Type        | Platform    | Description                                 | Documentation                                                          |
| ---------------- | ----------- | ------------------------------------------- | ---------------------------------------------------------------------- |
| `JavaHook`       | Android     | Hook for Java/Kotlin methods                | [`JavaHook`-Declaration](./docs/java-hook-declaration.md)              |
| `ObjcHook` | iOS         | Hook for Objective-C methods                | [`ObjcHook`-Declaration](./docs/objective-c-hook-declaration.md) |
| `NativeHook`     | Android/iOS | Hook for native functions (C/C++/Rust etc.) | [`NativeHook`-Declaration](./docs/native-hook-declaration.md)          |

> [!IMPORTANT]
> When loading a hook declaration, frooky will validate it and to detect invalid declarations. For example, it is not possible to declare a `JavaHook` and a `ObjcHook` hook in one hook file.

## Parameter- and Return-Type Declaration

An important feature of frooky is to decode data passed to functions or methods via arguments and their return values.

Depending on the type of the values, this can be simple or more complex. For example, if an argument or return value is simply a pointer, we need additional information to decode it properly.

frooky tries to decode arguments and return values by itself if possible. But in some cases, it is necessary to provide information about the types used. Before writing a hook declaration, it is therefore recommended to read the following documentation:

- [Parameter Declaration](docs/parameter-declaration.md)
- [Return Type Declaration](docs/return-type-declaration.md)

## Example

We'll use the OWASP MAS [MASTG-DEMO-0072](https://mas.owasp.org/MASTG/demos/android/MASVS-CRYPTO/MASTG-DEMO-0072/MASTG-DEMO-0072/) app to demonstrate hooking a cryptographic key generation method.

First you need to create a hook file, e.g., `keygen.yaml`:

```yaml
metadata:
  name: Android Key Generator Specifications
  platform: Android
  description: Captures the initialization of a KeyGenParameterSpec Builder 
  category: CRYPTO
  author: frooky dev team
  version: v1

hooks:
  - javaClass: android.security.keystore.KeyGenParameterSpec$Builder
    methods:
      - $init
```

Then run `frooky` with the hook file against your target app:

```bash
frooky -U -n org.owasp.mastestapp --platform android keygen.yaml
```

Events are written to the output file in JSON Lines format (one JSON object per line, known as NDJSON). 

Example Output (pretty-printed for readability):

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

## More Information

Please refer to the following documentation for more information about various topics:


- [Additional Settings and Best Practices](./docs/additional-features.md)
- [Development / Local Testing](./docs/develop.md)
- [Understanding Output Format](./docs/output.md)

