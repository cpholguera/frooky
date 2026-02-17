# frooky Agent Documentation

This documentation will tell you everything you need to know about the frooky agent and its features.

- [What is the frooky Agent?](#what-is-the-frooky-agent)
- [Compile And Run Standalone Client](#compile-and-run-standalone-client)
- [Hook Declaration Quickstart](#hook-declaration-quickstart)
- [Structure of a Hook File](#structure-of-a-hook-file)
- [Parameter- and Return-Type Declaration](#parameter--and-return-type-declaration)
- [Platform-Dependent Hook Declaration](#platform-dependent-hook-declaration)
- [Event Filters](#event-filters)

## What is the frooky Agent?

First things first: The frooky agent is the part of frooky which is executed on the target device (Android or iOS). It is written in TypeScript and does all the heavy lifting like:

- Resolving the methods and functions which will be hooked
- Hooking said methods and functions
- Decoding the input arguments and return values
- Compiling the gathered data into events
- Sending the events back to the host

It can be run standalone, but usually it is used with the frooky _host_ written in Python.

## Compile And Run Standalone Client

If you want to use the frooky agent without the Python host, or if you want to develop the agent itself, you have to compile the standalone client:

- **Install all dependencies:**

  ```sh
  npm install
  ```

- **Compile the development standalone client:**

  ```sh
  npm run build:watch:android <hook*.yaml>
  npm run build:watch:ios <hook*.yaml>
  ```

  This will compile a development build of the frooky agent, watch for changes in its source code as well as all `hook*.yaml` files and keep the compiled agents in the folder `./dist` fresh.

- **Start Frida with the compiled agent:**

  For Android:

  ```sh
  frida -U -f org.owasp.mytargetapp dist/agent-android.js
  ```

  For iOS:

  ```sh
  frida -U -f org.owasp.mytargetapp dist/agent-io.js
  ```

## Hook Declaration Quickstart

If you want to start writing frooky hooks files, we recommend reading at the platform documentation:

- [Java Hook Declaration](docs/java-hook-declaration.md)
- [Objective-C Hook Declaration](docs/objective-c-hook-declaration.md)
- [Native Hook Declaration](docs/native-hook-declaration.md)

Also have a look at the [examples](./docs/examples/) and the TypeScript [type declaration](./types/index.d.ts).

They will give you all necessary information to write hook files for majority of use cases.

For more advanced features and use cases continue reading this documentation. It will guide you through all frooky agent features.

## Structure of a Hook File

frooky uses structured YAML files to declare which methods or functions will be hooked. This is called a _hook file_.

A hook file consists of optional metadata and a list of _hook declaration. The following YAML file describes the basic structure:

```yaml
metadata:                         # All metadata are optional
  name: <name>                    # Name of the hook collection
  platform: Android|iOS           # Target platform (hooks must be platform-specific)
  description: <description>      # Description of what the hook collection does
  masCategory: <mas_category>     # STORAGE, CRYPTO, AUTH, NETWORK, etc
  author: <author>                # Your name or organization
  version: <version>              # Semantic version (e.g., v1)

hooks:                            # Collection of hook declarations
  - <hook_declaration>
```

> [!NOTE]
> **Example:**
>
> The following hook file hooks all RNG initialization methods and functions on an Android device and captures its arguments, return values and stack trace. This information can be used to detect insecure RNG.
>
> ```yaml
> metadata:
>   name: RNG initialization
>   platform: Android
>   description: Hooks all RNG initialization methods on Android (Java, kotlin, native)
>   masCategory: CRYPTOGRAPHY
>   author: mas@owasp.org
>   version: v1
>
> hooks:
>   - <hook_declaration> 
> ```

There are differences between Android, iOS or native hooks. Nevertheless, they share the following common properties.

| Property           | Type     | Description                                                |
| ------------------ | -------- | ---------------------------------------------------------- |
| `module`           | string   | Library/framework name. Mandatory for `NativeHook`.        |
| `stackTraceLimit`  | number   | Maximum stack frames to capture (default: 10)              |
| `stackTraceFilter` | string[] | Regex patterns to filter stack traces (see examples below) |
| `debug`            | boolean  | Enable verbose logging                                     |

## Parameter- and Return-Type Declaration

An important feature of frooky is to decode data passed to functions or methods via arguments and their return value.

In some cases, this is not as trivial as it as it seems at first. For example, if an argument- or return value is simply a pointer, we need additional information in order to decode it properly.

frooky is pretty flexible and able to decode various datatype. But this requires some declaration.  Before writing hook declaration, it is therefore recommended reading the following documentation:

- [Parameter Declaration](docs/parameter-declaration.md)
- [Return Type Declaration](docs/return-type-declaration.md)

## Platform-Dependent Hook Declaration

Depending on the platform, the hooks declaration may look different. Please read the linked documentation if you want to learn how to write hooks for the platform you are interested in.

frooky currently supports three types of hooks:

| Hook Type        | Platform    | Description                                 | Documentation                                                     |
| ---------------- | ----------- | ------------------------------------------- |-------------------------------------------------------------------|
| `JavaHook`       | Android     | Hook for Java/Kotlin methods                |[`JavaHook`-Declaration](./docs/java-hook-declaration.md)          |
| `ObjectiveCHook` | iOS         | Hook for Objective-C methods                |[`ObjectiveCHook`-Declaration](./docs/java-hook-declaration.md)    |
| `NativeHook`     | Android/iOS | Hook for native functions (C/C++/Rust etc.) |[`NativeHook`-Declaration](./docs/java-hook-declaration.md)        |

> [!IMPORTANT]
> When loading a hook declaration, frooky will validate it against a JSON schema in order to detect invalid declaration. This makes sure, that the declaration does not contain hooks for different platforms for example.

## Event Filters

If you hook a method which is used widely, it may be that you capture may events you are not interested in. This makes the analysis more difficult.

An example is `SharedPreferences` on Android. Let's assume, you want to know, if the target app uses them to store sensitive data on the device:

```yaml
javaClass: android.app.SharedPreferencesImpl$EditorImpl
methods:
  - name: putString
```

frooky will capture the events you are looking for, but also many more, like the following one:

```json
{
  "id": "169a35b1-da19-492f-a90c-74d7cc5bdb3a",
  "type": "hook",
  "category": "STORAGE",
  "time": "2026-02-09T09:08:32.125Z",
  "class": "android.app.SharedPreferencesImpl$EditorImpl",
  "method": "putString",
  "instanceId": 175301911,
  "stackTrace": [
    "android.app.SharedPreferencesImpl$EditorImpl.putString(Native Method)",
    "com.google.crypto.tink.integration.android.SharedPrefKeysetWriter.write(SharedPrefKeysetWriter.java:70)",
    "com.google.crypto.tink.KeysetHandle.writeWithAssociatedData(KeysetHandle.java:869)",
    "com.google.crypto.tink.KeysetHandle.write(KeysetHandle.java:858)",
    "com.google.crypto.tink.integration.android.AndroidKeysetManager$Builder.generateKeysetAndWriteToPrefs(AndroidKeysetManager.java:353)",
    "com.google.crypto.tink.integration.android.AndroidKeysetManager$Builder.build(AndroidKeysetManager.java:292)",
    "androidx.security.crypto.EncryptedSharedPreferences.create(EncryptedSharedPreferences.java:169)",
    "androidx.security.crypto.EncryptedSharedPreferences.create(EncryptedSharedPreferences.java:131)"
  ],
  "inputParameters": [
    {
      "declaredType": "java.lang.String",
      "value": "__androidx_security_crypto_encrypted_prefs_key_keyset__"
    },
[...]
```

This method call is initiated by Android when `EncryptedSharedPreferences` are initiated. This library uses `SharedPreferences` to store an encryption key.

Usually, these events are not of interest to security testers, as they want to test the actual target app and not OS libraries.

To filter out events which are not originating from the target app, frooky can filter events based on the stack trace. The following `<hook_configuration>` will only capture events where the target package name matches the stack trace:

```yaml
javaClass: android.app.SharedPreferencesImpl$EditorImpl
methods:
  - name: putString
  - stackTraceFilter: "^org\.owasp\.mastestapp"
```

With this filter, the noise can be reduced.
