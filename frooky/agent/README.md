# frooky Agent Documentation

This documentation covers everything you need to know about the frooky agent and its features.

- [What is frooky?](#what-is-frooky)
- [Quickstart](#quickstart)
- [Compile And Run Standalone Client](#compile-and-run-standalone-client)
- [Structure of a Hook File](#structure-of-a-hook-file)
- [Hook Declaration](#hook-declaration)
- [Parameter- and Return-Type Declaration](#parameter--and-return-type-declaration)
- [Additional Settings and Best Practices](#additional-settings-and-best-practices)

## What is frooky?

First things first: The frooky agent is the part of frooky that runs on the target device (Android or iOS). It is written in TypeScript and handles much of the heavy lifting, including:

- Resolving the methods and functions to hook
- Hooking those methods and functions
- Decoding input arguments and return values
- Processing the gathered data
- Generating events from the processed data
- Sending the events back to the host

It can run standalone, but it is usually used with the frooky host, which is written in Python.

Use it, if you **know what you want to hook** but you don't want to write custom frooky scripts or copy and paste them together.

For example you can use it to quickly hook functions or methods based on public API documentation and quickly get insight about them. 

However, frooky is not a tool for tracing function calls. For that, you should use [`frida-trace`](https://frida.re/docs/frida-trace/). But you may use the insight from `frida-trace`, and use it as starting point to write a frooky hook in order to decode more complex values entering and exiting the functions.

In general, the frooky hooks are designed in a way that you should be able to easily map them onto existing API documentation. 
 
## Quickstart

If you want to start writing frooky hooks files, we recommend reading the platform documentation:

<!-- no toc -->
- [Compile And Run Standalone Client](#compile-and-run-standalone-client)
- [`JavaHook`Declaration](docs/java-hook-declaration.md)
- [`ObjcHook` Declaration](docs/objective-c-hook-declaration.md)
- [`NativeHook` Declaration](docs/native-hook-declaration.md)

Also take a look at the [examples](./docs/examples/) and the TypeScript [type declaration](./types/index.d.ts).

These resources will give you all the necessary information to write hook files for the majority of use cases.

For more advanced features and use cases, continue reading this documentation. It will guide you through all frooky agent features.

## Compile And Run Standalone Client

If you want to use the frooky agent without the Python host, or to develop the agent itself, you must compile the standalone client:

- **Install all dependencies:**

  ```sh
  npm install
  ```

- **Compile the development standalone client:**

  ```sh
  npm run watch-android hook.yaml
  npm run watch-ios hook.yaml
  ```

  You can specify one or more `hook.yaml` files. Pattern expansion (`glob`) is supported.

This will compile a development build of the frooky agent, watch for changes in its source code and all `hook.yaml` files, and keep the compiled agents in the `./dist` folder up to date.

- **Start Frida with the compiled agent:**

  For Android:

  ```sh
  frida -U -f org.owasp.mytargetapp dist/agent-android.js
  ```

  For iOS:

  ```sh
  frida -U -f org.owasp.mytargetapp dist/agent-ios.js
  ```

## Structure of a Hook File

frooky uses structured YAML files to declare which methods or functions will be hooked. These are called _hook files_.

A hook file consists of optional metadata and a list of _hook declarations_. The following YAML file describes the basic structure:

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

**Example:**

The following hook file hooks all RNG initialization methods and functions on an Android device, capturing their arguments, return values, and stack trace. This information can be used to detect insecure RNG.
 
```yaml
metadata:
  name: RNG initialization
  platform: Android
  description: Hooks all RNG initialization methods on Android (Java, kotlin, native)
  masCategory: CRYPTOGRAPHY
  author: mas@owasp.org
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
> When loading a hook declaration, frooky will validate it and to detect invalid declarations. For example, it is not possible to declare a `JavaHoook` and a `ObjectiveCHook` hook in one hook file.

## Parameter- and Return-Type Declaration

An important feature of frooky is to decode data passed to functions or methods via arguments and their return values.

Depending on the type of the values, this can be simple or more complex. For example, if an argument or return value is simply a pointer, we need additional information to decode it properly.

frooky tries to decode arguments and return values by itself if possible. But in some cases, it is necessary to provide information about the types used. Before writing a hook declaration, it is therefore recommended to read the following documentation:

- [Parameter Declaration](docs/parameter-declaration.md)
- [Return Type Declaration](docs/return-type-declaration.md)


## Additional Settings and Best Practices

With the information in this document, you should be ready to write a hook file. But there are additional settings and features. They are described in the document [Additional Settings and Best Practices](docs/additional-features.md)
