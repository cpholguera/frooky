# frooky Agent Documentation

This documentation will tell you everything you need to know about the frooky agent and its features.

## What is the frooky Agent?

The frooky agent is the part of frooky which is executed on the target device (Android or iOS). It is written in TypeScript and does all the heavy lifting like:

- Resolving the methods and functions which will be hooked
- Hooking said methods and functions
- Decoding the input arguments and return values
- Compiling the gathered data into events
- Sending the events back to the host

It can be run standalone, but usually it is used with the frooky _host_ written in Python.

## Declaring Hooks

frooky uses structured YAML files to declare which methods or functions will be hooked. We call this _hook file_.

A hook file consists of optional metadata and a list of _hook configuration_. The following YAML file describes the basic structure:

```yaml
metadata:                         # All metadata are optional
  name: <name>                    # Name of the hook collection
  platform: Android|iOS           # Target platform (hooks must be platform-specific)
  description: <description>      # Description of what the hook collection does
  masCategory: <mas_category>     # STORAGE, CRYPTO, AUTH, NETWORK, etc
  author: <author>                # Your name or organization
  version: <version>              # Semantic version (e.g., v1)

hooks:                            # Collection of hook configurations
  - <hook_configuration>
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
>   - <hook_configuration> 
> ```

For more on writing hook configurations please read:

- [Java Hooks](docs/java-hooks.md)
- [Objective-C Hook](docs/objective-c-hooks.md)
- [Swift Hooks](docs/swift-hooks.md)
- [Native Hooks](docs/native-hooks.md)

## How to Compile the Standalone Frooky Agent

### Install packages

```sh
cd agent/
npm install
```

This will create two files:

1. `./dist/agent-android.js`: Compressed production build of the frooky agent for android.
1. `./dist/agent-ios.js`: Uncompressed build of the frooky agent for iOS. Better for development.

These agents use the [Frida RPC API](https://frida.re/docs/javascript-api/#rpc-exports) (`rpc`) in order to fetch the `hooks.json` at runtime.

## Development workflow

If you want to work on the frooky agent code itself, it is recommended to use Frida in combination with the following commands:

```sh
npm run watch-frida-android ./docs/examples/hooks*.json
npm run watch-frida-ios ./docs/examples/hooks*.json
```

The agent will update when you change the code, but also the JSON hook files.
