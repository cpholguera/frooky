# Frooky Hook Documentation

A frooky hook configuration describes how to hook a Java, Swift, Objective-C or native process.

This documentation describes the structure of a hook file and provides examples for the various cases.

<!-- no toc -->
- [Frooky Configuration](#frooky-configuration)
- [Basic Hook Configuration](#basic-hook-configuration)
  - [Hook Types](#hook-types)
  - [Properties for All Type of Hooks](#properties-for-all-type-of-hooks)
- [Java Hook Configuration](#java-hook-configuration)
  - [Basic Syntax](#basic-syntax)
  - [Method Overloads](#method-overloads)
  - [Java Type Signatures](#java-type-signatures)
- [Objective-C Hook Configuration](#objective-c-hook-configuration)
  - [Basic Syntax](#basic-syntax-1)
  - [Argument and Return Types](#argument-and-return-types)
- [Native Hook Configuration](#native-hook-configuration)
  - [Basic Syntax](#basic-syntax-2)
  - [Argument Descriptors](#argument-descriptors)
  - [Buffer Handling](#buffer-handling)
  - [Capturing Return Values](#capturing-return-values)
- [Swift Hook Configuration](#swift-hook-configuration)
  - [Basic Syntax](#basic-syntax-3)
- [Custom Decoders](#custom-decoders)

For each of the feature described here, there are examples in the [examples folder](../docs/examples/).

You will not only find `hooks.yaml` files there but also TypeScript code which shows, how the various types can be used to develop frooky, or [custom decoders](#custom-decoders) for certain cases.

## Frooky Configuration

A frooky configuration contains optional metadata about the hook collection, and a set of `<hook_configuration>`.

```yaml
metadata:                         # All metadata are optional
  name: <name>                    # Name of the hook collection
  platform: Android|iOS           # Target platform
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
> ```yaml
> metadata: android.webkit.WebView 
>   name: RNG initialization
>   description: Hooks all RNG initialization methods on Android (Java, kotlin, native)
>   masCategory: CRYPTOGRAPHY
>   author: mas@owasp.org
>   version: v1
>
> hooks:
>   - <hook_configuration> 
> ```

---------------------------

## Basic Hook Configuration

A `<hook_configuration>` consists of one or more of the following hook types:

### Hook Types

What kind of a type the `<hook_configuration>` is, is determined by a unique property.

Frooky supports four types of hooks:

| Hook Type        | Unique Properties | Platform    | Description                                 |
| ---------------- | ---------------   | ----------- | ------------------------------------------- |
| `JavaHook`       | `javaClass`       | Android     | Hook for Java/Kotlin methods                |
| `ObjectiveCHook` | `objClass`        | iOS         | Hook for Objective-C methods                |
| `NativeHook`     | `module`          | Android/iOS | Hook for native functions (C/C++/Rust etc.) |
| `SwiftHook`      | `swiftClass`      | iOS         | Hook for Swift methods                      |

> [!IMPORTANT]
> When loading a `<hook_configuration>`, frooky will validate it against a JSON schema in order to detect invalid configuration. This makes sure, that the `<hook_configuration>` does not contain hooks for different platforms for example.

### Properties for All Type of Hooks

There are differences between Android, iOS or native hooks. Nevertheless, they share a few common properties.

The following properties can be used for all types:

| Property           | Type     | Description                                            |
| ------------------ | -------- | -------------------------------------------------------|
| `module`           | string   | Library/framework name. Mandatory for `NativeHook`.    |
| `stackTraceLimit`  | number   | Maximum stack frames to capture                        |
| `stackTraceFilter` | string[] | Regex patterns to filter stack traces                  |
| `debug`            | boolean  | Enable verbose logging                                 |

---------------------------

## Java Hook Configuration

### Basic Syntax

The minimum necessary properties are `javaClass` and `methods`:

```yaml
javaClass: <class_name>           # Fully qualified Java class name
methods:                          # List of methods to be hooked
  - <java_method>
```

For this case *all* methods from the class will be hooked.

> [!NOTE]
> **Example:**
>
> ```yaml
> javaClass: android.webkit.WebView 
> methods:
>   - name: $init
>   - name: loadUrl
> ```
>
> This `<hook_configuration>` will hook the following methods:
>
> ```kotlin
> android.webkit.WebView()
> android.webkit.WebView.loadUrl(url: String)
> android.webkit.WebView.loadUrl(url: String, additionalHttpHeaders: MutableMap<String!, String!>)
> ```

> [!TIP]
>
> Use the following syntax for dynamic `<class_name>` lookup at runtime:
>
> - **Exact match**: `org.owasp.mastestapp.MainActivity`
> - **Wildcards**: `org.owasp.*.Http$Client` (per package level)
> - **Nested classes**: Use `$` separator (e.g., `Outer$Inner`)

> [!TIP]
> It is Frida convention that `$init` is the name of the constructor of a class.

### Method Overloads

If you only want to hook a certain overload, specify it by adding one or more `overload`:

```yaml
javaClass: <class_name>           # Fully qualified Java class name 
methods:
  - name: <method_name>           # Name of the Java method
    overloads:                    # List of overloads to be hooked
      - <overload>       
```

> [!NOTE]
> **Example:**
>
> ```yaml
> javaClass: android.content.Intent
> methods:
>   - name: putExtra
>     overloads:
>       - args:
>          - type: java.lang.String
>          - type: java.lang.String
>        - args:
>          - type: java.lang.String
>          - type: "[Z"
>  ```
>
> This will *only* hook the following methods:
>
> ```kotlin
> open fun android.content.Intent.putExtra(name: String!, value: String?): Intent
> open fun android.content.Intent.putExtra(name: String!, value: BooleanArray?): Intent
> ```

### Type Signatures

Frida, and therefore frooky, accept both [JNI type signatures](https://docs.oracle.com/en/java/javase/25/docs/specs/jni/types.html) but also their own, slightly different type signatures.

The following table shows the different kinds of types and their representation in Java, JNI and Frida:

| Kind              | Java Type Signature                                                                           | JNI Type Signature                                           | Frida Type Signature                                                                                 |
|-------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| Primitive         | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void`  | `Z`<br>`B`<br>`C`<br>`S`<br>`I`<br>`J`<br>`F`<br>`D`<br>`V`  | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void`         |
| Primitive Array   | `boolean[]`<br>`byte[]`<br>...                                                                | `[Z`<br>`[B`<br>...                                          | `[Z`<br>`[B`<br>...                                                                                  |
| Reference         | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                              | `Ljava/lang/Object;`<br>`Lorg/owasp/MyClass`<br>...          | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                                   |
| Reference Array   | `Object[]`<br>`MyClass[]`<br>...                                                              | `[Ljava/lang/Object;`<br>`[Lorg/owasp/MyClass`<br>...        | `[Ljava.lang.Object`<br>`[Lorg.owasp.MyClass`<br>...                                               |
| Multi-Dimensional | `int[][]`<br>`String[][]`<br>...                                                              | `[[I`<br>`[[Ljava/lang/String;`<br>...                       | `[[int`<br>`[[Ljava.lang.String`<br>...                                                              |

> [!NOTE]
> While both JNI and Frida type signatures are valid, it is more common to use Frida type signatures.

---------------------------

## Objective-C Hook Configuration

### Basic Syntax

The minimum necessary properties are `objcClass` and `methods`:

```yaml
objClass: <objc_class>            # Fully qualified Objective-C class
methods:                          # List of Objective-C methods to be hooked
  - <objc_method>
```

> [!NOTE]
> **Example:**
>
> ```yaml
> objClass: LAContext
> methods:
>  - name: "- invalidate"
> ```
>
> This `<hook_configuration>` will hook the following Objective-C method:
>
> ```objectivec
> - (void) invalidate;
> ```

> [!TIP]
>
> Objective-C method selectors can hook instance and class methods:
>
> - **Instance methods**: `- biometryType`
> - **Type methods**: `+ removeProperties`
>

### Argument and Return Types

If a `<objc_method>` has a return value or method arguments, frooky needs to how to decode them.

This is done by declaring the types in each `<objc_method>`. The syntax the same as used in the [official documentation](https://developer.apple.com/documentation?language=objc).

```yaml
objClass: <class_name>            # Fully qualified Objective-C class
methods:                       
  - name: <method_name>           # Name of the Objective-C method to be hooked
    args:                         # Positional list of argument types
      - <argument_type>    
    ret: <return_type>            # Type of the return value
```

> [!NOTE]
>
> **Example:**
>
> ```yaml
> objClass:  LAPrivateKey
> methods:
>  - name: "- setCredential"
>    args:
>      - "(NSData *) credential"
>      - "(LACredentialType) type"
>    ret: (BOOL)
>  ```
>
> Frooky will now try to decode the arguments and the return value based the type.
>

> [!IMPORTANT]
> At the moment, frooky provides decoders for simple types. It may therefor be, that the data is not decoded in depth.
>
> An example:
>
> ```yaml
> - objClass:   LAPublicKey
>   methods:
>    - name: "- decryptData"
>      args:
>        - "(NSData *) data"
>        - "(SecKeyAlgorithm) algorithm"
>        - "(void (^)(NSData * , NSError * )) handler"
> ```
>
> This `<hook_configuration>` encrypts the data and invokes the handler upon completion. To access the decrypted data, we must hook the handler implementation itself, as we need to intercept its first argument `(NSData * , NSError * )` when the method calls the handler after decryption finishes.
>
> At the moment, this feature is not yet implemented. You can find more on the topic of custom decoders in chapter [Custom Decoders](#custom-decoders).
>

## Native Hook Configuration

### Basic Syntax

The minimum necessary properties are `module` and `symbols`:

```yaml
module: <native_class>          # Fully qualified Objective-C class
symbols:                        # List of Objective-C methods to be hooked
  - <symbol>
```
















### Basic Syntax

The minimum necessary property is `symbol`:

```yaml
- symbol: <symbol>
```

> [!NOTE]
> **Example:**
>
> ```yaml
> - symbol: open
>   args:
>     - name: pathname
>       type: string
>     - name: flags
>       type: int32
> ```
>
> This `<hook_configuration>` will hook the native `open()` function.

> [!TIP]
>
> Native hooks work on both Android and iOS platforms for C/C++ functions.
>
> Use `module` property to specify the library containing the symbol:
>
> ```yaml
> - symbol: SSL_write
>   module: libssl.so
> ```

### Argument Descriptors

Native hooks require explicit argument descriptors to capture parameters:

```yaml
- symbol: <symbol>
  args:
    - name: <arg_name>
      type: <native_arg_type>
      direction: <in|out>
```

> [!NOTE]
> **Example:**
>
> ```yaml
> - symbol: memcpy
>   args:
>     - name: dest
>       type: pointer
>       direction: out
>     - name: src
>       type: bytes
>       length: 256
>       direction: in
>     - name: n
>       type: uint32
> ```

### Buffer Handling

For buffer arguments, specify length using one of these methods:

| Property      | Description                              |
|---------------|------------------------------------------|
| `length`      | Fixed buffer length in bytes             |
| `lengthInArg` | Index of argument containing the length  |

> [!NOTE]
> **Example:**
>
> ```yaml
> - symbol: read
>   args:
>     - name: fd
>       type: int32
>     - name: buf
>       type: bytes
>       lengthInArg: 2
>       direction: out
>     - name: count
>       type: uint32
> ```

### Capturing Return Values

To capture the function's return value, add a descriptor with `retValue: true`:

```yaml
- symbol: <symbol>
  args:
    - name: <return_name>
      type: <native_arg_type>
      retValue: true
```

> [!NOTE]
> **Example:**
>
> ```yaml
> - symbol: malloc
>   args:
>     - name: size
>       type: uint32
>     - name: result
>       type: pointer
>       retValue: true
> ```

## Swift Hook Configuration

> [!IMPORTANT]
> At the moment, frooky only supports `SwiftHook` if the mangled symbols have not been stripped. These are required to lookup the location of the method during runtime. Usually, productive build are stripped of them.
>
> At them moment, frooky does not support other means of Swift function hooking, because they require manual reverse engineering, which is not the focus of frooky at the time.
>

### Basic Syntax

The minimum necessary properties for a `SwiftHook` are `swiftClass` and `mangledSymbol`:

```yaml
- swiftClass: <swift_class>
  mangledSymbol: <mangled_symbol>
```

> [!NOTE]
> **Example:**
>
> ```yaml
> - swiftClass: MyApp.NetworkManager
>   mangledSymbol: _$s5MyApp14NetworkManagerC11sendRequestyyF
> ```
>
> This `<hook_configuration>` will hook the mangled Swift method symbol.

<!-- 

### Basic Syntax

```yaml
- swiftClass: <Module.ClassName>
  symbol: <mangled_symbol>
  args:
    - name: <arg_name>
      type: <arg_type>
```

### Example

```yaml
- swiftClass: Foundation.UserDefaults
  symbol: _TFC10Foundation12UserDefaults6setKey_forKey_
  args:
    - name: value
      type: pointer
    - name: key
      type: string
```

## Objective-C Hook Configuration

## Native Hook Configuration

---------------------------
## TypeScript API

### Type Definitions

```typescript
import * as Frooky from 'frooky'

// Java Hook
const javaHook: Frooky.JavaHook = {
  javaClass: 'android.net.wifi.WifiManager',
  methods: [
    { name: 'getConnectionInfo' }
  ]
}

// Native Hook
const nativeHook: Frooky.NativeHook = {
  module: 'libc.so',
  symbol: 'open',
  args: [
    { name: 'pathname', type: 'string' },
    { name: 'flags', type: 'int32' }
  ]
}

// Objective-C Hook
const objcHook: Frooky.ObjectiveCHook = {
  objClass: 'NSUserDefaults',
  symbol: '- setObject:forKey:',
  args: [
    { name: 'value', type: 'pointer' },
    { name: 'key', type: 'string' }
  ]
}

// Swift Hook
const swiftHook: Frooky.SwiftHook = {
  swiftClass: 'Foundation.FileManager',
  symbol: '_TFC10Foundation11FileManager8contentsAtPath_',
  args: [
    { name: 'path', type: 'string' }
  ]
}
```

### Complete Configuration

```typescript
const hooks: Frooky.Hooks = {
  category: 'NETWORK',
  hooks: [
    javaHook,
    nativeHook,
    objcHook,
    swiftHook
  ]
}
```

## Examples

### Android: Hooking Intent Operations

```yaml
category: PLATFORM

hooks:
  - javaClass: android.content.Intent
    methods:
      - name: setFlags
        overloads:
          - args:
              - name: int
                decoder: IntentFlagsDecoder
      - name: putExtra
        overloads:
          - args:
              - name: java.lang.String
              - name: java.lang.String
    stackTraceLimit: 10
```

### Android: Hooking SQLite Operations

```yaml
category: STORAGE

hooks:
  - javaClass: android.database.sqlite.SQLiteDatabase
    methods:
      - name: query
        overloads:
          - args:
              - name: java.lang.String
              - name: "[Ljava.lang.String;"
              - name: java.lang.String
              - name: "[Ljava.lang.String;"
              - name: java.lang.String
              - name: java.lang.String
              - name: java.lang.String
      - name: execSQL
    debug: true
```

### Android: Hooking Native Crypto Functions

```yaml
category: CRYPTO

hooks:
  - module: libcrypto.so
    symbol: EVP_EncryptInit_ex
    args:
      - name: ctx
        type: pointer
      - name: type
        type: pointer
      - name: impl
        type: pointer
      - name: key
        type: bytes
        length: 32
      - name: iv
        type: bytes
        length: 16
      - name: result
        type: int32
        retValue: true
    stackTraceLimit: 10

  - module: libssl.so
    symbol: SSL_write
    args:
      - name: ssl
        type: pointer
      - name: buf
        type: bytes
        lengthInArg: 2
      - name: num
        type: int32
      - name: written
        type: int32
        retValue: true
```

### iOS: Hooking Keychain Operations

```yaml
category: STORAGE

hooks:
  - objClass: SecItemAdd
    module: Security
    symbol: SecItemAdd
    args:
      - name: attributes
        type: CFDictionary
      - name: result
        type: pointer
        direction: out
      - name: status
        type: int32
        retValue: true

  - objClass: SecItemCopyMatching
    module: Security
    symbol: SecItemCopyMatching
    args:
      - name: query
        type: CFDictionary
      - name: result
        type: pointer
        direction: out
      - name: status
        type: int32
        retValue: true
```

### iOS: Hooking UserDefaults

```yaml
category: STORAGE

hooks:
  # Objective-C
  - objClass: NSUserDefaults
    symbol: "- setObject:forKey:"
    args:
      - name: value
        type: pointer
      - name: key
        type: string

  # Swift
  - swiftClass: Foundation.UserDefaults
    symbol: _TFC10Foundation12UserDefaults6setKey_forKey_
    args:
      - name: value
        type: pointer
      - name: key
        type: string
```

### iOS: Hooking Network Requests

```yaml
category: NETWORK

hooks:
  - objClass: NSURLSession
    symbol: "- dataTaskWithRequest:completionHandler:"
    args:
      - name: request
        type: pointer
      - name: completionHandler
        type: pointer
      - name: task
        type: pointer
        retValue: true
```

## Advanced Features

### Stack Trace Filtering

Filter out calls which do not originate from your target app, but maybe from an noisy SDK:

```yaml
- javaClass: android.content.SharedPreferences
  methods:
    - name: getString
  stackTraceLimit: 10
  stackTraceFilter:
    - "^org\\.owasp.\\."
```

### Debug Mode

Enable verbose logging for troubleshooting:

```yaml
- javaClass: com.example.MyClass
  methods:
    - name: debugMe
  debug: true
```

### Multiple Overloads

Handle methods with different signatures:

```yaml
- javaClass: android.content.Intent
  methods:
    - name: putExtra
      overloads:
        - args:
            - name: java.lang.String
            - name: java.lang.String
        - args:
            - name: java.lang.String
            - name: int
        - args:
            - name: java.lang.String
            - name: "[B"
```

### Custom Decoders

Use custom decoders for complex types:

```yaml
- javaClass: android.content.Intent
  methods:
    - name: setFlags
      overloads:
        - args:
            - name: int
              decoder: IntentFlagsDecoder  # Custom argument value decoder
    - name: getFlags
      decoder: IntentFlagsDecoder  # Custom return value decoder
```

Available decoders are located in `./android/decoders`.

## OWASP MAS Categories

Frooky supports categorizing hooks by OWASP Mobile Application Security (MAS) testing domains:

| Category     | Description                            |
| ------------ | -------------------------------------- |
| `STORAGE`    | Data storage and privacy               |
| `CRYPTO`     | Cryptographic operations               |
| `AUTH`       | Authentication mechanisms              |
| `NETWORK`    | Network communication                  |
| `PLATFORM`   | Platform interaction                   |
| `CODE`       | Code quality and build                 |
| `RESILIENCE` | Resilience against reverse engineering |
| `PRIVACY`    | Privacy controls                       |

## Best Practices

### 1. Organize Hooks by Category

```yaml
# crypto-hooks.yaml
category: CRYPTO
hooks:
  - # crypto-related hooks

# network-hooks.yaml
category: NETWORK
hooks:
  - # network-related hooks
```

### 2. Use Stack Trace Filtering

Reduce noise in logs by only including events relevant to you:

```yaml
stackTraceFilter:
  - "^org\\.owasp\\."
  - "^android\\."
```

### 3. Start with Debug Mode

Enable debug mode during development:

```yaml
debug: true
```

### 4. Specify Module Names

Improve hook reliability:

```yaml
- module: libcrypto.so
  symbol: EVP_EncryptInit_ex
``` -->
