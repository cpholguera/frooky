# Frooky Hook Documentation

A frooky hook configuration describes how to hook a Java, Swift, Objective-C or native process.

This documentation describes the structure of a hook file and provides examples for the various cases.

## Frooky Configuration

A frooky configuration contains optional metadata about the hooks, and a set of `<hook_configuration>`.

```yaml
metadata:                      # All metadata are optional
  name: <name>                 # Name of the hook collection
  platform: Android|iOS        # Target platform
  description: <description>   # Description of what the hook collection does
  masCategory: <mas_category>  # STORAGE, CRYPTO, AUTH, NETWORK, etc
  author: <author>             # Your name or organization
  version: <version>           # Semantic version (e.g., v1)

hooks:
  - <hook_configuration>       # Hook object - see hooks section below
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

## Hook Configuration

A `<hook_configuration>` consists of one or more of the following hook types:

### Hook Types

Frooky supports four types of hooks:

| Hook Type        | Platform    | Description                 |
| ---------------- | ----------- | --------------------------- |
| `JavaHook`       | Android     | Hook Java/Kotlin methods    |
| `NativeHook`     | Android/iOS | Hook native C/C++ functions |
| `ObjectiveCHook` | iOS         | Hook Objective-C methods    |
| `SwiftHook`      | iOS         | Hook Swift methods          |

> [!WARNING]
> The set must be compatible with one target platform. It is not possible to mix a `JavaHook` and a `ObjectiveCHook` in the same `hooks` list.

### Optional Properties

All hook types support these optional properties:

| Property           | Type     | Description                           |
| ------------------ | -------- | ------------------------------------- |
| `module`           | string   | Library/framework name                |
| `stackTraceLimit`  | number   | Maximum stack frames to capture       |
| `stackTraceFilter` | string[] | Regex patterns to filter stack traces |
| `debug`            | boolean  | Enable verbose logging                |

## Java Hook Configuration

### Basic Syntax

The minimum necessary properties are `<class_name>` and one `<method_name>`:

```yaml
- javaClass: <class_name>
  methods:
    - name: <method_name>
```

For this case *all* methods from the class will be hooked.

> [!NOTE]
> **Example:**
>
> ```yaml
> - javaClass: android.webkit.WebView 
>   methods:
>     - name: $init
>     - name: loadUrl
> ```
>
> This will hook the following methods:
>
> ```kotlin
> android.webkit.WebView.()
> android.webkit.WebView.loadUrl(url: String)
> android.webkit.WebView.loadUrl(url: String, additionalHttpHeaders: MutableMap<String!, String!>)
> ```

> [!TIP]
>
> You can use the following syntax for dynamic `<class_name>` lookup at runtime:
>
> - **Exact match**: `org.owasp.mastestapp.MainActivity`
> - **Wildcards**: `org.owasp.*.Http$Client` (per package level)
> - **Nested classes**: Use `$` separator (e.g., `Outer$Inner`)

### Method Overloads

If you only want to hook a certain overload, specify it by adding one or more `overload`:

```yaml
- javaClass: <class_name>
  methods:
    - name: <method_name>
    - overloads: <overload>
```

> [!NOTE]
> **Example:**
>
> ```yaml
> - javaClass: android.content.Intent
>   methods:
>     - name: putExtra
>       overloads:
>         - args:
>            - name: java.lang.String
>            - name: java.lang.String
>        - args:
>            - name: java.lang.String
>            - name: int
>  ```

### Java Type Notation Is Frida Notation

Examples:

| Type          | Notation              |
| ------------- | --------------------- |
| Primitive int | `int`                 |
| String        | `java.lang.String`    |
| Byte array    | `[B`                  |
| String array  | `[Ljava.lang.String;` |
| Custom class  | `com.example.MyClass` |

## Native Hook Configuration

### Basic Syntax

```yaml
- module: <library.so>
  symbol: <function_name>
  args:
    - name: <arg_name>
      type: <arg_type>
```

### Supported Argument Types

| Type           | Description                 |
| -------------- | --------------------------- |
| `string`       | Null-terminated C string    |
| `int32`        | 32-bit signed integer       |
| `uint32`       | 32-bit unsigned integer     |
| `int64`        | 64-bit signed integer       |
| `pointer`      | Memory address              |
| `bytes`        | Raw bytes (requires length) |
| `bool`         | Boolean value               |
| `double`       | 64-bit floating point       |
| `CFData`       | iOS CFData object           |
| `CFDictionary` | iOS CFDictionary object     |

### Buffer Arguments

#### Fixed Length

```yaml
- module: libcrypto.so
  symbol: EVP_EncryptInit_ex
  args:
    - name: key
      type: bytes
      length: 32
```

#### Dynamic Length

```yaml
- module: libc.so
  symbol: read
  args:
    - name: buf
      type: bytes
      lengthInArg: 2  # Length is in argument at index 2
    - name: count
      type: uint32
```

### Argument Direction

```yaml
args:
  - name: output_buffer
    type: bytes
    length: 256
    direction: out  # 'in' (default) or 'out'
```

### Capturing Return Values

```yaml
args:
  - name: result
    type: int32
    retValue: true
```

## Objective-C Hook Configuration

### Basic Syntax

```yaml
- objClass: <ClassName>
  symbol: <method_selector>
  args:
    - name: <arg_name>
      type: <arg_type>
```

### Method Selectors

| Method Type     | Selector Format           |
| --------------- | ------------------------- |
| Instance method | `- methodName:withParam:` |
| Class method    | `+ methodName:withParam:` |
| No parameters   | `- methodName`            |

### Example

```yaml
- objClass: NSUserDefaults
  symbol: "- setObject:forKey:"
  args:
    - name: value
      type: pointer
    - name: key
      type: string
```

## Swift Hook Configuration

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
```
