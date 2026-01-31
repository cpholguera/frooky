# Frooky Hook Documentation

## Hook Types

Frooky supports four types of hooks:

| Hook Type | Platform | Description |
|-----------|----------|-------------|
| `JavaHook` | Android | Hook Java/Kotlin methods |
| `NativeHook` | Android/iOS | Hook native C/C++ functions |
| `ObjectiveCHook` | iOS | Hook Objective-C methods |
| `SwiftHook` | iOS | Hook Swift methods |

## YAML Configuration

### Basic Structure

```yaml
category: <MAS_CATEGORY>  # Optional: STORAGE, CRYPTO, AUTH, NETWORK, etc.

hooks:
  - <hook_configuration>
```

### Common Properties

All hook types support these base properties:

| Property | Type | Description |
|----------|------|-------------|
| `module` | string | Library/framework name (optional) |
| `stackTraceLimit` | number | Maximum stack frames to capture |
| `stackTraceFilter` | string[] | Regex patterns to filter stack traces |
| `debug` | boolean | Enable verbose logging |

## Java Hooks

### Basic Syntax

```yaml
- javaClass: <fully.qualified.ClassName>
  methods:
    - name: <methodName>
```

### Class Name Patterns

- **Exact match**: `org.owasp.mastestapp.MainActivity`
- **Wildcards**: `org.owasp.*.Http$Client` (per package level)
- **Nested classes**: Use `$` separator (e.g., `Outer$Inner`)

### Method Overloads

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
```

### Java Type Notation Is Frida Notation

Examples:

| Type | Notation |
|------|----------|
| Primitive int | `int` |
| String | `java.lang.String` |
| Byte array | `[B` |
| String array | `[Ljava.lang.String;` |
| Custom class | `com.example.MyClass` |

## Native Hooks

### Basic Syntax

```yaml
- module: <library.so>
  symbol: <function_name>
  args:
    - name: <arg_name>
      type: <arg_type>
```

### Supported Argument Types

| Type | Description |
|------|-------------|
| `string` | Null-terminated C string |
| `int32` | 32-bit signed integer |
| `uint32` | 32-bit unsigned integer |
| `int64` | 64-bit signed integer |
| `pointer` | Memory address |
| `bytes` | Raw bytes (requires length) |
| `bool` | Boolean value |
| `double` | 64-bit floating point |
| `CFData` | iOS CFData object |
| `CFDictionary` | iOS CFDictionary object |

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

## Objective-C Hooks

### Basic Syntax

```yaml
- objClass: <ClassName>
  symbol: <method_selector>
  args:
    - name: <arg_name>
      type: <arg_type>
```

### Method Selectors

| Method Type | Selector Format |
|-------------|-----------------|
| Instance method | `- methodName:withParam:` |
| Class method | `+ methodName:withParam:` |
| No parameters | `- methodName` |

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

## Swift Hooks

### Basic Syntax

```yaml
- swiftClass: <Module.ClassName>
  symbol: <mangled_symbol>
  args:
    - name: <arg_name>
      type: <arg_type>
```

### Finding Mangled Symbols

Use `frida-trace` or `nm` to find mangled Swift symbols:

```bash
nm -gU YourApp | grep Swift
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
    stackTraceFilter:
      - "^libsystem_"
      - "^Foundation"
```

## Advanced Features

### Stack Trace Filtering

Filter out noisy framework calls:

```yaml
- javaClass: com.example.MyClass
  methods:
    - name: sensitiveMethod
  stackTraceLimit: 20
  stackTraceFilter:
    - "^java\\."
    - "^android\\."
    - "^com\\.android\\."
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
      retDecoder: IntentFlagsDecoder  # Custom return value decoder
```

Available decoders are located in `./android/decoders`.

## OWASP MAS Categories

Frooky supports categorizing hooks by OWASP Mobile Application Security (MAS) testing domains:

| Category | Description |
|----------|-------------|
| `STORAGE` | Data storage and privacy |
| `CRYPTO` | Cryptographic operations |
| `AUTH` | Authentication mechanisms |
| `NETWORK` | Network communication |
| `PLATFORM` | Platform interaction |
| `CODE` | Code quality and build |
| `RESILIENCE` | Resilience against reverse engineering |
| `PRIVACY` | Privacy controls |

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

Reduce noise in logs:

```yaml
stackTraceFilter:
  - "^java\\."
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

### 5. Document Custom Decoders

```yaml
- javaClass: android.content.Intent
  methods:
    - name: setFlags
      overloads:
        - args:
            - name: int
              decoder: IntentFlagsDecoder  # Decodes Intent flags as human-readable strings
```
