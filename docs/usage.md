# Usage

## Hook Files

Hook files use JSON format. When multiple hook files are provided, their `hooks` arrays are merged together.

### Basic Structure

```json
{
  "category": "STORAGE",
  "hooks": [
    {
      "class": "com.example.MyClass",
      "methods": ["method1", "method2"]
    }
  ]
}
```

### Java/Kotlin Hooks

#### Simple Method Hook

```json
{
  "class": "java.io.File",
  "method": "exists"
}
```

#### Multiple Methods

```json
{
  "class": "java.io.FileOutputStream",
  "methods": ["write", "close", "flush"]
}
```

#### Method Overloads

Specify exact method signatures using `overloads`:

```json
{
  "class": "java.io.FileOutputStream",
  "method": "write",
  "overloads": [
    { "args": ["[B"] },
    { "args": ["[B", "int", "int"] },
    { "args": ["int"] }
  ]
}
```

#### Stack Traces

Control stack trace depth with `maxFrames`:

```json
{
  "class": "javax.crypto.Cipher",
  "method": "doFinal",
  "maxFrames": 10
}
```

### Native Hooks

Native hooks intercept C/C++ functions. Set `native: true` and specify the symbol.

#### Basic Native Hook

```json
{
  "native": true,
  "symbol": "open",
  "module": "libc.so"
}
```

#### Argument Descriptors

Define how arguments should be captured:

```json
{
  "native": true,
  "symbol": "write",
  "module": "libc.so",
  "args": [
    { "name": "fd", "type": "int32" },
    { "name": "buf", "type": "bytes", "length": 256 },
    { "name": "count", "type": "int32" }
  ]
}
```

#### Dynamic Length from Another Argument

Use `lengthInArg` to read length from another argument:

```json
{
  "native": true,
  "symbol": "send",
  "module": "libc.so",
  "args": [
    { "name": "sockfd", "type": "int32" },
    { "name": "buf", "type": "bytes", "lengthInArg": 2 },
    { "name": "len", "type": "int32" },
    { "name": "flags", "type": "int32" }
  ]
}
```

#### Capture Return Values

Set `returnValue: true` on the last argument:

```json
{
  "native": true,
  "symbol": "read",
  "module": "libc.so",
  "args": [
    { "name": "fd", "type": "int32" },
    { "name": "buf", "type": "bytes", "lengthInArg": 2 },
    { "name": "count", "type": "int32" },
    { "name": "result", "type": "int32", "returnValue": true }
  ]
}
```

#### Outbound Parameters

Use `direction: "out"` for output parameters that should be read after the function returns:

```json
{
  "native": true,
  "symbol": "CCCrypt",
  "module": "libcommonCrypto.dylib",
  "args": [
    { "name": "op", "type": "int32" },
    { "name": "alg", "type": "int32" },
    { "name": "dataOut", "type": "bytes", "length": 256, "direction": "out" },
    { "name": "dataOutMoved", "type": "pointer", "direction": "out" }
  ]
}
```

#### Filter by Value

Only capture events when arguments match specific values:

```json
{
  "native": true,
  "symbol": "open",
  "module": "libc.so",
  "args": [
    { "name": "pathname", "type": "string", "filter": ["/data/", "/sdcard/"] }
  ]
}
```

#### Filter by Stack Trace

Only capture events when the call stack contains specific patterns:

```json
{
  "native": true,
  "symbol": "SSL_write",
  "module": "libssl.so",
  "filterEventsByStacktrace": ["com.example.network", "okhttp3"]
}
```

#### Debug Mode

Enable verbose logging for troubleshooting:

```json
{
  "native": true,
  "symbol": "problematic_function",
  "module": "libfoo.so",
  "debug": true
}
```

### Argument Types

| Type | Description |
|------|-------------|
| `string` | Null-terminated C string |
| `int32` | 32-bit signed integer |
| `uint32` | 32-bit unsigned integer |
| `int64` | 64-bit signed integer |
| `pointer` | Memory address |
| `bytes` | Raw bytes (requires `length` or `lengthInArg`) |
| `bool` | Boolean value |
| `double` | 64-bit floating point |
| `CFData` | iOS CFData object |
| `CFDictionary` | iOS CFDictionary object |

### iOS Objective-C Hooks

Hook Objective-C methods using `objClass` and `symbol`:

```json
{
  "native": true,
  "objClass": "NSURLSession",
  "symbol": "dataTaskWithRequest:completionHandler:"
}
```

## Output Format

Events are written to the output file in JSON Lines format (one JSON object per line, known as NDJSON). You can easily pretty-print it e.g. using `jq . output.json`.

First of all, a summary event is written when hooking is initialized, listing all resolved hooks. It includes:

- `type`: Indicates this is a summary event
- `hooks`: An array of all hooked methods with their classes and overloads
- `totalHooks`: Total number of hooks that were set up
- `errors`: Any errors encountered while setting up hooks
- `totalErrors`: Total number of errors encountered

After that, individual hook events are written each time a hooked method/function is called.

Example hook event (pretty-printed for clarity):

```json
{
    "id": "0117229c-b034-4676-ba33-075fc27922ba",
    "type": "hook",
    "category": "STORAGE",
    "time": "2026-01-18T16:17:25.470Z",
    "class": "android.app.SharedPreferencesImpl$EditorImpl",
    "method": "putString",
    "instanceId": 268282727,
    "stackTrace": [
        "android.app.SharedPreferencesImpl$EditorImpl.putString(Native Method)",
        "androidx.security.crypto.EncryptedSharedPreferences$Editor.putEncryptedObject(EncryptedSharedPreferences.java:389)",
        ...
    ],
    "inputParameters": [
        {
            "declaredType": "java.lang.String",
            "value": "AQMRC7OWD6/h1iJseuzJVrClpwKE8swB8gOrGnsdaN4="
        },
        {
            "declaredType": "java.lang.String",
            "value": "AX4R5MZu+J1p0U3hvKyuEnJDQopI+wupiSi8CAG8dzq0PU76NbbebjhqMtqCD7fFUy2SmmQuQVDlDrrj30d3GQes+PlD8HmRFszVTge039GQ"
        }
    ],
    "returnValue": [
        {
            "declaredType": "android.content.SharedPreferences$Editor",
            "value": "<instance: android.content.SharedPreferences$Editor, $className: android.app.SharedPreferencesImpl$EditorImpl>",
            "runtimeType": "android.app.SharedPreferencesImpl$EditorImpl",
            "instanceId": "268282727",
            "instanceToString": "android.app.SharedPreferencesImpl$EditorImpl@ffdab67"
        }
    ]
}
```

Explanation of fields:

- `id`: Unique identifier for the event (UUID)
- `type`: Type of event (e.g., "hook", "summary")
- `category`: Category specified in the hook file (e.g., "STORAGE", "CRYPTO")
- `time`: Timestamp of the event in ISO 8601 format
- `class`: Hooked class name
- `method`: Hooked method name
- `instanceId`: Unique identifier for the instance on which the method was called
- `stackTrace`: Captured stack trace leading to the method call
- `inputParameters`: Array of input parameters with their declared types and values
  - `declaredType`: The declared type of the parameter
  - `value`: The captured value of the parameter
- `returnValue`: Array of return values with their declared types and values
  - `declaredType`: The declared type of the return value
  - `value`: The captured value of the return value
  - `runtimeType`: The actual runtime type of the return value
  - `instanceId`: Unique identifier for the return value instance
  - `instanceToString`: String representation of the return value instance
