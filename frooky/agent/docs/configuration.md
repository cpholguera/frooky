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
> WebView(context: Context)
> WebView(context: Context, attrs: AttributeSet?)
> WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int)
> WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int, privateBrowsing: Boolean)
> WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int, defStyleRes: Int)
> WebView.loadUrl(url: String)
> WebView.loadUrl(url: String, additionalHttpHeaders: MutableMap<String!, String!>)
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
    types:                        # List of types which describe the overload
      - <types>       
```

> [!NOTE]
> **Example:**
>
> ```yaml
> javaClass: android.content.Intent
> methods:
>   - name: putExtra
>     types:
>       - - name: name
>           type: java.lang.String
>         - name: value
>           type: java.lang.String
>       - - name: name
>           type: java.lang.String
>         - name: value
>           type: "[Z"
>  ```
>
> This will *only* hook the following methods:
>
> ```kotlin
> Intent.putExtra(name: String!, value: String?): Intent
> Intent.putExtra(name: String!, value: BooleanArray?): Intent
> ```

### Type Descriptors

Frida, and therefore frooky, uses a custom type descriptors which is based on the internal [JVM field type descriptor](https://docs.oracle.com/javase/specs/jvms/se19/html/jvms-4.html#jvms-4.3.2).

The following table shows the different kinds of types and their representation in Java, the JVM and Frida:

| Kind of Type      | Java Type Descriptor                                                                          | JVM Type Descriptor                                          | Frida Type Descriptor                                                                                |
|-------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| Primitive         | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void`  | `Z`<br>`B`<br>`C`<br>`S`<br>`I`<br>`J`<br>`F`<br>`D`<br>`V`  | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void`         |
| Primitive Array   | `boolean[]`<br>`byte[]`<br>...                                                                | `[Z`<br>`[B`<br>...                                          | `[Z`<br>`[B`<br>...                                                                                  |
| Reference         | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                              | `Ljava/lang/Object;`<br>`Lorg/owasp/MyClass;`<br>...         | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                                     |
| Reference Array   | `Object[]`<br>`MyClass[]`<br>...                                                              | `[Ljava/lang/Object;`<br>`[Lorg/owasp/MyClass;`<br>...       | `[Ljava.lang.Object`<br>`[Lorg.owasp.MyClass`<br>...                                                 |
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
