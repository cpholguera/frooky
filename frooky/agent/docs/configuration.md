# Frooky Hook Documentation

A frooky hook configuration describes how to hook a Java, Swift, Objective-C or native process.

This documentation describes the structure of a hook file and provides examples for the various cases.

- [Frooky Hook Documentation](#frooky-hook-documentation)
  - [Frooky Configuration](#frooky-configuration)
  - [Basic Hook Configuration](#basic-hook-configuration)
    - [Hook Types](#hook-types)
    - [Properties for All Type of Hooks](#properties-for-all-type-of-hooks)
  - [Terminology, and Declaration Overview](#terminology-and-declaration-overview)
    - [Shared Declaration](#shared-declaration)
    - [`JavaHook` Declaration](#javahook-declaration)
    - [`ObjectiveCHook` Declaration](#objectivechook-declaration)
    - [`NativeHook` Declaration](#nativehook-declaration)
    - [`SwiftHook` Declaration](#swifthook-declaration)
  - [Java Hook Configuration](#java-hook-configuration)
    - [Basic Syntax](#basic-syntax)
    - [Method Overloads](#method-overloads)
    - [Type Descriptors](#type-descriptors)
  - [Objective-C Hook Configuration](#objective-c-hook-configuration)
    - [Basic Syntax](#basic-syntax-1)
    - [Argument and Return Types](#argument-and-return-types)
  - [Native Hook Configuration](#native-hook-configuration)
    - [Basic Syntax](#basic-syntax-2)
    - [Argument and Return Types](#argument-and-return-types-1)
  - [Swift Hook Configuration](#swift-hook-configuration)
    - [Basic Syntax](#basic-syntax-3)
  - [Advanced Features](#advanced-features)
    - [Time of Decoding](#time-of-decoding)

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

| Hook Type        | Platform    | Description                                 |
| ---------------- | ----------- | ------------------------------------------- |
| `JavaHook`       | Android     | Hook for Java/Kotlin methods                |
| `ObjectiveCHook` | iOS         | Hook for Objective-C methods                |
| `NativeHook`     | Android/iOS | Hook for native functions (C/C++/Rust etc.) |
| `SwiftHook`      | iOS         | Hook for Swift methods                      |

> [!IMPORTANT]
> When loading a `<hook_configuration>`, frooky will validate it against a JSON schema in order to detect invalid configuration. This makes sure, that the `<hook_configuration>` does not contain hooks for different platforms for example.

### Properties for All Type of Hooks

There are differences between Android, iOS or native hooks. Nevertheless, they share a few common properties.

The following properties can be used for all types:

| Property           | Type     | Description                                         |
| ------------------ | -------- | --------------------------------------------------- |
| `module`           | string   | Library/framework name. Mandatory for `NativeHook`. |
| `stackTraceLimit`  | number   | Maximum stack frames to capture                     |
| `stackTraceFilter` | string[] | Regex patterns to filter stack traces               |
| `debug`            | boolean  | Enable verbose logging                              |

## Terminology, and Declaration Overview

frooky can be used to declare hooks for different targets and programming languages. It is therefor important to be clear about the different conventions  and terminology. In order to avoid confusion, we therefore want to list the most important words with examples from the different platforms:


1. **Method**  
  A function associated with a class or object.

1. **Function**  
  A native function without an associated class or object.

1. **Symbol**  
  A unique identifier for a native function.

1. **Type Declaration**  
  Description of the type according to the platform specific references:

  [Android](https://docs.oracle.com/en/java/javase/25/docs/specs/jni/types.html), [iOS](https://developer.apple.com/documentation/objectivec?language=objc) and [Native](https://en.cppreference.com/w/c/language/declarations.html)

1. **Parameter List**  
  List of type declaration and their optional name.

1. **Overloading in Java**  
  In Java/Kotlin methods can be overloaded. A `<java_method_declaration>` is therefore structurally different than `objc_method_declaration` and `<native_function_declaration>`.


### Shared Declaration

These declarations are used for more than only one types of hooks.

```yaml
<parameter_declaration>:
  type: <String>                       # Type declaration according to platform standard
  name: <String>                       # Optional: Name of the parameter as string
  decodeAt: enter|exit|both            # Optional: Determines at what time the parameter's argument is decoded, Default: enter
  decoder: <String>|default            # Optional: Overwrites the default decoded based on the type. Default: default
```

### `JavaHook` Declaration

```yaml
javaClass: <String>                    # Fully qualified Java class name
methods:                               # List of Java methods to hook
  - <java_method_declaration>
```

```yaml
<java_method_declaration>:
  name: <String>                       # Name of the Java method
  overloads:                           # Optional: List of explicit method overloads
    - <overloads_declaration>
```

```yaml
<overloads_declaration>:
  parameters:                          # Parameter list of the overloaded method
    - <parameter_declaration>
```

### `ObjectiveCHook` Declaration

```yaml
objClass: <String>                     # Fully qualified Objective-C class name
methods:                               # List of Objective-C method declarations to be hooked
  - <objc_method_declaration>
```

```yaml
<objc_method_declaration>:
  name: <String>                       # Name of the Objective-C method
  returnType: <String>                 # Optional: Return type of the Objective-C method
  parameters:                          # Optional: Parameter list of the  Objective-C method
    - <parameter_declaration>
```

### `NativeHook` Declaration

```yaml
module: <String>                       # Fully qualified module name
functions:                             # List of native symbol declaration to be hooked
  - <native_function_declaration>
```

```yaml
<native_function_declaration>:
  symbol: <String>                     # Native symbol as string
  returnType: <String>                 # Optional: Return type of the function
  parameters:                          # Optional: Parameter list of the function
    - <parameter_declaration>
```

### `SwiftHook` Declaration

```yaml
methods:                               # List of mangled Swift symbols
  - <String> 
```

> [!NOTE]
> At the moment, frooky can only hook Swift methods based on their mangled symbol. The symbol contains all information required and is therefore sufficient. For more information about Swift go to [Swift Hook Configuration](#swift-hook-configuration)

---------------------------

## Java Hook Configuration

### Basic Syntax

The minimum necessary properties are `javaClass` and `methods`:

```yaml
javaClass: <String>                    # Fully qualified Java class name
methods:                               # List of Java methods to hook
  - <java_method_declaration>
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
> Use the following syntax for dynamic `<class>` lookup at runtime:
>
> - **Exact match**: `org.owasp.mastestapp.MainActivity`
> - **Wildcards**: `org.owasp.*.Http$Client` (per package level)
> - **Nested classes**: Use `$` separator (e.g., `Outer$Inner`)

> [!TIP]
> `$init` is the name of the constructor of a class.

### Method Overloads

If you only want to hook a certain overload, specify it by adding one or more `overload`:

```yaml
javaClass: <String>                    # Fully qualified Java class name
methods:                               # List of Java methods to hook
  - name: <String>                     # Name of the Java method
    overloads:                         # List of overloaded methods 
      - parameters:                    # List of parameter declarations for a one overload
        - <parameter_declaration>
```

> [!NOTE]
> **Example:**
>
> ```yaml
> javaClass: android.content.Intent
> methods:
>   - name: putExtra
>     overloads:
>       - parameters:
>         - type: java.lang.String
>           name: name
>         - type: java.lang.String
>           name: value
>       - parameters:
>         - type: java.lang.String
>           name: name
>         - type: "[Z"
>           name: value
>  ```
> This will *only* hook the following methods:
>
> ```kotlin
> Intent.putExtra(name: String!, value: String?): Intent
> Intent.putExtra(name: String!, value: BooleanArray?): Intent
> ```

### Type Descriptors

Frida, and therefore frooky, uses a custom type descriptors which is based on the internal [JVM field type descriptor](https://docs.oracle.com/javase/specs/jvms/se19/html/jvms-4.html#jvms-4.3.2).

The following table shows the different kinds of types and their representation in Java, the JVM and Frida:

| Kind of Type      | Java Type Descriptor                                                                         | JVM Type Descriptor                                         | Frida / frooky Type Descriptor                                                               |
| ----------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Primitive         | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void` | `Z`<br>`B`<br>`C`<br>`S`<br>`I`<br>`J`<br>`F`<br>`D`<br>`V` | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void` |
| Primitive Array   | `boolean[]`<br>`byte[]`<br>...                                                               | `[Z`<br>`[B`<br>...                                         | `[Z`<br>`[B`<br>...                                                                          |
| Reference         | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                             | `Ljava/lang/Object;`<br>`Lorg/owasp/MyClass;`<br>...        | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                             |
| Reference Array   | `Object[]`<br>`MyClass[]`<br>...                                                             | `[Ljava/lang/Object;`<br>`[Lorg/owasp/MyClass;`<br>...      | `[Ljava.lang.Object`<br>`[Lorg.owasp.MyClass`<br>...                                         |
| Multi-Dimensional | `int[][]`<br>`String[][]`<br>...                                                             | `[[I`<br>`[[Ljava/lang/String;`<br>...                      | `[[int`<br>`[[Ljava.lang.String`<br>...                                                      |

---------------------------

## Objective-C Hook Configuration

frooky can hook Objective-C instance and type methods.

> [!TIP]
>
> Use the following syntax to hook the two different kinds of Objective-C methods:
>
> - **Instance methods**: `- biometryType`
> - **Type methods**: `+ removeProperties`
>

### Basic Syntax

The minimum necessary properties are `objcClass` and `methods`:

```yaml
objClass: <String>                     # Fully qualified Objective-C class name
methods:                               # List of Objective-C method declarations to be hooked
  - <objc_method_declaration>
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
> This `<hook_configuration>` will hook the following [Objective-C instance method](https://developer.apple.com/documentation/localauthentication/lacontext/invalidate()?language=objc):
>
> ```objectivec
> - (void) invalidate;
> ```
>
> frooky will capture when this function is called and generate an event. Since the function takes no arguments and returns no value, the event will only contain timing and call stack information.
>

### Argument and Return Types

If a `<objc_method>` has a return value or method arguments, frooky needs to how to decode them.

This is done by declaring the types in each `<method>`. The syntax the same as used in the [official documentation](https://developer.apple.com/documentation?language=objc).

```yaml
objClass: <class>                      # Fully qualified Objective-C class name
methods:                       
  - name: <String>                     # Name of the Objective-C method
    returnType: <String>               # Return type of the Objective-C method
    parameters:                        # Parameter list of the  Objective-C method
      - <parameter_declaration>
```

> [!NOTE]
>
> **Example:**
>
> ```yaml
> objClass: NSUrl
> methods:
>   - name: "+ fileURLWithFileSystemRepresentation"
>     returnType: (NSURL *)
>     parameters:
>       - type: (const char *)
>         name: path
>       - type: (BOOL)
>         name: isDir
>       - type: (NSURL *)
>         name: baseURL
>  ```
>
> Frooky will try to decode the arguments and the return value based the type. This `<hook_configuration>` will hook the following [Objective-C type method](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):
>
> ```objectivec
> + (NSURL *) fileURLWithFileSystemRepresentation:(const char *) path 
>                                     isDirectory:(BOOL) isDir 
>                                   relativeToURL:(NSURL *) baseURL;
> ```

## Native Hook Configuration

> [!IMPORTANT]
> In oder to hook native functions, symbols must not be stripped. However, this is done by default for release builds on both [Android](https://developer.android.com/build/include-native-symbols) and [iOS](https://developer.apple.com/documentation/xcode/build-settings-reference#Symbols-Hidden-by-Default).
>

> [!TIP]
> Libraries, plugins or frameworks however, must keep symbols for the public API. To find symbols, use tools like `nm`, `objdump`, `radare2` or `ghidra` to extract all symbols in a binary executable.
>

### Basic Syntax

The minimum necessary properties are `module` and `functions`:

```yaml
module: <String>                       # Fully qualified module name
functions:                             # List of native symbol declaration to be hooked
  - <native_function_declaration>
```

> [!NOTE]
> **Example:**
>
> ```yaml
> module: libssl.so
> functions:
>  - symbol: ENGINE_load_builtin_engines
>  - symbol: ENGINE_cleanup
> ```
>
> This `<hook_configuration>` will hook the following two functions from the [OpenSSL Library](https://docs.openssl.org/master/man3/ENGINE_add):
>
> ```c
> void ENGINE_load_builtin_engines(void);
> void ENGINE_cleanup(void);
> ```
>
> frooky will capture when this function is called and generate an event. Since the function takes no arguments and returns no value, the event will only contain timing and call stack information.

### Argument and Return Types

If a `<function>` has a return value or method arguments, frooky needs to how to decode them.

This is done by declaring the types in each `<function>`. The syntax the same as [C function declarations](https://en.cppreference.com/w/c/language/function_declaration.html).

```yaml
module: <String>                       # Fully qualified module name
functions:                             # List of native symbol declaration to be hooked
  - symbol: <String>                   # Native symbol as string
    returnType: <String>               # Optional: Return type of the function
    parameters:                        # Optional: Parameter list of the function
      - <parameter_declaration>
```

> [!NOTE]
>
> **Example:**
>
> ```yaml
> module: libssl.so
> functions:
>   - symbol: OSSL_CMP_validate_cert_path
>     returnType: int
>     parameters:
>       - type: const OSSL_CMP_CTX *
>         name: ctx
>       - type: X509_STORE *
>         name: trusted_store
>       - type: X509 *
>         name: cert
> ```
>
> Frooky will try to decode the arguments and the return value based the type. 
> 
> This `<hook_configuration>` will hook the following function from the [OpenSSL Library](https://docs.openssl.org/master/man3/OSSL_CMP_validate_msg/):
>
> ```c
> int OSSL_CMP_validate_cert_path(const OSSL_CMP_CTX *ctx,
>                                X509_STORE *trusted_store, X509 *cert);
> ```

## Swift Hook Configuration

> [!IMPORTANT]
> At the moment, frooky only supports `SwiftHook` if the mangled symbols have not been stripped. These are required to lookup the location of the method during runtime. Usually, productive build are stripped of them.
>
> At them moment, frooky does not support other means of Swift function hooking, because they require manual reverse engineering, which is not the focus of frooky at the time.
>

### Basic Syntax

The minimum necessary properties for a `SwiftHook` is `methods`:

```yaml
methods:                               # List of mangled Swift symbol
  - <method>
```

> [!NOTE]
> **Example:**
>
> ```yaml
> methods: 
>   - "_$s5MyApp14NetworkManagerC11sendRequestyyF"
> ```
>
> This `<hook_configuration>` will hook the Swift method `MyApp.NetworkManager.sendRequest() -> ()`.

## Advanced Features

The previous Chapters described how basic method and function hooking. However, some use cases require more advanced configuration. These are discussed in this chapter.

### Time of Decoding

By default, arguments are decoded before the original code is called, and the return value after.

However, datastrucutres are often passed by reference. The function then changes data in the reference directly and returns a status code. If we decode them before the method or function is run, we are not able to access the data we want.

> [!NOTE]
> **Example on Android:**
>
> ```yaml
> javaClass: javax.crypto.Cipher 
> methods:
>   - name: doFinal
>     overloads:
>       - - name: output
>           type: "[B"
>         - name: outputOffset
>           type: int
>  ```
>
> This method decrypts data form the current instance and writes it into the byte array `output`. If we decode the array at the beginning, the data we might be interested in is not yet written.

If we want to decode the argument at at different time, we need to specify that using the `decodeAt` property of the `<parameter>`:


```yaml
 <class>                # Fully qualified Java class name 
name: <method_name>           # Name of the Java method
type:                    # List of types which describe the overloads
      - <type>       
```














`ObjectiveCHook` and `NativeHook` configurations have one 



> [!IMPORTANT]
> At the moment, frooky provides decoders for simple types. It may therefor be, that the data is not decoded in depth.
>
> An example:
>
> ```yaml
> - objClass: LAPublicKey
>   methods:
>   - name: "- decrypt"
>     args:
>       - - name: data
>           type: (NSData *)
>       - - name: algorithm
>           type: (SecKeyAlgorithm)
>       - - name: handler
>           type: (void (^)(NSData * , NSError * )
> ```
>
> This `<hook_configuration>` hooks the following method:
>
> ```objectivec
> - (void) decryptData:(NSData *) data 
>      secKeyAlgorithm:(SecKeyAlgorithm) algorithm 
>           completion:(void (^)(NSData * , NSError * )) handler;
> ```
>
> It decrypts the data and invokes the handler upon completion. The method would for example be called like that:
>
> ```objectivec
> [self decryptData:myData 
>  secKeyAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256 
>        completion:^(NSData *result, NSError *error) {
>           // handle result
>       }];
>
> ```
>
> To access the decrypted data, we must hook the handler implementation itself, as we need to intercept its first argument `(NSData * , NSError * )` when the method calls the handler after decryption finishes.
>
> At the moment, this feature is not yet implemented. You can find more on the topic of custom decoders in chapter [Custom Decoders](#custom-decoders).
>
