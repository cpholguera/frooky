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
javaClass: <class>                # Fully qualified Java class name
methods:                          # List of Java methods to be hooked
  - <method>
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
javaClass: <class>                # Fully qualified Java class name 
methods:
  - name: <method_name>           # Name of the Java method
    types:                        # List of types which describe the overload
      - <type>       
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

| Kind of Type      | Java Type Descriptor                                                                          | JVM Type Descriptor                                          | Frida / frooky Type Descriptor                                                                       |
|-------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| Primitive         | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void`  | `Z`<br>`B`<br>`C`<br>`S`<br>`I`<br>`J`<br>`F`<br>`D`<br>`V`  | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void`         |
| Primitive Array   | `boolean[]`<br>`byte[]`<br>...                                                                | `[Z`<br>`[B`<br>...                                          | `[Z`<br>`[B`<br>...                                                                                  |
| Reference         | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                              | `Ljava/lang/Object;`<br>`Lorg/owasp/MyClass;`<br>...         | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                                     |
| Reference Array   | `Object[]`<br>`MyClass[]`<br>...                                                              | `[Ljava/lang/Object;`<br>`[Lorg/owasp/MyClass;`<br>...       | `[Ljava.lang.Object`<br>`[Lorg.owasp.MyClass`<br>...                                                 |
| Multi-Dimensional | `int[][]`<br>`String[][]`<br>...                                                              | `[[I`<br>`[[Ljava/lang/String;`<br>...                       | `[[int`<br>`[[Ljava.lang.String`<br>...                                                              |

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
objClass: <class>                 # Fully qualified Objective-C class name
methods:                          # List of Objective-C methods to be hooked
  - <method>
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
objClass: <class>                 # Fully qualified Objective-C class name
methods:                       
  - name: <method_name>           # Name of the Objective-C method to be hooked
    types:                        # List of types which describe the positional arguments
      - <type>   
    ret: <type>                   # Describes the return type
```

> [!NOTE]
>
> **Example:**
>
> ```yaml
> objClass: NSUrl
> methods:
>   - name: "+ fileURLWithFileSystemRepresentation"
>     types:
>       - - name: path
>           type: (const char *)
>       - - name: isDir
>           type: (BOOL)
>       - - name: baseURL
>           type: (NSURL *)
>     ret: (NSURL *)
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
> Libraries, plugins or frameworks however, must keep symbols for the public API. To find symbols, use tools like `nm`, `objdump`, `radare2` or `ghidra` to extract all symbols in a binary executable.
>

### Basic Syntax

The minimum necessary properties are `module` and `symbols`:

```yaml
module: <module>                  # Name of the module the target functions are located
functions:                        # List of of functions to be hooked
  - <function>
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
module: <class>                   # Fully qualified Objective-C class name
functions:                       
  - symbol: <symbol_name>         
    types:                        # List of types which describe the positional arguments
      - <type>   
    ret: <type>                   # Describes the return type
```

> [!NOTE]
>
> **Example:**
>
> ```yaml
> module: libssl.so
> functions:
>   - symbol: OSSL_CMP_validate_cert_path
>     types:
>       - - name: ctx
>           type: const OSSL_CMP_CTX *
>       - - name: trusted_store
>           type: X509_STORE *
>       - - name: cert
>           type: X509 *
>     ret: int
> ```
>
> Frooky will try to decode the arguments and the return value based the type. This `<hook_configuration>` will hook the function `OSSL_CMP_validate_cert_path` from the [OpenSSL Library](https://docs.openssl.org/master/man3/OSSL_CMP_validate_msg/).

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

## Data Decoders

Objective-C and native hooks.

> [!IMPORTANT]
> At the moment, frooky provides decoders for simple types. It may therefor be, that the data is not decoded in depth.
>
> An example:
>
> ```yaml
> - objClass: LAPublicKey
>   methods:
>   - name: "- decrypt"
>     types:
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
