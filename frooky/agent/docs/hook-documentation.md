# frooky Hook Documentation

A frooky hook configuration describes how to hook a Java, Swift, Objective-C or native process.

This documentation describes the structure of a hook file and provides examples for the various cases.

- [frooky Hook Documentation](#frooky-hook-documentation)
- [frooky Configuration](#frooky-configuration)
- [Basic Hook Configuration](#basic-hook-configuration)
  - [Hook Types](#hook-types)
  - [Properties for All Type of Hooks](#properties-for-all-type-of-hooks)
- [Terminology, and Declaration Overview](#terminology-and-declaration-overview)
  - [Shared Declaration](#shared-declaration)
  - [`JavaHook` Declaration](#javahook-declaration)
  - [`ObjcHook` Declaration](#objchook-declaration)
  - [`NativeHook` Declaration](#nativehook-declaration)
  - [`SwiftHook` Declaration](#swifthook-declaration)
- [`JavaHook` Usage and Examples](#javahook-usage-and-examples)
  - [Basic Syntax](#basic-syntax)
  - [Method Overloads](#method-overloads)
  - [Type Descriptors](#type-descriptors)
- [`ObjcHook` Usage and Examples](#objchook-usage-and-examples)
  - [Basic Syntax](#basic-syntax-1)
  - [Parameter and Return Types](#parameter-and-return-types)
- [`NativeHook` Usage and Examples](#nativehook-usage-and-examples)
  - [Basic Syntax](#basic-syntax-2)
  - [Parameter and Return Types](#parameter-and-return-types-1)
- [`SwiftHook` Usage and Examples](#swifthook-usage-and-examples)
  - [Basic Syntax](#basic-syntax-3)
- [Advanced Features](#advanced-features)
  - [Time of Decoding](#time-of-decoding)
  - [Decoders with Parameters](#decoders-with-parameters)
  - [Custom Decoders](#custom-decoders)
  - [Event Filters](#event-filters)

  
For each of the feature described here, there are [YAML](../docs/examples/yaml/) and [TypeScript](../docs/examples/typeScript/) examples available.

# frooky Configuration

A frooky configuration contains optional metadata about the hook collection, and a set of `<hook_configuration>`.

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

> [!IMPORTANT]
> A single hook configuration file must target only one platform (Android or iOS). Mixing platforms in the same file will cause validation errors.

---------------------------

# Basic Hook Configuration

A `<hook_configuration>` consists of one or more of the following hook types:

## Hook Types

What kind of a type the `<hook_configuration>` is, is determined by a unique property.

frooky supports four types of hooks:

| Hook Type        | Platform    | Description                                 |
| ---------------- | ----------- | ------------------------------------------- |
| `JavaHook`       | Android     | Hook for Java/Kotlin methods                |
| `ObjectiveCHook` | iOS         | Hook for Objective-C methods                |
| `NativeHook`     | Android/iOS | Hook for native functions (C/C++/Rust etc.) |
| `SwiftHook`      | iOS         | Hook for Swift methods                      |

> [!IMPORTANT]
> When loading a `<hook_configuration>`, frooky will validate it against a JSON schema in order to detect invalid configuration. This makes sure, that the `<hook_configuration>` does not contain hooks for different platforms for example.

## Properties for All Type of Hooks

There are differences between Android, iOS or native hooks. Nevertheless, they share a few common properties.

The following properties can be used for all types:

| Property           | Type     | Description                                                |
| ------------------ | -------- | ---------------------------------------------------------- |
| `module`           | string   | Library/framework name. Mandatory for `NativeHook`.        |
| `stackTraceLimit`  | number   | Maximum stack frames to capture (default: 10)              |
| `stackTraceFilter` | string[] | Regex patterns to filter stack traces (see examples below) |
| `debug`            | boolean  | Enable verbose logging                                     |

# Terminology, and Declaration Overview

frooky can be used to declare hooks for different targets and programming languages. In order to avoid confusion, we list the most important terminology here:

1. **Method**  
  A function associated with a class or object.

1. **Function**  
  A native function without an associated class or object.

1. **Symbol**  
  A unique identifier for a native function in a compiled binary.

1. **Type, Function and Method Descriptors**  
   String representations describing types, functions, or methods according to platform-specific conventions: [Android](https://docs.oracle.com/en/java/javase/25/docs/specs/jni/types.html), [iOS](https://developer.apple.com/documentation/objectivec?language=objc) and [Native](https://en.cppreference.com/w/c/language/declarations.html)

1. **Parameter Declaration**  
  A combination of type descriptor and optional parameter name used in method and function declarations.

1. **Overloading**  
  In Java/Kotlin methods can be overloaded. An overload of a method has the same name, but a different parameter list. The return type can be different, but we do not care about that in a `<hook_configuration>`, since frooky can lookup the type at runtime.

## Shared Declaration

These declarations are used for more than only one types of hooks.

```yaml
<parameter_declaration>:
  type: <string>                       # Type notation according to platform standard
  name: <string>                       # Optional: Name of the parameter
  decodeAt: enter|exit|both            # Optional: When to decode the parameter. Default: enter
  decoder: <string>|autoSelect         # Optional: Custom decoder name. Default: autoSelect
```

> [!NOTE]
> **Built-in Decoders:**
>
> When `decoder: autoSelect` is used, frooky automatically selects a decoder based on the type:
>
> - Primitive types: `IntDecoder`, `BooleanDecoder`, `FloatDecoder`, etc.
> - Common types: `StringDecoder`, `ByteArrayDecoder`, `UrlDecoder`, etc.
> - Complex types: `JsonDecoder`, `XmlDecoder`, etc.
>
> Custom decoders can be specified by name (see [Custom Decoder](#custom-decoder) section).

## `JavaHook` Declaration

```yaml
javaClass: <string>                    # Fully qualified Java class name
methods:                               # List of Java methods to hook
  - <java_method_declaration>
```

```yaml
<java_method_declaration>:
  name: <string>                       # Name of the Java method
  overloads:                           # Optional: List of explicit method overloads
    - <overloads_declaration>
```

```yaml
<overloads_declaration>:
  parameters:                          # Parameter list of the overloaded method
    - <parameter_declaration>
```

## `ObjcHook` Declaration

```yaml
objcClass: <string>                     # Fully qualified Objective-C class name
methods:                               # List of Objective-C method declarations to be hooked
  - <objc_method_declaration>
```

```yaml
<objc_method_declaration>:
  name: <string>                       # Name of the Objective-C method (include - or + prefix)
  returnType: <string>                 # Optional: Return type of the Objective-C method
  parameters:                          # Optional: Parameter list of the Objective-C method
    - <parameter_declaration>
```

## `NativeHook` Declaration

```yaml
module: <string>                       # Fully qualified module name (mandatory)
functions:                             # List of native symbol declarations to be hooked
  - <native_function_declaration>
```

```yaml
<native_function_declaration>:
  symbol: <string>                     # Native symbol as string
  returnType: <string>                 # Optional: Return type of the function
  parameters:                          # Optional: Parameter list of the function
    - <parameter_declaration>
```

## `SwiftHook` Declaration

```yaml
methods:                               # List of mangled Swift symbols
  - <string> 
```

> [!NOTE]
> At the moment, frooky can only hook Swift methods based on their mangled symbol. The symbol contains all information required and is therefore sufficient. For more information about Swift go to [`SwiftHook` Usage and Examples](#swifthook-usage-and-examples).

---------------------------

# `JavaHook` Usage and Examples

## Basic Syntax

The minimum necessary properties are `javaClass` and `methods`:

```yaml
javaClass: <string>                    # Fully qualified Java class name
methods:                               # List of Java methods to hook
  - <java_method_declaration>
```

For this case *all* overloads of the specified methods from the class will be hooked.

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
> - **Wildcards**: `org.owasp.*.HttpClient` (per package level)
> - **Nested classes**: Use `$` separator (e.g., `Outer$Inner`)

> [!TIP]
> `$init` is the name of the constructor of a class.

## Method Overloads

If you only want to hook a certain overload, specify it by adding one or more `overload`:

```yaml
javaClass: <string>                    # Fully qualified Java class name
methods:                               # List of Java methods to hook
  - name: <string>                     # Name of the Java method
    overloads:                         # List of overloaded methods 
      - parameters:                    # List of parameter declarations for one overload
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
>
> This will *only* hook the following methods:
>
> ```kotlin
> Intent.putExtra(name: String!, value: String?): Intent
> Intent.putExtra(name: String!, value: BooleanArray?): Intent
> ```

## Type Descriptors

Frida, and therefore frooky, uses custom type descriptors which are based on the internal [JVM field type descriptor](https://docs.oracle.com/javase/specs/jvms/se19/html/jvms-4.html#jvms-4.3.2).

The following table shows the different kinds of types and their representation in Java, the JVM and Frida:

| Kind of Type      | Java Type Descriptor                                                                         | JVM Type Descriptor                                         | Frida / frooky Type Descriptor                                                               |
| ----------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Primitive         | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void` | `Z`<br>`B`<br>`C`<br>`S`<br>`I`<br>`J`<br>`F`<br>`D`<br>`V` | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void` |
| Primitive Array   | `boolean[]`<br>`byte[]`<br>...                                                               | `[Z`<br>`[B`<br>...                                         | `[Z`<br>`[B`<br>...                                                                          |
| Reference         | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                             | `Ljava/lang/Object;`<br>`Lorg/owasp/MyClass;`<br>...        | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                             |
| Reference Array   | `Object[]`<br>`MyClass[]`<br>...                                                             | `[Ljava/lang/Object;`<br>`[Lorg/owasp/MyClass;`<br>...      | `[Ljava.lang.Object`<br>`[Lorg.owasp.MyClass`<br>...                                         |
| Multi-Dimensional | `int[][]`<br>`String[][]`<br>...                                                             | `[[I`<br>`[[Ljava/lang/String;`<br>...                      | `[[int`<br>`[[Ljava.lang.String`<br>...                                                      |

> [!NOTE]
> Frida uses a hybrid notation that combines JVM-style array prefixes (`[`) with Java-style class names (dot-separated instead of slash-separated, without the `L` prefix and `;` suffix).

---------------------------

# `ObjcHook` Usage and Examples

frooky can hook Objective-C instance and class methods.

> [!TIP]
>
> Use the following syntax to hook the two different kinds of Objective-C methods:
>
> - **Instance methods**: `- biometryType`
> - **Class methods**: `+ removeProperties`
>

## Basic Syntax

The minimum necessary properties are `objcClass` and `methods`:

```yaml
objcClass: <string>                     # Fully qualified Objective-C class name
methods:                               # List of Objective-C method declarations to be hooked
  - <objc_method_declaration>
```

> [!NOTE]
> **Example:**
>
> ```yaml
> objcClass: LAContext
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

## Parameter and Return Types

When a method accepts parameters or returns a value, frooky needs to know how to decode them.

This is done by declaring the types in each `<method>`. The syntax is the same as used in the [official documentation](https://developer.apple.com/documentation?language=objc).

```yaml
objcClass: <string>                     # Fully qualified Objective-C class name
methods:                       
  - name: <string>                     # Name of the Objective-C method (include - or + prefix)
    returnType: <string>               # Return type of the Objective-C method
    parameters:                        # Parameter list of the Objective-C method
      - <parameter_declaration>
```

> [!NOTE]
>
> **Example:**
>
> ```yaml
> objcClass: NSURL
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
> frooky will try to decode the arguments and the return value based on the type. This `<hook_configuration>` will hook the following [Objective-C class method](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):
>
> ```objectivec
> + (NSURL *) fileURLWithFileSystemRepresentation:(const char *) path 
>                                     isDirectory:(BOOL) isDir 
>                                   relativeToURL:(NSURL *) baseURL;
> ```

# `NativeHook` Usage and Examples

> [!IMPORTANT]
> In order to hook native functions, symbols must not be stripped. However, this is done by default for release builds on both [Android](https://developer.android.com/build/include-native-symbols) and [iOS](https://developer.apple.com/documentation/xcode/build-settings-reference#Symbols-Hidden-by-Default).
>

> [!TIP]
> Libraries, plugins or frameworks however, must keep symbols for the public API. To find symbols, use tools like `nm`, `objdump`, `radare2` or `ghidra` to extract all symbols in a binary executable.
>

## Basic Syntax

The minimum necessary properties are `module` and `functions`:

```yaml
module: <string>                       # Fully qualified module name (mandatory)
functions:                             # List of native symbol declarations to be hooked
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
> frooky will capture when these functions are called and generate events. Since the functions take no arguments and return no value, the events will only contain timing and call stack information.

## Parameter and Return Types

When a method accepts parameters or returns a value, frooky needs to know how to decode them.

This is done by declaring the types in each `<function>`. The syntax is the same as [C function declarations](https://en.cppreference.com/w/c/language/function_declaration.html).

```yaml
module: <string>                       # Fully qualified module name (mandatory)
functions:                             # List of native symbol declarations to be hooked
  - symbol: <string>                   # Native symbol as string
    returnType: <string>               # Optional: Return type of the function
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
> frooky will try to decode the arguments and the return value based on the parameter type.
>
> This `<hook_configuration>` will hook the following function from the [OpenSSL Library](https://docs.openssl.org/master/man3/OSSL_CMP_validate_msg/):
>
> ```c
> int OSSL_CMP_validate_cert_path(const OSSL_CMP_CTX *ctx,
>                                X509_STORE *trusted_store, X509 *cert);
> ```

# `SwiftHook` Usage and Examples

> [!IMPORTANT]
> At the moment, frooky only supports `SwiftHook` if the mangled symbols have not been stripped. These are required to lookup the location of the method during runtime. Usually, production builds are stripped of them.
>
> At the moment, frooky does not support other means of Swift function hooking, because they require manual reverse engineering, which is not the focus of frooky at this time.
>

## Basic Syntax

The minimum necessary property for a `SwiftHook` is `methods`:

```yaml
methods:                               # List of mangled Swift symbols
  - <string>
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

> [!TIP]
> To find mangled Swift symbols in your binary use tools like `nm`, `objdump` or `ghidra`.
>
> After you found a symbol, demangle it using `SwiftDemangle` to verify it's the correct method, then use the mangled version in your hook configuration.

# Advanced Features

The previous chapters described how basic method and function hooking works. However, some use cases require more advanced configuration. These are discussed in this chapter.

## Time of Decoding

By default, arguments are decoded before the original code is called (`enter`), and the return value after (`exit`).

However, data structures are often passed by reference. The function then changes data in the reference directly and returns a status code. If we decode them before the method or function is run, we are not able to access the data we want.

**Default decoding at method entry on Android:**

```yaml
javaClass: javax.crypto.Cipher 
methods:
  - name: doFinal
    overloads:
      - parameters:
        - type: "[B"
          name: output
        - type: int
          name: outputOffset
```

This method decrypts data from the current instance and writes it into the byte array `output`. The return value is an `int` with the number of bytes written into `output`. If we decode the `output` at the beginning, we won't find any decrypted data yet.

If we want to decode the argument at a different time, we need to specify that using the `decodeAt` property of the `<parameter_declaration>`:

**Decoding at method exit on Android:**

```yaml
javaClass: javax.crypto.Cipher 
methods:
  - name: doFinal
    overloads:
      - parameters:
        - type: "[B"
          name: output
          decodeAt: exit
        - type: int
          name: outputOffset
 ```

Now, `output` is decoded before the method exits, capturing the decrypted data.

> [!TIP]
> Use `decodeAt: both` to capture the value at both entry and exit, useful for comparing before/after states.

## Decoders with Parameters

In native functions, primitive arrays are passed by reference. In some cases, the length is determined by a conventional terminating character, such as `\n` in a string. For generic byte array however, the length must be explicitly stated.

Method and functions therefore declare parameters which are used to determine the length of another parameter.

> [!NOTE]
> **Example:**
>
> ```c
> int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
>                      int *outl, const unsigned char *in, int inl);
> ```
>
> This function encrypts `inl` bytes from the buffer `in` and writes the encrypted version to `out`. Depending on the type of encryption algorithm used, it is unclear how many bytes will be written at the time the function is called. The actual number of bytes written, is placed in  `outl`.

Hence, the a native array decoder must be parameterized. You can pass any argument from the parameter list to the decoder using YAML anchors (`&`) and aliases (`*`):

```yaml
module: libssl.so
functions:
  - symbol: EVP_EncryptUpdate
    returnType: int
    parameters:
      - type: EVP_CIPHER_CTX *
        name: ctx
      - type: unsigned char *
        name: out
        decoderArguments:
          - *outl                      # Resolves to "outl"
      - type: int *
        name: &outl outl               # Creates an anchor to "outl"
      - type: const unsigned char *
        name: in
        decoderArguments:
          - *inl                       # Resolves to "inl"
      - type: int
        name: &inl inl                 # Creates an anchor to "inl"
```

Now, the decoder for the type `unsigned char *` is able to decode the array with a length of `int * outl` bytes, and the value from the parameter `int intl`  is passed to the  decoder for the type `const unsigned char *`.

## Custom Decoders

frooky provides decoders for primitive types and common complex types. By default, frooky chooses the decoder at runtime based on the type.

For example, an `int` will always be decoded as a number and if there is no decoder available for a given type, frooky will use a fallback decoder.

For some cases you want to manually bypass the automatic decoder matching. Two examples:

**Example 1: Decode an Integer as Flags**

```yaml
javaClass: android.content.Intent
methods:
  - name: setFlags
    overloads:
      - parameters:
        - type: int
          name: flags
          decoder: IntentFlagsDecoder
 ```

The parameter `flags` is a bitwise OR combination of [37 integers](https://developer.android.com/reference/kotlin/android/content/Intent#flags), each meaning something different. If you want to decode the flags on the device, you must provide a custom decoder which takes each flag and does a bitwise AND operation on the `flags` Integer.

If the result matches the value of the flag, it is set. This is a more stable way of decoding the flags compared to doing that on the host, as the flags may not be the same as on the actual device.

**Example 2: Handle Asynchronous Callback**

```yaml
objcClass: LAPrivateKey
methods:
  - name: "- decryptData"
    parameters:
      - type: (NSData *)
        name: data
      - type: (SecKeyAlgorithm)
        name: algorithm
      - type: (void (^)(NSData *, NSError *))
        name: handler
```
>
This `<hook_configuration>` hooks the following method:
>
```objectivec
- (void) decryptData:(NSData *) data 
     secKeyAlgorithm:(SecKeyAlgorithm) algorithm 
          completion:(void (^)(NSData *, NSError *)) handler;
```

It decrypts the data and invokes the handler upon completion. The method would for example be called like that:

```objectivec
[self decryptData:myData 
 secKeyAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256 
       completion:^(NSData *result, NSError *error) {
          // handle result with the decrypted data
      }];
```

To access the decrypted data, we must hook the handler implementation itself, as we need to intercept its first argument `(NSData *, NSError *)` when the method calls the handler after decryption finishes. For that we can write a custom decoder, let's call it `LaPlaintextDecoder`, and overwrite the default decoder for the `handler` argument:

```yaml
objcClass: LAPrivateKey
methods:
  - name: "- decryptData"
    parameters:
      - type: (NSData *)
        name: data
      - type: (SecKeyAlgorithm)
        name: algorithm
      - type: (void (^)(NSData *, NSError *))
        name: handler
        decoder: LaPlaintextDecoder
```

The decoder must:

1. Run at `enter` (default)
2. Create a new hook for the `handler` block
3. Intercept the callback when it's invoked

Once the handler is called by the decryption method, the hook intercepts the first parameter containing the decrypted plaintext as `NSData *`.

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
