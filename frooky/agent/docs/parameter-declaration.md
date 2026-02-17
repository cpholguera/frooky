# Parameter Declaration

frooky needs to know a function or method's signature in order to hook it correctly. Part of this signature is the parameter list which is a set of types and names for the arguments passed to the function or method. This documentation explains how to declare parameters.

- [1. Unnamed Parameters](#1-unnamed-parameters)
  - [1.1. Unnamed Java Parameters](#11-unnamed-java-parameters)
  - [1.2. Unnamed Objective-C Parameters](#12-unnamed-objective-c-parameters)
  - [1.3. Unnamed Native Parameters](#13-unnamed-native-parameters)
- [2. Named Parameters](#2-named-parameters)
  - [2.1. Named Java Parameters](#21-named-java-parameters)
  - [2.2. Named Objective-C Parameters](#22-named-objective-c-parameters)
  - [2.3. Named Native Parameters](#23-named-native-parameters)
- [3. Decoders](#3-decoders)
  - [3.1. `decoder`-Option: Custom Decoder](#31-decoder-option-custom-decoder)
    - [Asynchronous Callback Decoders](#asynchronous-callback-decoders)
    - [3.1.1. Custom Decoder in Java](#311-custom-decoder-in-java)
    - [3.1.2. Custom Decoder in Objective-C](#312-custom-decoder-in-objective-c)
    - [3.1.3. Custom Decoder in Native](#313-custom-decoder-in-native)
  - [3.2. `decodeAt`-Option: Declare the Time of Decoding](#32-decodeat-option-declare-the-time-of-decoding)
    - [3.2.1. Explicit Time of Decoding in Java](#321-explicit-time-of-decoding-in-java)
    - [3.2.2. Explicit Time of Decoding in Objective-C](#322-explicit-time-of-decoding-in-objective-c)
    - [3.2.3. Explicit Time of Decoding in Native](#323-explicit-time-of-decoding-in-native)
  - [3.3. `decoderArgs`-Option: Pass Arguments to Decoder](#33-decoderargs-option-pass-arguments-to-decoder)
    - [3.3.1. Pass Arguments to Decoder in Java](#331-pass-arguments-to-decoder-in-java)
    - [3.3.2. Pass Arguments to Decoder in Objective-C](#332-pass-arguments-to-decoder-in-objective-c)
    - [3.3.3. Pass Arguments to Decoder in Native](#333-pass-arguments-to-decoder-in-native)

> [!TIP]
> Technically, the name of an argument is not required, but it is recommended declaring the name as well, as this makes a declaration easier to read and provides more context information in the output of frooky.

There are different accepted ways declaring a parameter. The following chapters explain them.

## 1. Unnamed Parameters

This is the most simple declaration, solely based on its type. frooky will try to decode the arguments based on the automatically selected decoder:

```yaml
params: [ <type> ]
```

### 1.1. Unnamed Java Parameters

```yaml
javaClass: android.webkit.WebView
methods:
  - name: $init
    overloads:
      - params: [ android.content.Context ]
      - params: [ android.content.Context, android.util.AttributeSet, int, boolean ]
```

> [!NOTE]
> This example hooks the following constructors from the [Android Java Library](https://developer.android.com/reference/kotlin/android/webkit/WebView#public-constructors):
>
> ```kotlin
> WebView(context: Context)
> WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int, privateBrowsing: Boolean)
> ```

### 1.2. Unnamed Objective-C Parameters

```yaml
objcClass: NSURL
methods:
  - name: "+ fileURLWithFileSystemRepresentation"
    returnType: (NSURL *)
    params: [ "(const char *)", "(BOOL)", "(NSURL *)" ]
```

> [!NOTE]
> This example hooks the following class method from  [NSURL](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):
>
> ```objectivec
> + (NSURL *) fileURLWithFileSystemRepresentation:(const char *) path 
>                                     isDirectory:(BOOL) isDir 
>                                   relativeToURL:(NSURL *) baseURL;
> ```

### 1.3. Unnamed Native Parameters

```yaml
module: sqlite3.so
functions:
  - symbol: sqlite3_exec
    returnType: int
    params: [ "sqlite3*", "const char *", "void *", "void *", "char **" ]
```

> [!NOTE]
> This example hooks the following method from the [SQLite function](https://sqlite.org/c3ref/exec.html):
>
> ```c
> int sqlite3_exec(
>   sqlite3*,                                  /* An open database */
>   const char *sql,                           /* SQL to be evaluated */
>   int (*callback)(void*,int,char**,char**),  /* Callback function */
>   void *,                                    /* 1st argument to callback */
>   char **errmsg                              /* Error msg written here */
> );
> ```

## 2. Named Parameters

If you want declare the name of the parameter, you must use an array for the type an name pair.

```yaml
params:
  - [ <type>, <name> ]
```

> [!IMPORTANT]
> The first element is the type of the parameter, the second the name.

The following chapters use the same examples described in [Unnamed Parameters](#1-unnamed-parameters), but add parameters names.

### 2.1. Named Java Parameters

```yaml
javaClass: android.webkit.WebView
methods:
  - name: $init
    overloads:
      - params:
        - [ android.content.Context, context ]
        - [ android.util.AttributeSet, attrs ]
        - [ int, defStyleAttr ]
        - [ boolean, privateBrowsing ]
```

> [!NOTE]
> This example hooks the following constructors from the [Android Java Library](https://developer.android.com/reference/kotlin/android/webkit/WebView#public-constructors):
>
> ```kotlin
> WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int, privateBrowsing: Boolean)
> ```

### 2.2. Named Objective-C Parameters

```yaml
objcClass: NSURL
methods:
  - name: "+ fileURLWithFileSystemRepresentation"
    returnType: (NSURL *)
    params:
      - [ "(const char *)",  path ]
      - [ "(BOOL)", isDir ]
      - [ "(NSURL *)",  baseURL ]
```

> [!NOTE]
> This example hooks the following class method from  [NSURL](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):
>
> ```objectivec
> + (NSURL *) fileURLWithFileSystemRepresentation:(const char *) path 
>                                     isDirectory:(BOOL) isDir 
>                                   relativeToURL:(NSURL *) baseURL;
> ```

### 2.3. Named Native Parameters

```yaml
module: sqlite3.so
functions:
  - symbol: sqlite3_exec
    returnType: int
    params: 
      - "sqlite3*", 
      - [ "const char *", sql ]
      - [ "void *", callback ] 
      - "void *"
      - [ "char **", "errmsg" ]
```

> [!NOTE]
> This example hooks the following method from the [SQLite function](https://sqlite.org/c3ref/exec.html):
>
> ```c
> int sqlite3_exec(
>   sqlite3*,                                  /* An open database */
>   const char *sql,                           /* SQL to be evaluated */
>   int (*callback)(void*,int,char**,char**),  /* Callback function */
>   void *,                                    /* 1st argument to callback */
>   char **errmsg                              /* Error msg written here */
> );
> ```

## 3. Decoders

When ever the frooky agent hooks a function on method, it tries to decode the arguments passed to it as well as the value returned to the caller.

Depending on the type this can be fairly simle. Primitives, such as Integers, Floats or Shorts can be always be decoded by the frooky agent. However, some values required more complex decoders.

They are required, if the either the time of decoding varies, or if more context information is required. The following two chapters explain these cases.

You can add a decoder configuration object to any [unnamed parameter](#1-unnamed-parameters) and [named](#2-named-parameters) parameter.

This is done using the a decoder configuration. This is an object which can contain the following options:

- `decoder`
- `decodeAt`
- `decodeParams`

```yaml
params:
  - [ <type>,                                    # Parameter type
      <name>,                                    # Parameter name
      {                                          # Decoder configuration
        decoder: <decoder>,                      # Custom decoder name. Default: autoSelect
        decodeAt: <enter|exit|both>,             # When to decode the parameter. Default: enter
        decoderArgs: [<param_name>]              # List of arguments passed to the decoder. Must be a valid parameter name
      }
    ]
```

The following chapters will explain the concepts using practical example.

### 3.1. `decoder`-Option: Custom Decoder

By default, frooky chooses the decoder for an argument based on the type declared in the hook configuration. For example, an `int` will always be decoded as a number and if there is no decoder available for a given type, frooky will use a fallback decoder.

For some cases you want to manually bypass the automatic decoder matching. Custom decoders are located in the following folders:

- [./android/decoders](../android/decoders)
- [./ios/decoders](../ios/decoders)
- [./native/decoders](../native/decoders)

You'll find more information about them in their documentation. You are also welcome to develop your own decoders and contribute them to frooky.

#### Asynchronous Callback Decoders

Asynchronous computing adds decoding complexity in frooky. This chapter explains how we can use the frooky hook declaration to decode asynchronous callbacks.

Let's take the following Objective-C method as example:

```yaml
objcClass: LAPrivateKey
methods:
  - name: "- decryptData"
    params:
      - [ "(NSData *)",  data ]
      - [ "(SecKeyAlgorithm)",  algorithm ]
      - [ "(void (^)(NSData *, NSError *))",  handler ]
      - [ "(NSData *)",  data ]
```

> [!NOTE]
> This `<hook_configuration>` will hook the following [Objective-C instance method](https://developer.apple.com/documentation/localauthentication/laprivatekey/decrypt(_:algorithm:completion:)?language=objc):
>
> ```objectivec
> - (void) decryptData:(NSData *) data 
>      secKeyAlgorithm:(SecKeyAlgorithm) algorithm 
>           completion:(void (^)(NSData *, NSError *)) handler;
> ```

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

<!-- TODO: Reference frooky callback decoders when we implement them. -->

#### 3.1.1. Custom Decoder in Java

```yaml
javaClass: android.content.Intent
methods:
  - name: setFlags
    overloads:
      - params:
        - [ int, flags, { decoder: intentFlagsDecoder } ]
```

> [!NOTE]
> This example hooks the following method from the [Android Java Library](https://developer.android.com/reference/kotlin/android/content/Intent#setflags):
>
> ```kotlin
> open fun setFlags(flags: Int): Intent
> ```

The parameter `flags` is a bitwise OR combination of [special flags](https://developer.android.com/reference/kotlin/android/content/Intent#flags), each controlling how this intent is handled. The custom decoder `intentFlagsDecoder` extracts the information again by doing a bitwise AND operation on the `flags` Integer with each flag.

If the result matches the value of the flag, it is set. This is a more stable way of decoding the flags compared to doing that on the frooky host, as the flags may not be the same as on the actual device.

#### 3.1.2. Custom Decoder in Objective-C

```yaml
objcClass: LAPrivateKey
methods:
  - name: "- decryptData"
    params:
      - [ "(NSData *)", data ]
      - [ "(SecKeyAlgorithm)", algorithm ]
      - [ "(void (^)(NSData *, NSError *))", handler, { decoder: LAPrivateKey_decryptData_callbackDecoder } ]
```

> [!NOTE]
> This example hooks the following method from [LAPrivateKey](https://developer.apple.com/documentation/localauthentication/laprivatekey/decrypt(_:algorithm:completion:)?language=objc):
>
> ```objectivec
> - (void) decryptData:(NSData *) data 
>      secKeyAlgorithm:(SecKeyAlgorithm) algorithm 
>           completion:(void (^)(NSData * , NSError * )) handler;
> ```

The parameter `(void (^)(NSData *, NSError *)) handler` is a callback function, called once the data is decrypted. Using the `decoder` option, we can implement a decoder which instead of just printing then value (which is just a `pointer`), adds a new hook to the callback method.

To do that, the custom decoder `LAPrivateKey_decryptData_callbackDecoder` must:

1. Create a new hook for the `handler` block
2. Intercept the callback when it's invoked

Once the handler is called by the `decryptData` instance method, the hook intercepts the first parameter containing the decrypted plaintext as `NSData *`.

#### 3.1.3. Custom Decoder in Native

```yaml
module: sqlite3.so
functions:
  - symbol: sqlite3_exec
    returnType: int
    params: 
      - "sqlite3*"
      - [ "const char *", sql ]
      - [ "void *", callback, { decoder: sqlite3_exec_callbackDecoder } ]
      - "void *"
      - [ "char **", errmsg ]
```

> [!NOTE]
> This example hooks the following method from the [SQLite](https://sqlite.org/c3ref/exec.html):
>
> ```c
> int sqlite3_exec(
>   sqlite3*,                                  /* An open database */
>   const char *sql,                           /* SQL to be evaluated */
>   int (*callback)(void*,int,char**,char**),  /* Callback function */
>   void *,                                    /* 1st argument to callback */
>   char **errmsg                              /* Error msg written here */
> );
> ```

The 3rd parameter is a pointer to a callback function. The custom decoder `sqlite3_exec_callbackDecoder` handles the function pointer appropriately, potentially hooking the callback to intercept its invocations.

Like with the [previous example](#312-custom-decoder-in-objective-c), we can also use the `sqlite3_exec_callbackDecoder` to dynamically hook the callback method and decode the arguments passed to it. In this case, the data would be one retrieved row.

### 3.2. `decodeAt`-Option: Declare the Time of Decoding

By default, arguments are decoded when the function or method is called. Larger datastrucutres, such as arrays are often passed by reference with the intention to manipulate them within the function or method like the following example shows:

```java
public final int doFinal(byte[] output, 
                         int outputOffset)
```

This Java method form the class `javax.crypto.Cipher` de- or encrypts the data stored in the current object and writes the output into the byte array `output`.  If we want to access the de- or encrypted `output`, we must decode the value after the method completes.

To accommodate for these cases, you can specify the time of decoding using the following decoder options:

- After the function or method completes (`decodeAt: exit`)
- Both at the beginning and after the function or method completes (`decodeAt: both`)

#### 3.2.1. Explicit Time of Decoding in Java

```yaml
javaClass: javax.crypto.Cipher 
methods:
  - name: doFinal
    overloads:
      - params:
        - [ "[B", output, { decodeAt: exit } ]
        - [ int, outputOffset ]
 ```

> [!NOTE]
> This example hooks the following method from the [Android Java Library](https://developer.android.com/reference/javax/crypto/Cipher?hl=en#doFinal(byte[],%20int)):
>
> ```java
> public final int doFinal (byte[] output, 
>                           int outputOffset)
> ```

In order to access the decrypted data, the parameter `output` parameter must be decoded at exit.

#### 3.2.2. Explicit Time of Decoding in Objective-C

```yaml
objcClass:  NSFileManager
methods:
  - name: "- contentsOfDirectoryAtPath"
    returnType: "(NSArray<NSString *> *)"
    params:
      - [ "(NSString *)", path ]
      - [ "(NSError * *)", error, { decodeAt: exit } ]
```

> [!NOTE]
> This example hooks the following method from [NSFileManager](https://developer.apple.com/documentation/foundation/filemanager/contentsofdirectory(atpath:)?language=objc):
>
> ```objectivec
> - (NSArray<NSString *> *) contentsOfDirectoryAtPath:(NSString *) path 
>                                               error:(NSError * *) error;
> ```

The `error` parameter must decoded at exit because it only contains meaningful data if an error occurred during the operation.

#### 3.2.3. Explicit Time of Decoding in Native

```yaml
module: libsystem_c.dylib
name: realpath
params:
  - [ "const char *restrict", file_name ]
  - [ "char *restrict", resolved_name, { decodeAt: exit } ]
```

> [!NOTE]
> This example hooks the following method from the [C standard library on iOS](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/realpath.3.html):
>
> ```c
> char *realpath(const char *restrict file_name, 
>                char *restrict resolved_name);
> ```

The `resolved_name` parameter must be decoded at exit, because it contains absolute pathname after resolution.

### 3.3. `decoderArgs`-Option: Pass Arguments to Decoder

In native functions, primitive arrays are passed by reference. In some cases we need more context information in order to decode the parameter.

A very common example is the length of an buffer. If the buffer is not limited by a terminating symbol such as `\0` for C strings, the decoder must know the length at runtime. Usually, the information is passed to the function or method. The following example illustrates this pattern with an example form the [OpenSSL library](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/):

```c
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx,       // Cipher context
                      unsigned char *out,        // Output buffer
                      int *outl,                 // Length of the output buffer
                      const unsigned char *in,   // Input buffer
                      int inl);                  // Length of the input bugger
```

This function encrypts `inl` bytes from the `in` buffer and writes the encrypted version to the `out` buffer. Depending on the type of encryption algorithm used, it is unclear how many bytes will be written at the time the function is called.

If we want to decode the `out` buffer, we must pass its length argument (`outl`) to the buffer decoder.

> [!TIP]
> In general, this is not good coding practice, but sometimes we need context information which is not passed to the function or method by its parameters. For example when we need to access as a global variable.
>
> In this case, you should write a [custom decoder](#31-decoder-option-custom-decoder) and use it to fetch the data and decode the value. 

#### 3.3.1. Pass Arguments to Decoder in Java

```yaml
javaClass: java.io.FileInputStream
methods:
  - name: read
    overloads:
      - params:
        - [ "[B", buffer, { decoderArgs: [ len ] } ]
        - [ int, offset ]
        - [ int, len ]
```

> [!NOTE]
> This example hooks the following method from [Android Java Library](https://developer.android.com/reference/java/io/FileInputStream#read(byte[],%20int,%20int)):
>
> ```java
> public int read (byte[] b, 
>                  int off, 
>                  int len)
> ```

The decoder for `buffer` receives `len` to know how many bytes were actually read.

#### 3.3.2. Pass Arguments to Decoder in Objective-C

```yaml
objcClass: NSData
methods:
  - name: "- getBytes"
    params:
      - [ "(void *)", buffer, { decoderArgs: [ length ] } ]
      - [ "(NSUInteger)", length ]
```

> [!NOTE]
> This example hooks the following method from  [NSData](https://developer.apple.com/documentation/foundation/nsdata/getbytes(_:range:)?language=objc):
>
> ```objectivec
> - (void) getBytes:(void *) buffer 
>                    range:(NSRange) range;
> ```

The `buffer` decoder uses the `length` parameter to determine how many bytes to decode.

#### 3.3.3. Pass Arguments to Decoder in Native

```yaml
module: libssl.so
functions:
  - symbol: EVP_DigestFinal_ex
    returnType: int
    params:
      - [ "EVP_MD_CTX *", ctx ]
      - [ "unsigned char *", md, { decodeAt: exit, decoderArgs: [ ctx, s ] } ]
      - [ "unsigned int *", s ]
```

> [!NOTE]
> This example hooks the following method from [OpenSSL](https://docs.openssl.org/1.0.2/man3/EVP_DigestInit):
>
> ```c
> int EVP_DigestFinal_ex(EVP_MD_CTX *ctx,
>                        unsigned char *md,
>                        unsigned int *s);
> ```

The digest buffer `md` decoder uses the `ctx` to determine what kind of hash algorithm was used, and the length `s` to decode the buffer.
