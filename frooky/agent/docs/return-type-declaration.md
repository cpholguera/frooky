# Return Type Declaration

The return type declaration is a simpler variant of a [parameter declaration](./parameter-declaration.md).

- [1. Differences from Parameter Declaration](#1-differences-from-parameter-declaration)
- [2. Basic Usage](#2-basic-usage)
  - [2.1. Java Return Types](#21-java-return-types)
  - [2.2. Objective-C Return Types](#22-objective-c-return-types)
  - [2.3. Native Return Types](#23-native-return-types)
- [3. Decoders](#3-decoders)
  - [3.1. `decoder`-Option: Custom Decoder](#31-decoder-option-custom-decoder)
    - [3.1.1. Custom Decoder in Java](#311-custom-decoder-in-java)
    - [3.1.2. Custom Decoder in Objective-C](#312-custom-decoder-in-objective-c)
    - [3.1.3. Custom Decoder in Native](#313-custom-decoder-in-native)
  - [3.2. `decoderArgs`-Option: Pass Arguments to Decoder](#32-decoderargs-option-pass-arguments-to-decoder)
    - [3.2.2. Pass Arguments to Decoder in Objective-C](#322-pass-arguments-to-decoder-in-objective-c)

## 1. Differences from Parameter Declaration

Compared with a parameter declaration, a return type declaration differs in the following ways:

- It is declared only once per function or method
- It cannot be named
- It is always decoded after the function or method completes

The following chapter explains how to declare the return type with examples.

## 2. Basic Usage

The return type is declared only by its type. The following chapters will use examples to illustrate this.

### 2.1. Java Return Types

In Java, the method signature can be retrieved at runtime. Unless you want to override the [default decoder](#3-decoders), you don't need to provide an explicit return type.

### 2.2. Objective-C Return Types

> [!NOTE]
> This example hooks the following class method from [NSURL](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):
>
> ```objectivec
> + (NSURL *) fileURLWithFileSystemRepresentation:(const char *) path 
>                                     isDirectory:(BOOL) isDir 
>                                   relativeToURL:(NSURL *) baseURL;
> ```

```yaml
objcClass: NSURL
methods:
  - name: "+ fileURLWithFileSystemRepresentation"
    returnType: (NSURL *)
    params: [ "(const char *)", "(BOOL)", "(NSURL *)" ]
```

The return value is of type `(NSURL *)`. frooky will decode it using the default `(NSURL *)` decoder.

### 2.3. Native Return Types

> [!NOTE]
> This example hooks the following method from [OpenSSL](https://docs.openssl.org/1.0.2/man3/EVP_DigestInit):
>
> ```c
> int EVP_DigestFinal_ex(EVP_MD_CTX *ctx,
>                        unsigned char *md,
>                        unsigned int *s);
> ```

```yaml
module: libssl.so
functions:
  - symbol: EVP_DigestFinal_ex
    returnType: int
    params:
      - [ "EVP_MD_CTX *", ctx ]
      - [ "unsigned char *", md ]
      - [ "unsigned int *", s ]
```

The function returns an integer. It returns 1 on success and 0 on failure.

## 3. Decoders

If you want to configure the decoder for the return value, you can use the following two options:

- `decoder`
- `decoderArgs`

The following chapters will explain the concepts with a practical example.

### 3.1. `decoder`-Option: Custom Decoder

#### 3.1.1. Custom Decoder in Java

> [!NOTE]
> This example hooks the following method from the [Android Java Library](https://developer.android.com/reference/kotlin/android/content/Intent#getflags):
>
> ```kotlin
> open fun getFlags(): Int
> ```

```yaml
javaClass: android.content.Intent
methods:
  - name: getFlags
    returnType: [ int, { decoder: intentFlagsDecoder } ]
```

The return value is an integer representing the set flags for this intent. Instead of using the default integer decoder, frooky will use `intentFlagsDecoder` to process the return value and decode the set flags rather than just the integer.

#### 3.1.2. Custom Decoder in Objective-C

> [!NOTE]
> This example hooks the following instance method from [NSData](https://developer.apple.com/documentation/foundation/nsdata/base64encodedstring(options:)?language=objc):
>
> ```objectivec
> - (NSString *) base64EncodedStringWithOptions:(NSDataBase64EncodingOptions) options;
> ```

```yaml
objcClass: NSData
methods:
  - name: "- base64EncodedStringWithOptions"
    returnType: [ (NSString *),  { decoder: base64Decoder } ]
    params: [ "(NSDataBase64EncodingOptions)" ]
```

The return value is a base64-encoded string. The custom decoder `base64Decoder` can decode the base64 string to recover the original data.

#### 3.1.3. Custom Decoder in Native

> [!NOTE]
> This example hooks the following function from [OpenSSL](https://docs.openssl.org/master/man3/SSL_get_cipher):
>
> ```c
> int SSL_get_cipher_bits(const SSL *s, int *np);
> ```

```yaml
module: libssl.so
functions:
  - symbol: SSL_get_cipher_bits
    returnType: [ int, { decoder: openSslCipherDecoder } ]
    params:
      - [ "const SSL *", int ]
```

The return value is the number identifying the cipher suite. The custom decoder `openSslCipherDecoder` can decode the number and return a string representation of the cipher suite.

### 3.2. `decoderArgs`-Option: Pass Arguments to Decoder

While the use case for `decoderArgs` is less common, you can use it the same way as [parameters](./parameter-declaration.md#33-decoderargs-option-pass-arguments-to-decoder). It must reference the name of a parameter.

#### 3.2.2. Pass Arguments to Decoder in Objective-C

> [!NOTE]
> This example hooks the following instance method from [NSString](https://developer.apple.com/documentation/foundation/nsstring/data(using:)?language=objc):
>
> ```objectivec
> - (NSData *) dataUsingEncoding:(NSStringEncoding) encoding;
> ```

```yaml
objcClass: NSString
methods:
  - name: "- dataUsingEncoding"
    returnType: [ "(NSData *)", { decoderArgs: [ encoding ] }  ]
    params: [ ["(NSStringEncoding)", encoding ] ]
```

The return value is an `NSData` object. The decoder receives the `encoding` parameter to interpret the data correctly.
