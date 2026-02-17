# Return Type Declaration

The return type declaration is a simpler variant of a [parameter declaration](./parameter-declaration.md).

- [1. Differences to Parameter Declaration](#1-differences-to-parameter-declaration)
- [2. Basic Usage](#2-basic-usage)
  - [2.1. 2.1 Java Return Types](#21-21-java-return-types)
  - [2.2. 2.2 Objective-C Return Types](#22-22-objective-c-return-types)
  - [2.3. 2.3 Native Return Types](#23-23-native-return-types)
- [3. Decoders](#3-decoders)
  - [3.1. `decoder`-Option: Custom Decoder](#31-decoder-option-custom-decoder)
    - [3.1.1. Custom Decoder in Java](#311-custom-decoder-in-java)
    - [3.1.2. Custom Decoder in Objective-C](#312-custom-decoder-in-objective-c)
    - [3.1.3. Custom Decoder in Native](#313-custom-decoder-in-native)
  - [3.2. `decoderArgs`-Option: Pass Arguments to Decoder](#32-decoderargs-option-pass-arguments-to-decoder)
    - [3.2.2. Pass Arguments to Decoder in Objective-C](#322-pass-arguments-to-decoder-in-objective-c)

## 1. Differences to Parameter Declaration

Compared to a parameter declaration, the return type declaration differs in the following ways:

- It is only declared once per function or method
- It cannot be named
- It is always decoded after the function or method completes

The following chapter explains how to declare the return type based on examples.

## 2. Basic Usage

The return type is declared only by it's type. The following chapters will use examples to illustrate this.

### 2.1. 2.1 Java Return Types

In Java, the method signature can be retrieved during runtime. In fact, this is always done by frooky in order to overload the right target method.

Because of that, the return type is always known. The developer therefore must not declare a return type.

### 2.2. 2.2 Objective-C Return Types

> [!NOTE]
> This example hooks the following class method from  [NSURL](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):
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

The return value is of the type. frooky will decode it using the default `(NSURL *)` decoder.

### 2.3. 2.3 Native Return Types

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

The return value is an integer. The function returns 1 for success and 0 for failure.

## 3. Decoders

If you want to configure the decoder of the return value, you can use the following two options:

- `decoder`
- `decodeParams`

The following chapters will explain the concepts using practical example.

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
    returnType: [ java.lang.String, { decoder: intentFlagsDecoder } ]
```

The return value is a `java.lang.String` representing the set flags for this intent. Instead of using the default integer decoder, frooky will use `intentFlagsDecoder` to process the return value and decode the set flags instead of just the integer.

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

The return value is a base64-encoded string. The custom decoder `base64Decoder` can for example decode the base 64 string in order to get the original data.

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

The return value is the number identifying the cipher suite. The custom decoder `openSslCipherDecoder` can decode the number and return the a string representation of the cipher suite.

### 3.2. `decoderArgs`-Option: Pass Arguments to Decoder

While the use case for `decoderArgs` is less common, you can use it in the same way as with [parameters](./parameter-declaration.md#33-decoderargs-option-pass-arguments-to-decoder). They must reference the name of a parameter.

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
    returnType: [ "(NSData *)", { decoderArgs: encoding }  ]
    params: [ ["(NSStringEncoding)", encoding ] ]
```

The return value is an `NSData` object. The decoder receives the `encoding` parameter to properly interpret the data.
