# Return Type Declaration

The return type declaration is a simpler variant of a [parameter declaration](./parameter-declaration.md).

- [Return Type vs. Parameter Declaration](#return-type-vs-parameter-declaration)
- [Basic Usage](#basic-usage)
  - [Java Return Types](#java-return-types)
  - [Objective-C Return Types](#objective-c-return-types)
  - [Native Return Types](#native-return-types)
- [Decoders](#decoders)
  - [`decoder`-Option: Custom Decoder](#decoder-option-custom-decoder)
    - [Custom Decoder in Java](#custom-decoder-in-java)
    - [Custom Decoder in Objective-C](#custom-decoder-in-objective-c)
    - [Custom Decoder in Native](#custom-decoder-in-native)
  - [`decoderArgs`-Option: Pass Arguments to Decoder](#decoderargs-option-pass-arguments-to-decoder)
    - [Pass Arguments to Decoder in Objective-C](#pass-arguments-to-decoder-in-objective-c)

## Return Type vs. Parameter Declaration

Compared with a parameter declaration, a return type declaration differs in the following ways:

- It is declared only once per function or method
- It cannot be named
- It is always decoded after the function or method completes

The following chapter explains how to declare the return type with examples.

## Basic Usage

The return type is declared only by its type. The following chapters will use examples to illustrate this.

### Java Return Types

In Java, the method signature can be retrieved at runtime. Unless you want to override the [default decoder](#3-decoders), you don't need to provide an explicit return type.

### Objective-C Return Types

```yaml
objcClass: NSURL
methods:
  - name: "+ fileURLWithFileSystemRepresentation"
    returnType: (NSURL *)
    params: [ "(const char *)", "(BOOL)", "(NSURL *)" ]
```

The return value is of type `(NSURL *)`. frooky will decode it using the default `(NSURL *)` decoder.

This example hooks the following class method from [NSURL](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):

```objectivec
+ (NSURL *) fileURLWithFileSystemRepresentation:(const char *) path 
                                    isDirectory:(BOOL) isDir 
                                  relativeToURL:(NSURL *) baseURL;
```


### Native Return Types

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

This example hooks the following method from [OpenSSL](https://docs.openssl.org/1.0.2/man3/EVP_DigestInit):

```c
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx,
                       unsigned char *md,
                       unsigned int *s);
```



The function returns an integer. It returns 1 on success and 0 on failure.

## Decoders

If you want to configure the decoder for the return value, you can use the following two options:

- `decoder`
- `decoderArgs`

The following chapters will explain the concepts with a practical example.

### `decoder`-Option: Custom Decoder

#### Custom Decoder in Java

```yaml
javaClass: android.content.Intent
methods:
  - name: getFlags
    returnType: [ int, { decoder: intentFlagsDecoder } ]
```

This example hooks the following method from the [Android Java Library](https://developer.android.com/reference/kotlin/android/content/Intent#getflags):

```kotlin
open fun getFlags(): Int
```



The return value is an integer representing the set flags for this intent. Instead of using the default integer decoder, frooky will use `intentFlagsDecoder` to process the return value and decode the set flags rather than just the integer.

#### Custom Decoder in Objective-C

```yaml
objcClass: NSData
methods:
  - name: "- base64EncodedStringWithOptions"
    returnType: [ (NSString *),  { decoder: base64Decoder } ]
    params: [ "(NSDataBase64EncodingOptions)" ]
```


 This example hooks the following instance method from [NSData](https://developer.apple.com/documentation/foundation/nsdata/base64encodedstring(options:)?language=objc):

```objectivec
- (NSString *) base64EncodedStringWithOptions:(NSDataBase64EncodingOptions) options;
```


The return value is a base64-encoded string. The custom decoder `base64Decoder` can decode the base64 string to recover the original data.

#### Custom Decoder in Native

```yaml
module: libssl.so
functions:
  - symbol: SSL_get_cipher_bits
    returnType: [ int, { decoder: openSslCipherDecoder } ]
    params:
      - [ "const SSL *", int ]
```

This example hooks the following function from [OpenSSL](https://docs.openssl.org/master/man3/SSL_get_cipher):

```c
int SSL_get_cipher_bits(const SSL *s, int *np);
```

The return value is the number identifying the cipher suite. The custom decoder `openSslCipherDecoder` can decode the number and return a string representation of the cipher suite.

### `decoderArgs`-Option: Pass Arguments to Decoder

While the use case for `decoderArgs` is less common, you can use it the same way as [parameters](./parameter-declaration.md#33-decoderargs-option-pass-arguments-to-decoder). It must reference the name of a parameter.

#### Pass Arguments to Decoder in Objective-C

```yaml
objcClass: NSString
methods:
  - name: "- dataUsingEncoding"
    returnType: [ "(NSData *)", { decoderArgs: [ encoding ] }  ]
    params: [ ["(NSStringEncoding)", encoding ] ]
```

This example hooks the following instance method from [NSString](https://developer.apple.com/documentation/foundation/nsstring/data(using:)?language=objc):

```objectivec
- (NSData *) dataUsingEncoding:(NSStringEncoding) encoding;
```

The return value is an `NSData` object. The decoder receives the `encoding` parameter to interpret the data correctly.
