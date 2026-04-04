# Return Type Declaration

The return type declaration is a simpler variant of a [parameter declaration](./parameter-declaration.md).

- [Return Type vs. Parameter Declaration](#return-type-vs-parameter-declaration)
- [Basic Usage](#basic-usage)
  - [Java Return Types](#java-return-types)
  - [Objective-C Return Types](#objective-c-return-types)
  - [Native Return Types](#native-return-types)
- [Decoders](#decoders)
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
  - name: "+ fileURLWithFileSystemRepresentation:isDirectory:relativeToURL:"
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

If you want to configure the decoder for the return value, you can use the following option:

- `decoderArgs`

The following chapters will explain the concepts with a practical example.

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
