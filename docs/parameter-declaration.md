# Parameter Declaration

frooky needs to know a function or method's signature to hook it correctly. Part of this signature is the parameter list, which includes the types and names of the arguments passed to the function or method. This documentation explains how to declare parameters.

There are different accepted ways to declare a parameter. The following chapters explain them.

- [Unnamed Parameters](#unnamed-parameters)
  - [Unnamed Java Parameters](#unnamed-java-parameters)
  - [Unnamed Objective-C Parameters](#unnamed-objective-c-parameters)
  - [Unnamed Native Parameters](#unnamed-native-parameters)
- [Named Parameters](#named-parameters)
  - [Named Java Parameters](#named-java-parameters)
  - [Named Objective-C Parameters](#named-objective-c-parameters)
  - [Named Native Parameters](#named-native-parameters)
- [Decoders](#decoders)
  - [`decoder`-Option: Custom Decoder](#decoder-option-custom-decoder)
    - [Custom Decoder in Java](#custom-decoder-in-java)
    - [Custom Decoder in Objective-C](#custom-decoder-in-objective-c)
    - [Custom Decoder in Native](#custom-decoder-in-native)
  - [`decodeAt`-Option: Declare the Time of Decoding](#decodeat-option-declare-the-time-of-decoding)
    - [Explicit Time of Decoding in Java](#explicit-time-of-decoding-in-java)
    - [Explicit Time of Decoding in Objective-C](#explicit-time-of-decoding-in-objective-c)
    - [Explicit Time of Decoding in Native](#explicit-time-of-decoding-in-native)
  - [`decoderArgs`-Option: Pass Arguments to Decoder](#decoderargs-option-pass-arguments-to-decoder)
    - [Pass Arguments to Decoder in Java](#pass-arguments-to-decoder-in-java)
    - [Pass Arguments to Decoder in Objective-C](#pass-arguments-to-decoder-in-objective-c)
    - [Pass Arguments to Decoder in Native](#pass-arguments-to-decoder-in-native)


## Unnamed Parameters

This is the simplest declaration, based solely on its type:

```yaml
params: [ <type> ]
```

frooky will try to decode the arguments based on the provided type.

### Unnamed Java Parameters

```yaml
javaClass: android.webkit.WebView
methods:
  - name: $init
    overloads:
      - params: [ android.content.Context ]
      - params: [ android.content.Context, android.util.AttributeSet, int, boolean ]
```

This example hooks the following constructors from the [Android Java Library](https://developer.android.com/reference/kotlin/android/webkit/WebView#public-constructors):

```kotlin
WebView(context: Context)
WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int, privateBrowsing: Boolean)
```

### Unnamed Objective-C Parameters

```yaml
objcClass: NSURL
methods:
  - name: "+ fileURLWithFileSystemRepresentation"
    returnType: (NSURL *)
    params: [ "(const char *)", "(BOOL)", "(NSURL *)" ]
```

This example hooks the following class method from  [NSURL](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):

```objectivec
+ (NSURL *) fileURLWithFileSystemRepresentation:(const char *) path 
                                    isDirectory:(BOOL) isDir 
                                  relativeToURL:(NSURL *) baseURL;
```

### Unnamed Native Parameters

```yaml
module: sqlite3.so
functions:
  - symbol: sqlite3_exec
    returnType: int
    params: [ "sqlite3*", "const char *", "void *", "void *", "char **" ]
```

This example hooks the following method from the [SQLite function](https://sqlite.org/c3ref/exec.html):

```c
int sqlite3_exec(
  sqlite3*,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
);
```

## Named Parameters

If you want to declare the name of the parameter, you must use an array for the type and name pair.

```yaml
params:
  - [ <type>, <name> ]
```

The following chapters use the same examples described in [Unnamed Parameters](#1-unnamed-parameters) but add parameter names.

> [!TIP]
> Technically, the name of an argument is not required, but it is recommended to declare the name as well, as this makes a declaration easier to read and provides more context in the output of frooky.

### Named Java Parameters

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

This example hooks the following constructors from the [Android Java Library](https://developer.android.com/reference/kotlin/android/webkit/WebView#public-constructors):

```kotlin
WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int, privateBrowsing: Boolean)
```

### Named Objective-C Parameters

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

This example hooks the following class method from [NSURL](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):

```objectivec
+ (NSURL *) fileURLWithFileSystemRepresentation:(const char *) path 
                                    isDirectory:(BOOL) isDir 
                                  relativeToURL:(NSURL *) baseURL;
```

### Named Native Parameters

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


This example hooks the following method from the [SQLite function](https://sqlite.org/c3ref/exec.html):

```c
int sqlite3_exec(
  sqlite3*,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
);
```

## Decoders

When hooking a method, frooky tries to decode arguments as well as return values. Depending on the type, this can be fairly simple. Primitives, such as Integers, Floats, or Shorts, can always be decoded by the frooky agent. However, some values require more complex decoders.

These are required when the time of decoding varies, or when more context information is needed. The following two chapters explain these cases.

You can configure a decoder by adding a decoder configuration object to a parameter declaration.

This is done using a decoder configuration added to any [unnamed](#1-unnamed-parameters) and [named](#2-named-parameters) parameters. It can contain the following options:

- `decoder`
- `decodeAt`
- `decodeArgs`

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

The following chapters will explain the concepts through practical examples.

### `decoder`-Option: Custom Decoder

By default, frooky selects the decoder for an argument based on the type declared in the hook configuration. For example, an `int` is always decoded as a number, and if no decoder is available for a given type, frooky uses a fallback decoder.

In some cases, you want to manually bypass the automatic decoder matching. Custom decoders are located in the following folders:

- [./android/decoders](../android/decoders)
- [./ios/decoders](../ios/decoders)
- [./native/decoders](../native/decoders)

You'll find more information about them in their documentation. You are also welcome to develop your own decoders and contribute them to frooky.

To get an idea about what an more complex decoder can do, let's look how to use them in a common pattern, callback functions:

#### Custom Decoder in Java

```yaml
javaClass: android.content.Intent
methods:
  - name: setFlags
    overloads:
      - params:
        - [ int, flags, { decoder: intentFlagsDecoder } ]
```

This example hooks the following method from the [Android Java Library](https://developer.android.com/reference/kotlin/android/content/Intent#setflags):

```kotlin
open fun setFlags(flags: Int): Intent
```

The parameter `flags` is a bitwise OR combination of [special flags](https://developer.android.com/reference/kotlin/android/content/Intent#flags), each controlling how this intent is handled. The custom decoder `intentFlagsDecoder` extracts the information by performing a bitwise AND operation between the `flags` Integer and each flag.

If the result matches the value of the flag, it is set. This is a more stable way of decoding the flags than doing it on the frooky host, as the flags may not be the same as on the actual device.

#### Custom Decoder in Objective-C

Custom decoders are handy when asynchronous patterns are used. The following method has an argument called `handler` which is a pointer to a method which is called, once it decrypted the data:

```yaml
objcClass: LAPrivateKey
methods:
  - name: "- decryptData"
    params:
      - [ "(NSData *)", data ]
      - [ "(SecKeyAlgorithm)", algorithm ]
      - [ "(void (^)(NSData *, NSError *))", handler, { decoder: LAPrivateKey_decryptData_callbackDecoder } ]
```

This example hooks the following method from [LAPrivateKey](https://developer.apple.com/documentation/localauthentication/laprivatekey/decrypt(_:algorithm:completion:)?language=objc):

```objectivec
- (void) decryptData:(NSData *) data 
     secKeyAlgorithm:(SecKeyAlgorithm) algorithm 
          completion:(void (^)(NSData * , NSError * )) handler;
```

The parameter `(void (^)(NSData *, NSError *)) handler` is a callback function that is called once the data is decrypted.  For this example, the method would be called like this:

```objectivec
[self decryptData:myData 
 secKeyAlgorithm:kSecKeyAlgorithmRSAEncryptionOAEPSHA256 
       completion:^(NSData *result, NSError *error) {
          // handle result with the decrypted data
      }];
```

Using the `decoder` option, we can implement a decoder that, instead of just printing the value (which is just a `pointer`), adds a new hook to the callback method.

To do that, the custom decoder `LAPrivateKey_decryptData_callbackDecoder` must:

1. Create a new hook for the `handler` block
2. Intercept the callback when it's invoked

Once the handler is called by the `decryptData` instance method, the hook intercepts the first parameter, which contains the decrypted plaintext as `NSData *`.

#### Custom Decoder in Native

Value decoding in native code is often more complex compared to decoding Java or Objective-C values. The reason for that is, that native code usually strips symbols and the `struct` data structure does not contain information about its structure during runtime. 

Arguments or return values often are _just_ pointers with no additional information about how to interpret it. This makes decoding the them a bigger challenge.

However, with a custom decoder we can still decode them based on external information, such as the documentation for the public API or the definition of the associated `struct` from a header file.

Let's look at how we can do that using two examples:

**Example 1: Decoding a Callback Function Pointer**

The following function from the SQLite library executes a SQL query and then calls the function at the pointer `callback`:

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

This example hooks the following method from [SQLite](https://sqlite.org/c3ref/exec.html):

```c
int sqlite3_exec(
  sqlite3*,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
);
```

If we want to hook the `callback` function, we can write a custom decoder for this argument. The decoder `sqlite3_exec_callbackDecoder` handles the function pointer appropriately, potentially hooking the callback to intercept its invocations.

As in the [previous example](#312-custom-decoder-in-objective-c), we can also use the `sqlite3_exec_callbackDecoder` to dynamically hook the callback method and decode the arguments passed to it. In this case, the data would be the retrieved row.


**Example 2: Decoding `struct` based on its definition**

```yaml
module: libssl.so
functions:
  - symbol: DSA_sign
    returnType: int
    params: 
      - [ int, type ]
      - [ "const unsigned char *", dgst ]
      - [ int, len ]
      - [ "unsigned char *", sigret ]
      - [ unsigned int *, siglen ]
      - [ "DSA *", dsa, { decoder: dsa_decoder } ] 
```

This example hooks the following function from [OpenSSL](https://docs.openssl.org/1.1.1/man3/DSA_sign/):

```c
int DSA_sign(int type, const unsigned char *dgst, int len,
               unsigned char *sigret, unsigned int * siglen, DSA *dsa);
```

`DSA_verify` computes a digital signature on `dgst` using the private key stored in the `dsa` structure and stores it into `sigret`.


Let's assume, we want to access the private key whenever this function is called. We can do that by writing a custom decoder which decodes the `dsa` structure. 

Compared to most Java or Objective-C data structures, a native `struct` does have information about the structure itself in memory. This means, to write a decoder, we need to have information about the content of the `struct`. If the source code is public, we can use this information to write a decoder based on the `struct` definition. 

In this case, we can use the [public source code](https://github.com/openssl/openssl/blob/master/crypto/dsa/dsa_local.h) and get the definition:

```c

struct dsa_st {
    /*
     * This first variable is used to pick up errors where a DSA is passed
     * instead of an EVP_PKEY
     */
    int pad;
    int32_t version;
    FFC_PARAMS params;
    BIGNUM *pub_key; /* y public key */
    BIGNUM *priv_key; /* x private key */
    int flags;
    /* Normally used to cache montgomery values */
    BN_MONT_CTX *method_mont_p;
    CRYPTO_REF_COUNT references;
#ifndef FIPS_MODULE
    CRYPTO_EX_DATA ex_data;
#endif
    const DSA_METHOD *meth;
    CRYPTO_RWLOCK *lock;
    OSSL_LIB_CTX *libctx;

    /* Provider data */
    size_t dirty_cnt; /* If any key material changes, increment this */
} DSA;
```

If we want to access `priv_key`, we need to know at what position its pointer (`BIGNUM *`) is. This can be done by calculating the offset based on the elements in the struct before it based and their size.

To get to the position of `BIGNUM *priv_key`, we need to add up the size of the following elements:

- `int`
- `int32_t`
- `FFC_PARAMS`
- `pointer`

Since `FFC_PARAMS` is `struct` itself, we need to use its definition in order to calculate its full size:


```c
typedef struct ffc_params_st {
    /* Primes */
    BIGNUM *p;
    BIGNUM *q;
    /* Generator */
    BIGNUM *g;
    /* DH X9.42 Optional Subgroup factor j >= 2 where p = j * q + 1 */
    BIGNUM *j;

    /* Required for FIPS186_4 validation of p, q and optionally canonical g */
    unsigned char *seed;
    /* If this value is zero the hash size is used as the seed length */
    size_t seedlen;
    /* Required for FIPS186_4 validation of p and q */
    int pcounter;
    int nid; /* The identity of a named group */

    /*
     * Required for FIPS186_4 generation & validation of canonical g.
     * It uses unverifiable g if this value is -1.
     */
    int gindex;
    int h; /* loop counter for unverifiable g */

    unsigned int flags;
    /*
     * The digest to use for generation or validation. If this value is NULL,
     * then the digest is chosen using the value of N.
     */
    const char *mdname;
    const char *mdprops;
    /* Default key length for known named groups according to RFC7919 */
    int keylength;
} FFC_PARAMS;
```

After adding up all elements, we can access the pointer to `priv_key`.


> [!IMPORTANT]
>
> Decoding data structures in native code is generally more complex and error prone as we often don't have information about the data available at runtime.
>
> In the example above, it was possible to calculate the offset. However, this is not always possible. For example if macros are used add or remove elements at compile time, a `struct` of the same library can vary depending on the compilation settings.
> 
> Further, internally used data structures may change from version to version. If an element is removed or added, the decoder would interpret the data wrongly.
>
> It is therefore important to be aware of these limitations and use `struct` decoders cautiously.



### `decodeAt`-Option: Declare the Time of Decoding

By default, arguments are decoded when the function or method is called. Larger data structures, such as arrays, are often passed by reference to allow manipulation within the function or method, as the following example shows:

```java
public final int doFinal(byte[] output, 
                         int outputOffset)
```

This Java method from the class `javax.crypto.Cipher` encrypts or decrypts the data stored in the current object and writes the output to the byte array `output`. To access the encrypted or decrypted `output`, you must decode the value after the method completes.

To accommodate these cases, you can specify the timing of decoding using the following decoder options:

- After the function or method completes (`decodeAt: exit`)
- Both at the beginning and after the function or method completes (`decodeAt: both`)

#### Explicit Time of Decoding in Java

```yaml
javaClass: javax.crypto.Cipher 
methods:
  - name: doFinal
    overloads:
      - params:
        - [ "[B", output, { decodeAt: exit } ]
        - [ int, outputOffset ]
 ```

This example hooks the following method from the [Android Java Library](https://developer.android.com/reference/javax/crypto/Cipher?hl=en#doFinal(byte[],%20int)):

```java
public final int doFinal (byte[] output, 
                          int outputOffset)
```

In order to access the decrypted data, the `output` parameter must be decoded at exit.

#### Explicit Time of Decoding in Objective-C

```yaml
objcClass:  NSFileManager
methods:
  - name: "- contentsOfDirectoryAtPath"
    returnType: "(NSArray<NSString *> *)"
    params:
      - [ "(NSString *)", path ]
      - [ "(NSError * *)", error, { decodeAt: exit } ]
```

This example hooks the following method from [NSFileManager](https://developer.apple.com/documentation/foundation/filemanager/contentsofdirectory(atpath:)?language=objc):

```objectivec
- (NSArray<NSString *> *) contentsOfDirectoryAtPath:(NSString *) path 
                                              error:(NSError * *) error;
```

The `error` parameter must be decoded at exit because it contains meaningful data only if an error occurred during the operation.

#### Explicit Time of Decoding in Native

```yaml
module: libsystem_c.dylib
name: realpath
params:
  - [ "const char *restrict", file_name ]
  - [ "char *restrict", resolved_name, { decodeAt: exit } ]
```


This example hooks the following method from the [C standard library on iOS](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/realpath.3.html):

```c
char *realpath(const char *restrict file_name, 
               char *restrict resolved_name);
```

The `resolved_name` parameter must be decoded at exit because it contains an absolute pathname after resolution.

### `decoderArgs`-Option: Pass Arguments to Decoder

In native functions, primitive arrays are passed by reference. In some cases, we need additional context to decode the parameter.

A common example is the length of a buffer. If the buffer is not terminated by a symbol such as `\0` for C strings, the decoder must know the length at runtime. Usually, this information is passed to the function or method. The following example illustrates this pattern from the [OpenSSL library](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/):

```c
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx,       // Cipher context
                      unsigned char *out,        // Output buffer
                      int *outl,                 // Length of the output buffer
                      const unsigned char *in,   // Input buffer
                      int inl);                  // Length of the input bugger
```

This function encrypts `inl` bytes from the `in` buffer and writes the encrypted result to the `out` buffer. Depending on the encryption algorithm used, it is unclear how many bytes will be written when the function is called.

If we want to decode the `out` buffer, we must pass its length (`outl`) to the buffer decoder.


#### Pass Arguments to Decoder in Java

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

This example hooks the following method from the [Android Java Library](https://developer.android.com/reference/java/io/FileInputStream#read(byte[],%20int,%20int)):

```java
public int read (byte[] b, 
                 int off, 
                 int len)
```

The decoder for `buffer` receives `len` to indicate how many bytes were actually read.

#### Pass Arguments to Decoder in Objective-C

```yaml
objcClass: NSData
methods:
  - name: "- getBytes"
    params:
      - [ "(void *)", buffer, { decoderArgs: [ length ] } ]
      - [ "(NSUInteger)", length ]
```

This example hooks the following method from [NSData](https://developer.apple.com/documentation/foundation/nsdata/getbytes(_:range:)?language=objc):

```objectivec
- (void) getBytes:(void *) buffer 
                   range:(NSRange) range;
```

The `buffer` decoder uses the `length` parameter to specify how many bytes to decode.

#### Pass Arguments to Decoder in Native

```yaml
module: libssl.so
functions:
  - symbol: EVP_DigestFinal_ex
    returnType: int
    params:
      - [ "EVP_MD_CTX *", ctx ]
      - [ "unsigned char *", md, { decodeAt: exit, decoderArgs: [ ctx ] } ]
      - [ "unsigned int *", s ]
```

This example hooks the following method from [OpenSSL](https://docs.openssl.org/1.0.2/man3/EVP_DigestInit):

```c
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx,
                       unsigned char *md,
                       unsigned int *s);
```

This function retrieves the digest data from `ctx` and moves it into `md`. So in order to decode `md`, we need to know the type of the digest algorithm or the size of the digest, hence we pass `ctx`.
