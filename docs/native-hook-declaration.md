# `NativeHook` Declaration

This documentation explains how to write native hook declarations.

- [Structure of a `NativeHook` Declaration](#structure-of-a-nativehook-declaration)
- [Basic Usage](#basic-usage)
- [Decoding Arguments and Return Values](#decoding-arguments-and-return-values)

## Structure

A `NativeHook` declaration is a YAML object with these top level fields:

```yaml
module: <module name>
functions:
  - <symbol name>
  - symbol: <symbol name>
    returnType: <type>                # Optional
    params:                           # Optional
      - <parameter declaration>
```

`module` is the name of the native module, for example a shared library such as `libssl.so`.

`functions` is a list of native functions to hook. Each item in `functions` can be written in one of two forms.

Use the **short form** when you only want to hook a symbol and do not need argument or return value decoding.

```yaml
module: <module name>
functions:
  - <symbol name>
```

Use the **expanded form** when you want frooky to decode arguments and or the return value.

```yaml
module: <module name>
functions:
  - symbol: <symbol name>
    returnType: <type>                # Optional
    params:                           # Optional
      - <parameter declaration>
```

In the expanded form:

- `symbol`: Native symbol name.
- `returnType`: Optional return type of the function.
- `params`: Optional list of parameter declarations.

> [!IMPORTANT]
> Read the documentation for [parameter](./parameter-declaration.md) and [return type](./return-type-declaration.md) declarations to learn how to declare and configure them correctly.
>
> There are multiple ways to declare a parameter. In this document, all examples use [named parameters](./parameter-declaration.md#22-named-objective-c-parameters).

## Basic Usage

The minimum required properties are `module` and `functions`:

```yaml
module: <string>                       # Fully qualified module name (mandatory)
functions:                             # List of native symbol declarations to be hooked
  - <native_function_declaration>
```

**Example:**

```yaml
module: libssl.so
functions:
 - symbol: ENGINE_load_builtin_engines
 - symbol: ENGINE_cleanup
```

This `<hook_configuration>` hooks the following two functions from the [OpenSSL Library](https://docs.openssl.org/master/man3/ENGINE_add):

```c
void ENGINE_load_builtin_engines(void);
void ENGINE_cleanup(void);
```


## Decoding Arguments and Return Values

When a method accepts parameters or returns a value, frooky needs to know how to decode them.

This is done by declaring the types in each `<function>`. The syntax is the same as [C function declarations](https://en.cppreference.com/w/c/language/function_declaration.html).

```yaml
module: <string>                       # Fully qualified module name (mandatory)
functions:                             # List of native symbol declarations to be hooked
  - symbol: <string>                   # Native symbol as string
    returnType: <string>               # Optional: Return type of the function
    params:                            # Optional: Parameter list of the function
      - <parameter_declaration>
```

**Example:**

```yaml
module: libssl.so
functions:
  - symbol: OSSL_CMP_validate_cert_path
    returnType: int
    params:
      - [ "const OSSL_CMP_CTX *", ctx ]
      - [ "X509_STORE *", trusted_store ]
      - [ "X509 *", cert ]
```

This `<hook_configuration>` will hook the following function from the [OpenSSL Library](https://docs.openssl.org/master/man3/OSSL_CMP_validate_msg/):

```c
int OSSL_CMP_validate_cert_path(const OSSL_CMP_CTX *ctx,
                                X509_STORE *trusted_store, 
                                X509 *cert);
```

Depending on the type, frooky is able to decode them using the built in decoders. If the types are more complex, you may need to [custom decoders](./parameter-declaration.md#custom-decoder-in-native).

