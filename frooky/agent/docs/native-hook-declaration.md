# `NativeHook` Declaration

This documentation explains how to write native hook declarations.

- [Structure of a `NativeHook` Declaration](#structure-of-a-nativehook-declaration)
- [Basic Usage](#basic-usage)

## Structure of a `NativeHook` Declaration

```yaml
module: <string>                       # Fully qualified module name
functions:                             # List of native symbol declarations to be hooked
  - <native_function_declaration>
```

`<native_function_declaration>` can be shortened, but arguments and return values are not decoded now:

```yaml
<native_function_declaration>:
  - <string>                           # Name of the native function
```

`<native_function_declaration>` with valued decoding must be declared as follows:

```yaml
<native_function_declaration>:
  symbol: <string>                     # Native symbol as string
  returnType: <string>                 # Optional: Return type of the function
  params:                              # Optional: Parameter list of the function
    - <parameter_declaration>
```

> [!IMPORTANT]
> Please read the documentation on [parameter](./parameter-declaration.md) and [return type](./return-type-declaration.md) declaration if you want to learn how to declare and configure them properly.
>
> There are multiple ways to declare a parameter. In this document, we always use [named parameters](./parameter-declaration.md#22-named-objective-c-parameters).

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

> [!NOTE]
> This `<hook_configuration>` hooks the following two functions from the [OpenSSL Library](https://docs.openssl.org/master/man3/ENGINE_add):
>
> ```c
> void ENGINE_load_builtin_engines(void);
> void ENGINE_cleanup(void);
> ```

frooky will capture when these functions are called and generate events. Since the functions take no arguments and return no value, the events will contain only timing and call stack information.

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

> [!NOTE]
> This `<hook_configuration>` will hook the following function from the [OpenSSL Library](https://docs.openssl.org/master/man3/OSSL_CMP_validate_msg/):
>
> ```c
> int OSSL_CMP_validate_cert_path(const OSSL_CMP_CTX *ctx,
>                                X509_STORE *trusted_store, X509 *cert);
> ```

frooky will attempt to decode the arguments and the return value based on the parameter types.
