# `ObjcHook` Declaration

This documentation explains how to write Objective-C hook declarations.

- [Structure of an `ObjcHook` Declaration](#structure-of-an-objchook-declaration)
- [Basic Usage](#basic-usage)
- [Decoding Arguments and Return Values](#decoding-arguments-and-return-values)

## Structure

A `ObjcHook` declaration is a YAML object with these top level fields:

```yaml
objcClass: <Objective-C class name>
methods:
  - <method name>
  - name: <method name>
    returnType: <type>                # Optional
    params:                           # Optional
      - <parameter declaration>
```

`objcClass` is the name of the Objective-C class.

`methods` is a list of Objective-C methods to hook. Each item in `methods` can be written in one of two forms.

Use the **short form** when you only want to hook a method and do not need argument or return value decoding.

```yaml
objcClass: <Objective-C class name>
methods:
  - <method name>
```

Use the **expanded form** when you want frooky to decode arguments and or the return value.

```yaml
objcClass: <Objective-C class name>
methods:
  - name: <method name>
    returnType: <type>                # Optional
    params:                           # Optional
      - <parameter declaration>
```

In the expanded form:

- `name`: Objective-C method name, including the `-` or `+` prefix.
- `returnType`: Optional return type of the Objective-C method.
- `params`: Optional list of parameter declarations.

> [!IMPORTANT]
> Read the documentation for [parameter](./parameter-declaration.md) and [return type](./return-type-declaration.md) declarations to learn how to declare and configure them correctly.
>
> There are multiple ways to declare a parameter. In this document, all examples use [named parameters](./parameter-declaration.md#22-named-objective-c-parameters).

## Basic Usage

The minimum required fields are `objcClass` and `methods`:

```yaml
objcClass: <Objective-C class name>
methods:
  - <method name>
```

> [!TIP]
>
> Use the following syntax to hook the two kinds of Objective-C methods:
>
> - **Instance methods**: `- biometryType`
> - **Class methods**: `+ removeProperties`

**Example:**

```yaml
objcClass: LAContext
methods:
  - "- invalidate"
```

You can also write the same declaration in expanded form:

```yaml
objcClass: LAContext
methods:
  - name: "- invalidate"
```

This declaration hooks the following [Objective-C instance method](https://developer.apple.com/documentation/localauthentication/lacontext/invalidate%28%29?language=objc):

```objectivec
- (void) invalidate;
```

## Decoding Arguments and Return Values

When a method accepts parameters or returns a value, frooky needs to know their types to decode them properly:


```yaml
objcClass: <string>                    # Fully qualified Objective-C class name
methods:                       
  - name: <string>                     # Name of the Objective-C method (include - or + prefix)
    returnType: <string>               # Return type of the Objective-C method
    params:                            # Parameter list of the Objective-C method
      - <parameter_declaration>
```

**Example:**

```yaml
objcClass: NSURL
methods:
  - name: "+ fileURLWithFileSystemRepresentation"
    returnType: "(NSURL *)"
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

Depending on the type, frooky is able to decode them using the built in decoders. If the types are more complex, you may need to [custom decoders](./parameter-declaration.md#custom-decoder-in-objective-c).
