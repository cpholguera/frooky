# `ObjcHook` Declaration

This documentation explains how to write Objective-C hook declarations.

- [Structure of an `ObjcHook` Declaration](#structure-of-an-objchook-declaration)
- [Basic Usage](#basic-usage)
- [Decoding Arguments and Return Values](#decoding-arguments-and-return-values)

## Structure

```yaml
objcClass: <string>                    # Fully qualified Objective-C class name
methods:                               # List of Objective-C method declarations to be hooked
  - <objc_method_declaration>
```

`<objc_method_declaration>` can be shortened, but arguments and return values are not decoded now:

```yaml
<objc_method_declaration>:
  - <string>                           # Name of the Objective-C method 
```

`<objc_method_declaration>` with value decoding must be declared as follows:

```yaml
<objc_method_declaration>:
  name: <string>                       # Name of the Objective-C method (include - or + prefix)
  returnType: <string>                 # Optional: Return type of the Objective-C method
  params:                              # Optional: Parameter list of the Objective-C method
    - <parameter_declaration>
```

> [!IMPORTANT]
> Please read the documentation on [parameter](./parameter-declaration.md) and [return type](./return-type-declaration.md) declaration if you want to learn how to declare and configure them properly.
>
> There are multiple ways to declare a parameter. In this document, we always use [named parameters](./parameter-declaration.md#22-named-objective-c-parameters).

## Basic Usage

The minimum required properties are `objcClass` and `methods`:

```yaml
objcClass: <string>                    # Fully qualified Objective-C class name
methods:                               # List of Objective-C method declarations to be hooked
  - <objc_method_declaration>
```

> [!TIP]
>
> Use the following syntax to hook two kinds of Objective-C methods:
>
> - **Instance methods**: `- biometryType`
> - **Class methods**: `+ removeProperties`

**Example:**

```yaml
objcClass: LAContext
methods:
 - name: "- invalidate"
```

This `<hook_configuration>` will hook the following [Objective-C instance method](https://developer.apple.com/documentation/localauthentication/lacontext/invalidate()?language=objc):

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
