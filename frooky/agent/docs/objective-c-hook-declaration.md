# `ObjcHook` Declaration

This documentation explains how to write Objective-C hook declarations.

- [Structure of a `ObjcHook` Declaration](#structure-of-a-objchook-declaration)
- [Basic Usage](#basic-usage)

## Structure of an `ObjcHook` Declaration

```yaml
objcClass: <string>                     # Fully qualified Objective-C class name
methods:                               # List of Objective-C method declarations to be hooked
  - <objc_method_declaration>
```

`<objc_method_declaration>` can be shortened, but arguments and return values are not decoded now:

```yaml
<objc_method_declaration>:
  - <string>                           # Name of the native function
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

> [!NOTE]
> This `<hook_configuration>` will hook the following [Objective-C instance method](https://developer.apple.com/documentation/localauthentication/lacontext/invalidate()?language=objc):
>
> ```objectivec
> - (void) invalidate;
> ```

frooky will capture when this function is called and generate an event. Because the function takes no arguments and returns no value, the event will contain only timing and call stack information.

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

> [!NOTE]
> This example hooks the following class method from [NSURL](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):
>
> ```objectivec
> + (NSURL *) fileURLWithFileSystemRepresentation:(const char *) path 
>                                     isDirectory:(BOOL) isDir 
>                                   relativeToURL:(NSURL *) baseURL;
> ```
