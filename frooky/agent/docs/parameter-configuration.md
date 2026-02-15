# Parameter Configuration

frooky needs to know a function or method's signature in order to hook it correctly. Part of this signature is the parameter list which is a set of types and names for the arguments passed to the function or method.

> [!TIP]
> Technically, the name of an argument is not required, but it is recommended declaring the name as well, as this makes a declaration easier to read and provides more context information in the output of frooky.

There are different accepted ways defining a parameter. The following chapters explain them.

## Unnamed Parameters

This is the most simple way of defining a parameter solely based on its type. frooky will try to decode the arguments based on the automatically selected decoder.

### Unnamed Java Parameters

```yaml
javaClass: android.webkit.WebView
methods:
  - name: $init
    overloads:
      - params: [ Context ]
      - params: [ Context, AttributeSet, Int, Boolean ]
```

This `<hook_configuration>` will hook the following method:

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

This `<hook_configuration>` will hook the following [Objective-C class method](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):

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

This `<hook_configuration>` will hook the following [SQLite function](https://sqlite.org/c3ref/exec.html):

```c
int sqlite3_exec(
  sqlite3*,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
);
```

> [!IMPORTANT]
> The 3rd parameter is a pointer to the callback function. Please see also [Custom Decoders](#custom-decoders) for more information, about how to handle a fallback function.

## Named Parameters

If you want declare the name of the parameter, you have must use an array for the type an name pair.

> [!IMPORTANT]
> The first element is the type of the parameter, the second the name.

The following chapters use the same examples described in [Unnamed Parameters](#unnamed-parameters), but add parameters names.

### Named Java Parameters

```yaml
javaClass: android.webkit.WebView
methods:
  - name: $init
    overloads:
      - params:
        - [ Context, context ]
        - [ AttributeSet, attrs ]
        - [ Int, defStyleAttr ]
        - [ Boolean, privateBrowsing ]
```

This `<hook_configuration>` will hook the following method:

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

This `<hook_configuration>` will hook the following [Objective-C class method](https://developer.apple.com/documentation/foundation/nsurl/fileurl(withfilesystemrepresentation:isdirectory:relativeto:)?language=objc):

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

This `<hook_configuration>` will hook the following [SQLite function](https://sqlite.org/c3ref/exec.html):

```c
int sqlite3_exec(
  sqlite3*,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
);
```

> [!NOTE]
> Not all parameters have a name in this example. The ones without name can be declared as [unnamed parameter](#unnamed-native-parameters).

## Decoder Configuration

You can add a decoder configuration object to any [unnamed](#unnamed-parameters) and [named](#named-parameters) parameter.

This is done using the a `decoder` object. The object can contain the following properties:

- `decoder`
- `decodeAt`
- `decodeParams`

The following chapters will explain the concepts using practical example.

### Parameters with explicit Time of Decoding

As described in the chapter [Time of Decoding](./decoder-configuration.md#time-of-decoding), for some parameters the time of decoding is important. By default, an argument passed to a function or method is decoded at entry. But you can also choose to decode the parameter at the following times:

- After the function or method completes
- Both at the beginning and after the function or method completes

