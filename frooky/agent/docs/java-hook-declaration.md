# `JavaHook` Declaration

This documentation explains how to write a Java hook declaration.

- [Structure of a `JavaHook` Declaration](#structure-of-a-javahook-declaration)
- [Basic Usage](#basic-usage)
- [Method Overloads](#method-overloads)
- [Type Descriptors](#type-descriptors)

## Structure of a `JavaHook` Declaration

```yaml
javaClass: <string>                    # Fully qualified Java class name
methods:                               # List of Java methods to hook
  - <java_method_declaration>
```

`<java_method_declaration>` without overloads can be shortened:

```yaml
<java_method_declaration>:
  - <string>                           # Name of the Java method
```

`<java_method_declaration>` with overloads must be declared like that:

```yaml
<java_method_declaration>:
  name: <string>                       # Name of the Java method
  overloads:                           # Optional: List of explicit method overloads
    - <overloads_declaration>
```

```yaml
<overloads_declaration>:
  params:                          # Parameter list of the overloaded method
    - <parameter_declaration>
```

> [!IMPORTANT]
> Please read the documentation on [parameter](./parameter-declaration.md) and [return type](./return-type-declaration.md) declaration to learn how to declare and configure them properly.
>
> There are multiple ways to declare a parameter. In this document, we always use [named parameters](./parameter-declaration.md#11-unnamed-java-parameters).

## Basic Usage

The minimum required properties are `javaClass` and `methods`:

```yaml
javaClass: <string>                    # Fully qualified Java class name
methods:                               # List of Java methods to hook
  - name: <java_method_name>
```

In this case, *all* overloads of the specified methods from the class will be hooked.

**Example:**

```yaml
javaClass: android.webkit.WebView 
methods:
  - name: $init
  - name: loadUrl
```

> [!TIP]
> `$init` is the name of the constructor of a class.

This `<hook_declaration>` will hook the following methods:

```kotlin
WebView(context: Context)
WebView(context: Context, attrs: AttributeSet?)
WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int)
WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int, privateBrowsing: Boolean)
WebView(context: Context, attrs: AttributeSet?, defStyleAttr: Int, defStyleRes: Int)
WebView.loadUrl(url: String)
WebView.loadUrl(url: String, additionalHttpHeaders: MutableMap<String!, String!>)
```

> [!TIP]
>
> Use the following syntax for dynamic `<class>` lookup at runtime:
>
> - **Exact match**: `org.owasp.mastestapp.MainActivity`
> - **Wildcards**: `org.owasp.*.HttpClient` (at the package level)
> - **Nested classes**: Use the `$` separator (e.g., `Outer$Inner`)

## Method Overloads

If you only want to hook a specific overload, specify it by adding one or more overloads to `overloads`:

```yaml
javaClass: <string>                    # Fully qualified Java class name
methods:                               # List of Java methods to hook
  - name: <string>                     # Name of the Java method
    overloads:                         # List of overloaded methods 
      - params:                        # List of parameter declarations for one overload
        - <parameter_declaration>
```

**Example:**

```yaml
javaClass: android.content.Intent
methods:
  - name: putExtra
    overloads:
      - params:
        - [ "java.lang.String", name ]
        - [ "java.lang.String", value ]
      - params:
        - [ "java.lang.String", name ]
        - [ "[Z", value ]
```

This will *only* hook the following methods:

```kotlin
Intent.putExtra(name: String!, value: String?): Intent
Intent.putExtra(name: String!, value: BooleanArray?): Intent
```

## Type Descriptors

Frida, and therefore frooky, uses custom type descriptors based on the internal [JVM field type descriptor](https://docs.oracle.com/javase/specs/jvms/se19/html/jvms-4.html#jvms-4.3.2).

The following table shows the different kinds of types and their representations in Java, the JVM, and Frida:

| Kind of Type      | Java Type Descriptor                                                                         | JVM Type Descriptor                                         | Frida / frooky Type Descriptor                                                               |
| ----------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Primitive         | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void` | `Z`<br>`B`<br>`C`<br>`S`<br>`I`<br>`J`<br>`F`<br>`D`<br>`V` | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void` |
| Primitive Array   | `boolean[]`<br>`byte[]`<br>...                                                               | `[Z`<br>`[B`<br>...                                         | `[Z`<br>`[B`<br>...                                                                          |
| Reference         | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                             | `Ljava/lang/Object;`<br>`Lorg/owasp/MyClass;`<br>...        | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                             |
| Reference Array   | `Object[]`<br>`MyClass[]`<br>...                                                             | `[Ljava/lang/Object;`<br>`[Lorg/owasp/MyClass;`<br>...      | `[Ljava.lang.Object`<br>`[Lorg.owasp.MyClass`<br>...                                         |
| Multi-Dimensional | `int[][]`<br>`String[][]`<br>...                                                             | `[[I`<br>`[[Ljava/lang/String;`<br>...                      | `[[int`<br>`[[Ljava.lang.String`<br>...                                                      |

> [!NOTE]
> Frida uses a hybrid notation that combines JVM-style array prefixes (`[`) with Java-style class names (dot-separated rather than slash-separated, without the `L` prefix and `;` suffix).
