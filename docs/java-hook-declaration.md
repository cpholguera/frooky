# `JavaHook` Declaration

This documentation explains how to write Java hooks.

- [Structure of a `JavaHook` Declaration](#structure-of-a-javahook-declaration)
- [Basic Usage](#basic-usage)
- [Method Overloads](#method-overloads)
- [Type Descriptors](#type-descriptors)

## Structure

A `JavaHook` declaration is a YAML object with these top level fields:

```yaml
javaClass: <fully qualified Java class name>
methods:
  - <method name>
  - name: <method name>
    overloads:                        # Optional
      - params:
          - <parameter declaration>
```

Each item in `methods` can be written in one of two forms.

Use the **short form** to hook all overloads of a method.

```yaml
javaClass: <fully qualified Java class name>
methods:
  - <method name>
```

Use the **expanded form** when you want to declare specific overloads.

```yaml
javaClass: <fully qualified Java class name>
methods:
  - name: <method name>
    overloads:                        # Optional
      - params:
          - <parameter declaration>
```

Each item in `overloads` describes one method signature.

```yaml
params:
  - <parameter declaration>
```

> [!IMPORTANT]
> Please read the documentation on [parameter](./parameter-declaration.md) and [return type](./return-type-declaration.md) declaration to learn how to declare and configure them properly.
>
> There are multiple ways to declare a parameter. In this document, we always use [named parameters](./parameter-declaration.md#21-named-java-parameters).

## Basic Usage

The minimum required fields are `javaClass` and `methods`.

```yaml
javaClass: <fully qualified Java class name>
methods:
  - <method name>
```

This hooks all overloads of each listed method in the specified class.

**Example:**

```yaml
javaClass: android.webkit.WebView
methods:
  - $init
  - loadUrl
```

This declaration hooks all constructor overloads of `WebView`, plus all overloads of `loadUrl`.

> [!NOTE]
> `$init` is the constructor name.

This declaration hooks the following methods:

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
> Use the following syntax for dynamic class lookup at runtime.
>
> - **Exact match:** `org.owasp.mastestapp.MainActivity`
> - **Wildcards:** `org.owasp.*.HttpClient`, at the package level
> - **Nested classes:** use the `$` separator, for example `Outer$Inner`

## Method Overloads

To hook only specific overloads of a method, use the expanded form and provide a list of overload declarations under `overloads`.

```yaml
javaClass: <fully qualified Java class name>
methods:
  - name: <method name>
    overloads:                        # Optional
      - params:
          - <parameter declaration>
```

Each item in `overloads` matches one overloaded method signature including the relevant [parameter declarations](./parameter-declaration.md).

**Example:**

```yaml
javaClass: android.content.Intent
methods:
  - name: putExtra
    overloads:
      - params:
          - ["java.lang.String", name]
          - ["java.lang.String", value]
      - params:
          - ["java.lang.String", name]
          - ["[Z", value]
```

This hooks **only** the following methods:

```kotlin
Intent.putExtra(name: String!, value: String?): Intent
Intent.putExtra(name: String!, value: BooleanArray?): Intent
```

## Type Descriptors

Frida, and therefore frooky, uses custom type descriptors based on the internal [JVM field type descriptor](https://docs.oracle.com/javase/specs/jvms/se19/html/jvms-4.html#jvms-4.3.2).

The following table shows how types are represented in Java, the JVM, and Frida or frooky.

| Kind of Type      | Java Type Descriptor                                                                         | JVM Type Descriptor                                         | Frida / frooky Type Descriptor                                                               |
| ----------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Primitive         | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void` | `Z`<br>`B`<br>`C`<br>`S`<br>`I`<br>`J`<br>`F`<br>`D`<br>`V` | `boolean`<br>`byte`<br>`char`<br>`short`<br>`int`<br>`long`<br>`float`<br>`double`<br>`void` |
| Primitive Array   | `boolean[]`<br>`byte[]`<br>...                                                               | `[Z`<br>`[B`<br>...                                         | `[Z`<br>`[B`<br>...                                                                          |
| Reference         | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                             | `Ljava/lang/Object;`<br>`Lorg/owasp/MyClass;`<br>...        | `java.lang.Object`<br>`org.owasp.MyClass`<br>...                                             |
| Reference Array   | `Object[]`<br>`MyClass[]`<br>...                                                             | `[Ljava/lang/Object;`<br>`[Lorg/owasp/MyClass;`<br>...      | `[Ljava.lang.Object`<br>`[Lorg.owasp.MyClass`<br>...                                         |
| Multi-Dimensional | `int[][]`<br>`String[][]`<br>...                                                             | `[[I`<br>`[[Ljava/lang/String;`<br>...                      | `[[int`<br>`[[Ljava.lang.String`<br>...                                                      |

> [!NOTE]
> Frida uses a hybrid notation that combines JVM-style array prefixes (`[`) with Java-style class names (dot-separated rather than slash-separated, without the `L` prefix and `;` suffix).
