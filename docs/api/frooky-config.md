# frooky Configuration Schema

```txt
frooky-config.schema.json
```

Schema for defining hooks for frooky.

| Abstract               | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                    |
| :--------------------- | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------- |
| Cannot be instantiated | Yes        | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [frooky-config.schema.json](frooky-config.schema.json "open original schema") |

## frooky Configuration Type

`object[]` ([Details](frooky-config-items.md))

# frooky Configuration Definitions

## Definitions group debugProperty

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/debugProperty"}
```

| Property | Type | Required | Nullable | Defined by |
| :------- | :--- | :------- | :------- | :--------- |

## Definitions group nativeArgsArray

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/nativeArgsArray"}
```

| Property | Type | Required | Nullable | Defined by |
| :------- | :--- | :------- | :------- | :--------- |

## Definitions group javaOverloads

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/javaOverloads"}
```

| Property | Type | Required | Nullable | Defined by |
| :------- | :--- | :------- | :------- | :--------- |

## Definitions group javaMethods

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/javaMethods"}
```

| Property | Type | Required | Nullable | Defined by |
| :------- | :--- | :------- | :------- | :--------- |

## Definitions group javaHookCore

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/javaHookCore"}
```

| Property            | Type     | Required | Nullable       | Defined by                                                                                                                                                |
| :------------------ | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [class](#class)     | `string` | Required | cannot be null | [frooky Configuration](frooky-config-definitions-javahookcore-properties-class.md "frooky-config.schema.json#/definitions/javaHookCore/properties/class") |
| [methods](#methods) | `array`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-javamethods.md "frooky-config.schema.json#/definitions/javaHookCore/properties/methods")                 |

### class

Fully qualified Java/Kotlin class name

`class`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-javahookcore-properties-class.md "frooky-config.schema.json#/definitions/javaHookCore/properties/class")

#### class Type

`string`

### methods

Array of methods to hook

`methods`

* is required

* Type: `object[]` ([Details](frooky-config-definitions-javamethods-items.md))

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-javamethods.md "frooky-config.schema.json#/definitions/javaHookCore/properties/methods")

#### methods Type

`object[]` ([Details](frooky-config-definitions-javamethods-items.md))

#### methods Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

## Definitions group javaHook

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/javaHook"}
```

| Property | Type | Required | Nullable | Defined by |
| :------- | :--- | :------- | :------- | :--------- |

## Definitions group nativeHook

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/nativeHook"}
```

| Property                                              | Type      | Required | Nullable       | Defined by                                                                                                                                                                                  |
| :---------------------------------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [native](#native)                                     | `boolean` | Required | cannot be null | [frooky Configuration](frooky-config-definitions-nativehook-properties-native.md "frooky-config.schema.json#/definitions/nativeHook/properties/native")                                     |
| [symbol](#symbol)                                     | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-nativehook-properties-symbol.md "frooky-config.schema.json#/definitions/nativeHook/properties/symbol")                                     |
| [module](#module)                                     | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-nativehook-properties-module.md "frooky-config.schema.json#/definitions/nativeHook/properties/module")                                     |
| [args](#args)                                         | `array`   | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargsarray.md "frooky-config.schema.json#/definitions/nativeHook/properties/args")                                                    |
| [filterEventsByStacktrace](#filtereventsbystacktrace) | `array`   | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativehook-properties-filtereventsbystacktrace.md "frooky-config.schema.json#/definitions/nativeHook/properties/filterEventsByStacktrace") |
| [debug](#debug)                                       | `boolean` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativehook-properties-debug.md "frooky-config.schema.json#/definitions/nativeHook/properties/debug")                                       |

### native



`native`

* is required

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativehook-properties-native.md "frooky-config.schema.json#/definitions/nativeHook/properties/native")

#### native Type

`boolean`

#### native Constraints

**constant**: the value of this property must be equal to:

```json
true
```

### symbol

Native function symbol name

`symbol`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativehook-properties-symbol.md "frooky-config.schema.json#/definitions/nativeHook/properties/symbol")

#### symbol Type

`string`

### module

Library/module name (e.g., 'libc.so', 'libssl.so')

`module`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativehook-properties-module.md "frooky-config.schema.json#/definitions/nativeHook/properties/module")

#### module Type

`string`

### args



`args`

* is optional

* Type: `object[]` ([Details](frooky-config-definitions-nativeargumentdescriptor.md))

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargsarray.md "frooky-config.schema.json#/definitions/nativeHook/properties/args")

#### args Type

`object[]` ([Details](frooky-config-definitions-nativeargumentdescriptor.md))

### filterEventsByStacktrace

Only capture when stack contains these patterns

`filterEventsByStacktrace`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativehook-properties-filtereventsbystacktrace.md "frooky-config.schema.json#/definitions/nativeHook/properties/filterEventsByStacktrace")

#### filterEventsByStacktrace Type

`string[]`

### debug

Enable verbose logging

`debug`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativehook-properties-debug.md "frooky-config.schema.json#/definitions/nativeHook/properties/debug")

#### debug Type

`boolean`

## Definitions group objcHook

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/objcHook"}
```

| Property              | Type      | Required | Nullable       | Defined by                                                                                                                                              |
| :-------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [native](#native-1)   | `boolean` | Required | cannot be null | [frooky Configuration](frooky-config-definitions-objchook-properties-native.md "frooky-config.schema.json#/definitions/objcHook/properties/native")     |
| [objClass](#objclass) | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-objchook-properties-objclass.md "frooky-config.schema.json#/definitions/objcHook/properties/objClass") |
| [symbol](#symbol-1)   | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-objchook-properties-symbol.md "frooky-config.schema.json#/definitions/objcHook/properties/symbol")     |
| [args](#args-1)       | `array`   | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargsarray.md "frooky-config.schema.json#/definitions/objcHook/properties/args")                  |
| [debug](#debug-1)     | `boolean` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-objchook-properties-debug.md "frooky-config.schema.json#/definitions/objcHook/properties/debug")       |

### native



`native`

* is required

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-objchook-properties-native.md "frooky-config.schema.json#/definitions/objcHook/properties/native")

#### native Type

`boolean`

#### native Constraints

**constant**: the value of this property must be equal to:

```json
true
```

### objClass

Objective-C class name

`objClass`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-objchook-properties-objclass.md "frooky-config.schema.json#/definitions/objcHook/properties/objClass")

#### objClass Type

`string`

### symbol

Objective-C method selector (e.g., 'dataTaskWithRequest:completionHandler:')

`symbol`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-objchook-properties-symbol.md "frooky-config.schema.json#/definitions/objcHook/properties/symbol")

#### symbol Type

`string`

### args



`args`

* is optional

* Type: `object[]` ([Details](frooky-config-definitions-nativeargumentdescriptor.md))

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargsarray.md "frooky-config.schema.json#/definitions/objcHook/properties/args")

#### args Type

`object[]` ([Details](frooky-config-definitions-nativeargumentdescriptor.md))

### debug

Enable verbose logging

`debug`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-objchook-properties-debug.md "frooky-config.schema.json#/definitions/objcHook/properties/debug")

#### debug Type

`boolean`

## Definitions group swiftHook

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/swiftHook"}
```

| Property                  | Type      | Required | Nullable       | Defined by                                                                                                                                                    |
| :------------------------ | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [native](#native-2)       | `boolean` | Required | cannot be null | [frooky Configuration](frooky-config-definitions-swifthook-properties-native.md "frooky-config.schema.json#/definitions/swiftHook/properties/native")         |
| [swiftClass](#swiftclass) | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-swifthook-properties-swiftclass.md "frooky-config.schema.json#/definitions/swiftHook/properties/swiftClass") |
| [symbol](#symbol-2)       | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-swifthook-properties-symbol.md "frooky-config.schema.json#/definitions/swiftHook/properties/symbol")         |
| [module](#module-1)       | `string`  | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-swifthook-properties-module.md "frooky-config.schema.json#/definitions/swiftHook/properties/module")         |
| [debug](#debug-2)         | `boolean` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-swifthook-properties-debug.md "frooky-config.schema.json#/definitions/swiftHook/properties/debug")           |

### native



`native`

* is required

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-swifthook-properties-native.md "frooky-config.schema.json#/definitions/swiftHook/properties/native")

#### native Type

`boolean`

#### native Constraints

**constant**: the value of this property must be equal to:

```json
true
```

### swiftClass

Swift class name (mangled or demangled)

`swiftClass`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-swifthook-properties-swiftclass.md "frooky-config.schema.json#/definitions/swiftHook/properties/swiftClass")

#### swiftClass Type

`string`

### symbol

Swift method name

`symbol`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-swifthook-properties-symbol.md "frooky-config.schema.json#/definitions/swiftHook/properties/symbol")

#### symbol Type

`string`

### module

Swift module name (optional)

`module`

* is optional

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-swifthook-properties-module.md "frooky-config.schema.json#/definitions/swiftHook/properties/module")

#### module Type

`string`

### debug

Enable verbose logging

`debug`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-swifthook-properties-debug.md "frooky-config.schema.json#/definitions/swiftHook/properties/debug")

#### debug Type

`boolean`

## Definitions group nativeArgumentDescriptor

Reference this group by using

```json
{"$ref":"frooky-config.schema.json#/definitions/nativeArgumentDescriptor"}
```

| Property                    | Type      | Required | Nullable       | Defined by                                                                                                                                                                                    |
| :-------------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [name](#name)               | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-name.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/name")               |
| [type](#type)               | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-type.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/type")               |
| [length](#length)           | `integer` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-length.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/length")           |
| [lengthInArg](#lengthinarg) | `integer` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-lengthinarg.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/lengthInArg") |
| [direction](#direction)     | `string`  | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-direction.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/direction")     |
| [returnValue](#returnvalue) | `boolean` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-returnvalue.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/returnValue") |
| [filter](#filter)           | `array`   | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-filter.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/filter")           |

### name



`name`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-name.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/name")

#### name Type

`string`

### type

Native C/C++ types and iOS Foundation types

`type`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-type.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/type")

#### type Type

`string`

#### type Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"string"`       |             |
| `"int32"`        |             |
| `"uint32"`       |             |
| `"int64"`        |             |
| `"pointer"`      |             |
| `"bytes"`        |             |
| `"bool"`         |             |
| `"double"`       |             |
| `"CFData"`       |             |
| `"CFDictionary"` |             |

### length

Fixed byte length for 'bytes' type

`length`

* is optional

* Type: `integer`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-length.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/length")

#### length Type

`integer`

#### length Constraints

**minimum**: the value of this number must greater than or equal to: `1`

### lengthInArg

Argument index containing the length

`lengthInArg`

* is optional

* Type: `integer`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-lengthinarg.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/lengthInArg")

#### lengthInArg Type

`integer`

#### lengthInArg Constraints

**minimum**: the value of this number must greater than or equal to: `0`

### direction

Parameter direction (out = read after return)

`direction`

* is optional

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-direction.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/direction")

#### direction Type

`string`

#### direction Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value   | Explanation |
| :------ | :---------- |
| `"in"`  |             |
| `"out"` |             |

### returnValue

Capture as return value

`returnValue`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-returnvalue.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/returnValue")

#### returnValue Type

`boolean`

### filter

Only capture when value matches these patterns

`filter`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-filter.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/filter")

#### filter Type

`string[]`
