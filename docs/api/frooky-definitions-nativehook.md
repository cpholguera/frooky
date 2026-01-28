# Untitled object in frooky JSON API Schema

```txt
frooky.schema.json#/definitions/nativeHook
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky.schema.json\*](frooky.schema.json "open original schema") |

## nativeHook Type

`object` ([Details](frooky-definitions-nativehook.md))

not

* any of

  * [Untitled undefined type in frooky JSON API](frooky-definitions-nativehook-not-anyof-0.md "check type definition")

  * [Untitled undefined type in frooky JSON API](frooky-definitions-nativehook-not-anyof-1.md "check type definition")

# nativeHook Properties

| Property                                              | Type      | Required | Nullable       | Defined by                                                                                                                                                               |
| :---------------------------------------------------- | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [native](#native)                                     | `boolean` | Required | cannot be null | [frooky JSON API](frooky-definitions-nativehook-properties-native.md "frooky.schema.json#/definitions/nativeHook/properties/native")                                     |
| [symbol](#symbol)                                     | `string`  | Required | cannot be null | [frooky JSON API](frooky-definitions-nativehook-properties-symbol.md "frooky.schema.json#/definitions/nativeHook/properties/symbol")                                     |
| [module](#module)                                     | `string`  | Required | cannot be null | [frooky JSON API](frooky-definitions-nativehook-properties-module.md "frooky.schema.json#/definitions/nativeHook/properties/module")                                     |
| [args](#args)                                         | `array`   | Optional | cannot be null | [frooky JSON API](frooky-definitions-nativeargsarray.md "frooky.schema.json#/definitions/nativeHook/properties/args")                                                    |
| [filterEventsByStacktrace](#filtereventsbystacktrace) | `array`   | Optional | cannot be null | [frooky JSON API](frooky-definitions-nativehook-properties-filtereventsbystacktrace.md "frooky.schema.json#/definitions/nativeHook/properties/filterEventsByStacktrace") |
| [debug](#debug)                                       | `boolean` | Optional | cannot be null | [frooky JSON API](frooky-definitions-debugproperty.md "frooky.schema.json#/definitions/nativeHook/properties/debug")                                                     |

## native



`native`

* is required

* Type: `boolean`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-nativehook-properties-native.md "frooky.schema.json#/definitions/nativeHook/properties/native")

### native Type

`boolean`

### native Constraints

**constant**: the value of this property must be equal to:

```json
true
```

## symbol

Native function symbol name

`symbol`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-nativehook-properties-symbol.md "frooky.schema.json#/definitions/nativeHook/properties/symbol")

### symbol Type

`string`

## module

Library/module name (e.g., 'libc.so', 'libssl.so')

`module`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-nativehook-properties-module.md "frooky.schema.json#/definitions/nativeHook/properties/module")

### module Type

`string`

## args



`args`

* is optional

* Type: `object[]` ([Details](frooky-definitions-nativeargumentdescriptor.md))

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-nativeargsarray.md "frooky.schema.json#/definitions/nativeHook/properties/args")

### args Type

`object[]` ([Details](frooky-definitions-nativeargumentdescriptor.md))

## filterEventsByStacktrace

Only capture when stack contains these patterns

`filterEventsByStacktrace`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-nativehook-properties-filtereventsbystacktrace.md "frooky.schema.json#/definitions/nativeHook/properties/filterEventsByStacktrace")

### filterEventsByStacktrace Type

`string[]`

## debug

Enable verbose logging

`debug`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-debugproperty.md "frooky.schema.json#/definitions/nativeHook/properties/debug")

### debug Type

`boolean`
