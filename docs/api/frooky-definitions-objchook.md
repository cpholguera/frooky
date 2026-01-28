# Untitled object in frooky JSON API Schema

```txt
frooky.schema.json#/definitions/objcHook
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky.schema.json\*](frooky.schema.json "open original schema") |

## objcHook Type

`object` ([Details](frooky-definitions-objchook.md))

not

* [Untitled undefined type in frooky JSON API](frooky-definitions-objchook-not.md "check type definition")

# objcHook Properties

| Property              | Type      | Required | Nullable       | Defined by                                                                                                                           |
| :-------------------- | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------- |
| [native](#native)     | `boolean` | Required | cannot be null | [frooky JSON API](frooky-definitions-objchook-properties-native.md "frooky.schema.json#/definitions/objcHook/properties/native")     |
| [objClass](#objclass) | `string`  | Required | cannot be null | [frooky JSON API](frooky-definitions-objchook-properties-objclass.md "frooky.schema.json#/definitions/objcHook/properties/objClass") |
| [symbol](#symbol)     | `string`  | Required | cannot be null | [frooky JSON API](frooky-definitions-objchook-properties-symbol.md "frooky.schema.json#/definitions/objcHook/properties/symbol")     |
| [args](#args)         | `array`   | Optional | cannot be null | [frooky JSON API](frooky-definitions-nativeargsarray.md "frooky.schema.json#/definitions/objcHook/properties/args")                  |
| [debug](#debug)       | `boolean` | Optional | cannot be null | [frooky JSON API](frooky-definitions-debugproperty.md "frooky.schema.json#/definitions/objcHook/properties/debug")                   |

## native



`native`

* is required

* Type: `boolean`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-objchook-properties-native.md "frooky.schema.json#/definitions/objcHook/properties/native")

### native Type

`boolean`

### native Constraints

**constant**: the value of this property must be equal to:

```json
true
```

## objClass

Objective-C class name

`objClass`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-objchook-properties-objclass.md "frooky.schema.json#/definitions/objcHook/properties/objClass")

### objClass Type

`string`

## symbol

Objective-C method selector (e.g., 'dataTaskWithRequest:completionHandler:')

`symbol`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-objchook-properties-symbol.md "frooky.schema.json#/definitions/objcHook/properties/symbol")

### symbol Type

`string`

## args



`args`

* is optional

* Type: `object[]` ([Details](frooky-definitions-nativeargumentdescriptor.md))

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-nativeargsarray.md "frooky.schema.json#/definitions/objcHook/properties/args")

### args Type

`object[]` ([Details](frooky-definitions-nativeargumentdescriptor.md))

## debug

Enable verbose logging

`debug`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-debugproperty.md "frooky.schema.json#/definitions/objcHook/properties/debug")

### debug Type

`boolean`
