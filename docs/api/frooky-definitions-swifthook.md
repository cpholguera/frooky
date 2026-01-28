# Untitled object in frooky JSON API Schema

```txt
frooky.schema.json#/definitions/swiftHook
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky.schema.json\*](frooky.schema.json "open original schema") |

## swiftHook Type

`object` ([Details](frooky-definitions-swifthook.md))

not

* [Untitled undefined type in frooky JSON API](frooky-definitions-swifthook-not.md "check type definition")

# swiftHook Properties

| Property                  | Type      | Required | Nullable       | Defined by                                                                                                                                 |
| :------------------------ | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------- |
| [native](#native)         | `boolean` | Required | cannot be null | [frooky JSON API](frooky-definitions-swifthook-properties-native.md "frooky.schema.json#/definitions/swiftHook/properties/native")         |
| [swiftClass](#swiftclass) | `string`  | Required | cannot be null | [frooky JSON API](frooky-definitions-swifthook-properties-swiftclass.md "frooky.schema.json#/definitions/swiftHook/properties/swiftClass") |
| [symbol](#symbol)         | `string`  | Required | cannot be null | [frooky JSON API](frooky-definitions-swifthook-properties-symbol.md "frooky.schema.json#/definitions/swiftHook/properties/symbol")         |
| [module](#module)         | `string`  | Optional | cannot be null | [frooky JSON API](frooky-definitions-swifthook-properties-module.md "frooky.schema.json#/definitions/swiftHook/properties/module")         |
| [debug](#debug)           | `boolean` | Optional | cannot be null | [frooky JSON API](frooky-definitions-debugproperty.md "frooky.schema.json#/definitions/swiftHook/properties/debug")                        |

## native



`native`

* is required

* Type: `boolean`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-swifthook-properties-native.md "frooky.schema.json#/definitions/swiftHook/properties/native")

### native Type

`boolean`

### native Constraints

**constant**: the value of this property must be equal to:

```json
true
```

## swiftClass

Swift class name (mangled or demangled)

`swiftClass`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-swifthook-properties-swiftclass.md "frooky.schema.json#/definitions/swiftHook/properties/swiftClass")

### swiftClass Type

`string`

## symbol

Swift method name

`symbol`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-swifthook-properties-symbol.md "frooky.schema.json#/definitions/swiftHook/properties/symbol")

### symbol Type

`string`

## module

Swift module name (optional)

`module`

* is optional

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-swifthook-properties-module.md "frooky.schema.json#/definitions/swiftHook/properties/module")

### module Type

`string`

## debug

Enable verbose logging

`debug`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-debugproperty.md "frooky.schema.json#/definitions/swiftHook/properties/debug")

### debug Type

`boolean`
