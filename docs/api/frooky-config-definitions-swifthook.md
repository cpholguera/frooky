# Untitled object in frooky Configuration Schema

```txt
frooky-config.schema.json#/definitions/swiftHook
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky-config.schema.json\*](frooky-config.schema.json "open original schema") |

## swiftHook Type

`object` ([Details](frooky-config-definitions-swifthook.md))

not

* [Untitled undefined type in frooky Configuration](frooky-config-definitions-swifthook-not.md "check type definition")

# swiftHook Properties

| Property                  | Type      | Required | Nullable       | Defined by                                                                                                                                                    |
| :------------------------ | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [native](#native)         | `boolean` | Required | cannot be null | [frooky Configuration](frooky-config-definitions-swifthook-properties-native.md "frooky-config.schema.json#/definitions/swiftHook/properties/native")         |
| [swiftClass](#swiftclass) | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-swifthook-properties-swiftclass.md "frooky-config.schema.json#/definitions/swiftHook/properties/swiftClass") |
| [symbol](#symbol)         | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-swifthook-properties-symbol.md "frooky-config.schema.json#/definitions/swiftHook/properties/symbol")         |
| [module](#module)         | `string`  | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-swifthook-properties-module.md "frooky-config.schema.json#/definitions/swiftHook/properties/module")         |
| [debug](#debug)           | `boolean` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-debugproperty.md "frooky-config.schema.json#/definitions/swiftHook/properties/debug")                        |

## native



`native`

* is required

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-swifthook-properties-native.md "frooky-config.schema.json#/definitions/swiftHook/properties/native")

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

* defined in: [frooky Configuration](frooky-config-definitions-swifthook-properties-swiftclass.md "frooky-config.schema.json#/definitions/swiftHook/properties/swiftClass")

### swiftClass Type

`string`

## symbol

Swift method name

`symbol`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-swifthook-properties-symbol.md "frooky-config.schema.json#/definitions/swiftHook/properties/symbol")

### symbol Type

`string`

## module

Swift module name (optional)

`module`

* is optional

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-swifthook-properties-module.md "frooky-config.schema.json#/definitions/swiftHook/properties/module")

### module Type

`string`

## debug

Enable verbose logging

`debug`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-debugproperty.md "frooky-config.schema.json#/definitions/swiftHook/properties/debug")

### debug Type

`boolean`
