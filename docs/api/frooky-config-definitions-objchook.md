# Untitled object in frooky Configuration Schema

```txt
frooky-config.schema.json#/definitions/objcHook
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky-config.schema.json\*](frooky-config.schema.json "open original schema") |

## objcHook Type

`object` ([Details](frooky-config-definitions-objchook.md))

not

* [Untitled undefined type in frooky Configuration](frooky-config-definitions-objchook-not.md "check type definition")

# objcHook Properties

| Property              | Type      | Required | Nullable       | Defined by                                                                                                                                              |
| :-------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [native](#native)     | `boolean` | Required | cannot be null | [frooky Configuration](frooky-config-definitions-objchook-properties-native.md "frooky-config.schema.json#/definitions/objcHook/properties/native")     |
| [objClass](#objclass) | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-objchook-properties-objclass.md "frooky-config.schema.json#/definitions/objcHook/properties/objClass") |
| [symbol](#symbol)     | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-objchook-properties-symbol.md "frooky-config.schema.json#/definitions/objcHook/properties/symbol")     |
| [args](#args)         | `array`   | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargsarray.md "frooky-config.schema.json#/definitions/objcHook/properties/args")                  |
| [debug](#debug)       | `boolean` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-debugproperty.md "frooky-config.schema.json#/definitions/objcHook/properties/debug")                   |

## native



`native`

* is required

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-objchook-properties-native.md "frooky-config.schema.json#/definitions/objcHook/properties/native")

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

* defined in: [frooky Configuration](frooky-config-definitions-objchook-properties-objclass.md "frooky-config.schema.json#/definitions/objcHook/properties/objClass")

### objClass Type

`string`

## symbol

Objective-C method selector (e.g., 'dataTaskWithRequest:completionHandler:')

`symbol`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-objchook-properties-symbol.md "frooky-config.schema.json#/definitions/objcHook/properties/symbol")

### symbol Type

`string`

## args



`args`

* is optional

* Type: `object[]` ([Details](frooky-config-definitions-nativeargumentdescriptor.md))

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargsarray.md "frooky-config.schema.json#/definitions/objcHook/properties/args")

### args Type

`object[]` ([Details](frooky-config-definitions-nativeargumentdescriptor.md))

## debug

Enable verbose logging

`debug`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-debugproperty.md "frooky-config.schema.json#/definitions/objcHook/properties/debug")

### debug Type

`boolean`
