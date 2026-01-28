# Untitled object in frooky Configuration Schema

```txt
frooky-config.schema.json#/definitions/javaHookCore
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky-config.schema.json\*](frooky-config.schema.json "open original schema") |

## javaHookCore Type

`object` ([Details](frooky-config-definitions-javahookcore.md))

not

* [Untitled undefined type in frooky Configuration](frooky-config-definitions-javahookcore-not.md "check type definition")

# javaHookCore Properties

| Property            | Type     | Required | Nullable       | Defined by                                                                                                                                                |
| :------------------ | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [class](#class)     | `string` | Required | cannot be null | [frooky Configuration](frooky-config-definitions-javahookcore-properties-class.md "frooky-config.schema.json#/definitions/javaHookCore/properties/class") |
| [methods](#methods) | `array`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-javamethods.md "frooky-config.schema.json#/definitions/javaHookCore/properties/methods")                 |

## class

Fully qualified Java/Kotlin class name

`class`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-javahookcore-properties-class.md "frooky-config.schema.json#/definitions/javaHookCore/properties/class")

### class Type

`string`

## methods

Array of methods to hook

`methods`

* is required

* Type: `object[]` ([Details](frooky-config-definitions-javamethods-items.md))

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-javamethods.md "frooky-config.schema.json#/definitions/javaHookCore/properties/methods")

### methods Type

`object[]` ([Details](frooky-config-definitions-javamethods-items.md))

### methods Constraints

**minimum number of items**: the minimum number of items for this array is: `1`
