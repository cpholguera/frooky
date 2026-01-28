# Untitled object in frooky JSON API Schema

```txt
frooky.schema.json#/definitions/javaHookCore
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky.schema.json\*](frooky.schema.json "open original schema") |

## javaHookCore Type

`object` ([Details](frooky-definitions-javahookcore.md))

not

* [Untitled undefined type in frooky JSON API](frooky-definitions-javahookcore-not.md "check type definition")

# javaHookCore Properties

| Property            | Type     | Required | Nullable       | Defined by                                                                                                                             |
| :------------------ | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------- |
| [class](#class)     | `string` | Required | cannot be null | [frooky JSON API](frooky-definitions-javahookcore-properties-class.md "frooky.schema.json#/definitions/javaHookCore/properties/class") |
| [methods](#methods) | `array`  | Required | cannot be null | [frooky JSON API](frooky-definitions-javamethods.md "frooky.schema.json#/definitions/javaHookCore/properties/methods")                 |

## class

Fully qualified Java/Kotlin class name

`class`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-javahookcore-properties-class.md "frooky.schema.json#/definitions/javaHookCore/properties/class")

### class Type

`string`

## methods

Array of methods to hook

`methods`

* is required

* Type: `object[]` ([Details](frooky-definitions-javamethods-items.md))

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-javamethods.md "frooky.schema.json#/definitions/javaHookCore/properties/methods")

### methods Type

`object[]` ([Details](frooky-definitions-javamethods-items.md))

### methods Constraints

**minimum number of items**: the minimum number of items for this array is: `1`
