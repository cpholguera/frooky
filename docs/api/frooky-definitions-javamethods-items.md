# Untitled object in frooky JSON API Schema

```txt
frooky.schema.json#/definitions/javaMethods/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky.schema.json\*](frooky.schema.json "open original schema") |

## items Type

`object` ([Details](frooky-definitions-javamethods-items.md))

# items Properties

| Property                | Type     | Required | Nullable       | Defined by                                                                                                                                     |
| :---------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------- |
| [name](#name)           | `string` | Required | cannot be null | [frooky JSON API](frooky-definitions-javamethods-items-properties-name.md "frooky.schema.json#/definitions/javaMethods/items/properties/name") |
| [overloads](#overloads) | `array`  | Optional | cannot be null | [frooky JSON API](frooky-definitions-javaoverloads.md "frooky.schema.json#/definitions/javaMethods/items/properties/overloads")                |

## name

Method name

`name`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-javamethods-items-properties-name.md "frooky.schema.json#/definitions/javaMethods/items/properties/name")

### name Type

`string`

## overloads

Specify exact method signatures for overloaded methods

`overloads`

* is optional

* Type: `object[]` ([Details](frooky-definitions-javaoverloads-items.md))

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-javaoverloads.md "frooky.schema.json#/definitions/javaMethods/items/properties/overloads")

### overloads Type

`object[]` ([Details](frooky-definitions-javaoverloads-items.md))
