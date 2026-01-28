# Untitled object in frooky Configuration Schema

```txt
frooky-config.schema.json#/definitions/javaMethods/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky-config.schema.json\*](frooky-config.schema.json "open original schema") |

## items Type

`object` ([Details](frooky-config-definitions-javamethods-items.md))

# items Properties

| Property                | Type     | Required | Nullable       | Defined by                                                                                                                                                        |
| :---------------------- | :------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [name](#name)           | `string` | Required | cannot be null | [frooky Configuration](frooky-config-definitions-javamethods-items-properties-name.md "frooky-config.schema.json#/definitions/javaMethods/items/properties/name") |
| [overloads](#overloads) | `array`  | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-javaoverloads.md "frooky-config.schema.json#/definitions/javaMethods/items/properties/overloads")                |

## name

Method name

`name`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-javamethods-items-properties-name.md "frooky-config.schema.json#/definitions/javaMethods/items/properties/name")

### name Type

`string`

## overloads

Specify exact method signatures for overloaded methods

`overloads`

* is optional

* Type: `object[]` ([Details](frooky-config-definitions-javaoverloads-items.md))

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-javaoverloads.md "frooky-config.schema.json#/definitions/javaMethods/items/properties/overloads")

### overloads Type

`object[]` ([Details](frooky-config-definitions-javaoverloads-items.md))
