# Untitled object in frooky JSON API Schema

```txt
frooky.schema.json#/definitions/javaHook/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky.schema.json\*](frooky.schema.json "open original schema") |

## 1 Type

`object` ([Details](frooky-definitions-javahook-allof-1.md))

# 1 Properties

| Property                        | Type      | Required | Nullable       | Defined by                                                                                                                                             |
| :------------------------------ | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| [maxFrames](#maxframes)         | `integer` | Optional | cannot be null | [frooky JSON API](frooky-definitions-javahook-allof-1-properties-maxframes.md "frooky.schema.json#/definitions/javaHook/allOf/1/properties/maxFrames") |
| [prerequisites](#prerequisites) | `array`   | Optional | cannot be null | [frooky JSON API](frooky-definitions-javamethods.md "frooky.schema.json#/definitions/javaHook/allOf/1/properties/prerequisites")                       |

## maxFrames

Stack trace depth

`maxFrames`

* is optional

* Type: `integer`

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-javahook-allof-1-properties-maxframes.md "frooky.schema.json#/definitions/javaHook/allOf/1/properties/maxFrames")

### maxFrames Type

`integer`

### maxFrames Constraints

**minimum**: the value of this number must greater than or equal to: `1`

## prerequisites

Array of methods to hook

`prerequisites`

* is optional

* Type: `object[]` ([Details](frooky-definitions-javamethods-items.md))

* cannot be null

* defined in: [frooky JSON API](frooky-definitions-javamethods.md "frooky.schema.json#/definitions/javaHook/allOf/1/properties/prerequisites")

### prerequisites Type

`object[]` ([Details](frooky-definitions-javamethods-items.md))

### prerequisites Constraints

**minimum number of items**: the minimum number of items for this array is: `1`
