# Untitled object in frooky JSON API Schema

```txt
frooky.schema.json#/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky.schema.json\*](frooky.schema.json "open original schema") |

## items Type

`object` ([Details](frooky-items.md))

# items Properties

| Property              | Type     | Required | Nullable       | Defined by                                                                                             |
| :-------------------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------- |
| [category](#category) | `string` | Required | cannot be null | [frooky JSON API](frooky-items-properties-category.md "frooky.schema.json#/items/properties/category") |
| [hooks](#hooks)       | `array`  | Required | cannot be null | [frooky JSON API](frooky-items-properties-hooks.md "frooky.schema.json#/items/properties/hooks")       |

## category

OWASP MAS category

`category`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky JSON API](frooky-items-properties-category.md "frooky.schema.json#/items/properties/category")

### category Type

`string`

### category Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value          | Explanation |
| :------------- | :---------- |
| `"STORAGE"`    |             |
| `"CRYPTO"`     |             |
| `"AUTH"`       |             |
| `"NETWORK"`    |             |
| `"PLATFORM"`   |             |
| `"CODE"`       |             |
| `"RESILIENCE"` |             |
| `"PRIVACY"`    |             |

## hooks



`hooks`

* is required

* Type: an array of merged types ([Details](frooky-items-properties-hooks-items.md))

* cannot be null

* defined in: [frooky JSON API](frooky-items-properties-hooks.md "frooky.schema.json#/items/properties/hooks")

### hooks Type

an array of merged types ([Details](frooky-items-properties-hooks-items.md))
