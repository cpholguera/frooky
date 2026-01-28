# Untitled object in frooky Configuration Schema

```txt
frooky-config.schema.json#/definitions/nativeArgumentDescriptor
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [frooky-config.schema.json\*](frooky-config.schema.json "open original schema") |

## nativeArgumentDescriptor Type

`object` ([Details](frooky-config-definitions-nativeargumentdescriptor.md))

# nativeArgumentDescriptor Properties

| Property                    | Type      | Required | Nullable       | Defined by                                                                                                                                                                                    |
| :-------------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [name](#name)               | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-name.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/name")               |
| [type](#type)               | `string`  | Required | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-type.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/type")               |
| [length](#length)           | `integer` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-length.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/length")           |
| [lengthInArg](#lengthinarg) | `integer` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-lengthinarg.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/lengthInArg") |
| [direction](#direction)     | `string`  | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-direction.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/direction")     |
| [returnValue](#returnvalue) | `boolean` | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-returnvalue.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/returnValue") |
| [filter](#filter)           | `array`   | Optional | cannot be null | [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-filter.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/filter")           |

## name



`name`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-name.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/name")

### name Type

`string`

## type

Native C/C++ types and iOS Foundation types

`type`

* is required

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-type.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/type")

### type Type

`string`

### type Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"string"`       |             |
| `"int32"`        |             |
| `"uint32"`       |             |
| `"int64"`        |             |
| `"pointer"`      |             |
| `"bytes"`        |             |
| `"bool"`         |             |
| `"double"`       |             |
| `"CFData"`       |             |
| `"CFDictionary"` |             |

## length

Fixed byte length for 'bytes' type

`length`

* is optional

* Type: `integer`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-length.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/length")

### length Type

`integer`

### length Constraints

**minimum**: the value of this number must greater than or equal to: `1`

## lengthInArg

Argument index containing the length

`lengthInArg`

* is optional

* Type: `integer`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-lengthinarg.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/lengthInArg")

### lengthInArg Type

`integer`

### lengthInArg Constraints

**minimum**: the value of this number must greater than or equal to: `0`

## direction

Parameter direction (out = read after return)

`direction`

* is optional

* Type: `string`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-direction.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/direction")

### direction Type

`string`

### direction Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value   | Explanation |
| :------ | :---------- |
| `"in"`  |             |
| `"out"` |             |

## returnValue

Capture as return value

`returnValue`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-returnvalue.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/returnValue")

### returnValue Type

`boolean`

## filter

Only capture when value matches these patterns

`filter`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [frooky Configuration](frooky-config-definitions-nativeargumentdescriptor-properties-filter.md "frooky-config.schema.json#/definitions/nativeArgumentDescriptor/properties/filter")

### filter Type

`string[]`
