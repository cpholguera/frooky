# JSON Hook schemas

## 1. Basic Method Definitions

### 1.1 Single method as string

```json
{
  "class": "com.class",
  "method": "deleteAllData"
}
```

### 1.2 Methods array with string

```json
{
  "class": "com.class",
  "methods": [
    "deleteAllData"
  ]
}
```

### 1.3 Single method as object

```json
{
  "class": "com.class",
  "method": {
    "name": "deleteAllData"
  }
}
```

### 1.4 Methods array with an object

```json
{
  "class": "com.class",
  "methods": [
    {
      "name": "deleteAllData"
    }
  ]
}
```

## 2. Method Overloads

### 2.1 Overload with a single parameter array

```jsonc
{
  "class": "com.class",
  "method": {
    "name": "deleteAllData",
    "overload": "String" // type String
  }
}
```

### 2.2 Overload with a single parameter array

```jsonc
{
  "class": "com.class",
  "method": {
    "name": "deleteAllData",
    "overload": [ // type String[]
      "String",
      "Int"
    ]
  }
}
```

### 2.3 Overload with an Overload object and single param

```jsonc
{
  "class": "com.class",
  "method": {
    "name": "deleteAllData",
    "overload": { // type OverloadObject[]
      "param": "String",
    }
  }
}
```

### 2.4 Overload with an Overload object and a param array

```jsonc
{
  "class": "com.class",
  "method": {
    "name": "deleteAllData",
    "overload": { // type OverloadObject[]
      "params": [
        "String",
        "Int"
      ]
    }
  }
}
```

### 2.5 Four overloads as objects and arrays

```jsonc 
{
  "class": "com.class",
  "method": {
    "name": "deleteAllData",
    "overloads": [ // type OverloadObject[]
      "String",
      [
        "String",
        "Int"
      ],
      {
        "param": "String"
      },
      {
        "params": [
          "String",
          "Int"
        ]
      }
    ]
  }
}
```

## 3. Prerequisites

### 3.1 Single prerequisite with method string

```json
{
  "class": "com.class",
  "method": "deleteAllData",
  "prerequisite": {
    "class": "android.webkit.WebStorage",
    "method": "getInstance"
  }
}
```

### 3.2 Prerequisites array

```json
{
  "class": "com.class",
  "method": "deleteAllData",
  "prerequisites": [
    {
      "class": "android.webkit.WebStorage",
      "method": "getInstance"
    }
  ]
}
```

### 3.3 Prerequisite with method object

```json
{
  "class": "com.class",
  "method": "deleteAllData",
  "prerequisite": {
    "class": "android.webkit.WebStorage",
    "method": {
      "name": "getInstance"
    }
  }
}
```

### 3.4 Prerequisite with method overload

```json
{
  "class": "com.class",
  "method": "deleteAllData",
  "prerequisite": {
    "class": "android.webkit.WebStorage",
    "method": {
      "name": "getInstance",
      "overload": "..."
    }
  }
}
```