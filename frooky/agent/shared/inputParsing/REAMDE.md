# YAML Parsing

The types in this folder are used for the public YAML files. They extend certain types which make it easier to write short hook files, but are cumbersome to parse internally.

**Example 1**: Method names**

In the YAML file we can use the following different ways to declare a method:

```yaml
hooks:
  - javaClass: android.security.AttestedKeyPair
    methods:
      - $init
      - getKeyPair


  - javaClass: android.security.AttestedKeyPair
    methods:
      - name: $init
      - name: getKeyPair
```

**Example 2**:  Parameters

```yaml
  - module: libssl.so
    functions:
      - symbol: EVP_EncryptInit_ex
        returnType: int
        params:
          - "EVP_CIPHER_CTX *"
          - ["const EVP_CIPHER *", type]
          - { type: "ENGINE *", name: "impl" }
```

These are all valid ways which give the user flexibility. But internally it introduces complexity when working with the different types.

We therefore only use objects internally (e.g. `{name: "getKeyPair"}` or `{ type: "ENGINE *", name: "impl" }`).

The types in this folder are therefore extending the internally used types for YAML parsing.

## Zod Schemas

This folder contains **automatically** generated [zod schemas](https://zod.dev/).

They are used to validate the frooky configuration during the initialization.

Run `npm run build:zodSchema` to build them manually.

> [!WARNING]
> Do not change these files, as they are automatically overwritten every time the frooky type changes.
