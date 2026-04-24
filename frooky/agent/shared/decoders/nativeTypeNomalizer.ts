import type { Param } from "../hook/parameter";

export type FundamentalType = "void" | "int" | "uint" | "long" | "ulong" | "char" | "uchar" | "size_t" | "ssize_t" | "float" | "double" | "int8" | "uint8" | "int16" | "uint16" | "int32" | "uint32" | "int64" | "uint64" | "bool";

export interface NativeType {
  type: "pointer" | FundamentalType;
  pointee?: FundamentalType | string;
  depth?: number;
}

// small helper
function t(type: FundamentalType): NativeType {
  return { type };
}

const FUNDAMENTAL_TYPE_ALIASES: Record<string, NativeType> = {
  // --- void ---
  void: t("void"),

  // --- bool ---
  bool: t("bool"),
  _Bool: t("bool"),
  boolean: t("bool"),

  // --- char / uchar ---
  char: t("char"),
  schar: t("char"),
  "signed char": t("char"),

  uchar: t("uchar"),
  "unsigned char": t("uchar"),

  // --- int8 / uint8 ---
  int8: t("int8"),
  int8_t: t("int8"),

  uint8: t("uint8"),
  uint8_t: t("uint8"),

  // --- int16 / uint16 ---
  int16: t("int16"),
  int16_t: t("int16"),
  short: t("int16"),
  "signed short": t("int16"),
  "short int": t("int16"),
  "signed short int": t("int16"),

  uint16: t("uint16"),
  uint16_t: t("uint16"),
  ushort: t("uint16"),
  "unsigned short": t("uint16"),
  "unsigned short int": t("uint16"),

  // --- int32 / uint32 ---
  int32: t("int32"),
  int32_t: t("int32"),

  uint32: t("uint32"),
  uint32_t: t("uint32"),

  // --- int / uint ---
  int: t("int"),
  signed: t("int"),
  "signed int": t("int"),

  uint: t("uint"),
  unsigned: t("uint"),
  "unsigned int": t("uint"),

  // --- int64 / uint64 ---
  int64: t("int64"),
  int64_t: t("int64"),
  "long long": t("int64"),
  "signed long long": t("int64"),
  "long long int": t("int64"),

  uint64: t("uint64"),
  uint64_t: t("uint64"),
  "unsigned long long": t("uint64"),
  "unsigned long long int": t("uint64"),

  // --- long / ulong ---
  long: t("long"),
  llong: t("int64"),
  "signed long": t("long"),
  "long int": t("long"),

  ulong: t("ulong"),
  ullong: t("uint64"),
  "unsigned long": t("ulong"),
  "unsigned long int": t("ulong"),

  // --- size_t / ssize_t ---
  size_t: t("size_t"),
  ssize_t: t("ssize_t"),

  // --- float / double ---
  float: t("float"),
  double: t("double"),
};

/**
 * Normalizes a C/C++ type string into a canonical key for lookup and comparison.
 * Handles pointer declarations by removing spaces around `*` and collapsing
 * remaining whitespace (e.g. for multi-word types like `unsigned char`).
 *
 * @param type - The C/C++ type string to normalize.
 * @returns The normalized type string.
 *
 * @example
 * normalize("char *")       // "char*"
 * normalize("char* ")       // "char*"
 * normalize("unsigned char **") // "unsigned char**"
 */

function createPointerType(normalizedType: string, param: Param): NativeType {
  return {
    type: "pointer",
    pointee: "char",
    depth: 2,
  };
}

function normalizePointerTypes(type: string): string {
  return type
    .trim()
    .toLowerCase()
    .replace(/\s*\*\s*/g, "*")
    .replace(/\s+/g, " ");
}

export function normalizeNativeType(param: Param): NativeType {
  const normalizedType = normalizePointerTypes(param.type);
  if (normalizedType.endsWith("*")) {
    // type pointer
    return createPointerType(normalizedType, param);
  } else {
    // fundamental type or invalid type
    return FUNDAMENTAL_TYPE_ALIASES[normalizedType];
  }
}
