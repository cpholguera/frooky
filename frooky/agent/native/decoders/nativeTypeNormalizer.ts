import { NativeParam } from "../hook/nativeParam";
import type { FundamentalType } from "./nativeDecoder";

export interface NativeType {
  type: "pointer" | FundamentalType;
  pointee?: FundamentalType | string;
  depth?: number;
}

// tiny little helper
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
 * Constructs a {@link NativeType} representing a C/C++ pointer type from a
 * normalized type string (e.g. `"char*"`, `"unsigned char**"`).
 *
 * The base type (left of the first `*`) is resolved through
 * {@link FUNDAMENTAL_TYPE_ALIASES} to its canonical form. Unknown base types
 * (e.g. struct names) are passed through as-is.
 *
 * @param normalizedType - A normalized pointer type string as produced by
 *   {@link normalizePointerTypes}, e.g. `"char*"` or `"unsigned char**"`.
 * @param param - The original {@link Param} associated with this type.
 * @returns A {@link NativeType} with `type: "pointer"`, a resolved `pointee`,
 *   and a `depth` equal to the number of indirection levels.
 *
 * @example
 * createPointerType("char*", param)
 * // { type: "pointer", pointee: "char", depth: 1 }
 *
 * createPointerType("unsigned char**", param)
 * // { type: "pointer", pointee: "uchar", depth: 2 }
 *
 * createPointerType("SomeStruct*", param)
 * // { type: "pointer", pointee: "SomeStruct", depth: 1 }
 */
function createPointerType(normalizedType: string): NativeType {
  // Count pointer depth and extract base type
  const starIndex = normalizedType.indexOf("*");
  const baseType = normalizedType.slice(0, starIndex).trim();
  const depth = (normalizedType.match(/\*/g) ?? []).length;

  // Resolve the base type through aliases
  const resolvedBase = FUNDAMENTAL_TYPE_ALIASES[baseType];
  const pointee: string = resolvedBase ? resolvedBase.type : baseType;

  return {
    type: "pointer",
    pointee,
    depth,
  };
}

export function normalizeNativeType(nativeParam: NativeParam): NativeType {
  // basic normalization
  const normalizedNativeType = nativeParam.type
    .trim()
    .toLowerCase()
    .replace(/\s*\*\s*/g, "*") // remove spaces around *
    .replace(/\s+/g, " "); // remove consecutive whitespace
  if (normalizedNativeType.endsWith("*")) {
    // type pointer
    return createPointerType(normalizedNativeType);
  } else {
    // fundamental type or invalid type
    return FUNDAMENTAL_TYPE_ALIASES[normalizedNativeType];
  }
}
