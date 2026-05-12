export const FRIDA_FUNDAMENTAL_TYPES = [
  "void",
  "bool",
  "char",
  "uchar",
  "int8",
  "uint8",
  "int16",
  "uint16",
  "int32",
  "uint32",
  "int",
  "uint",
  "int64",
  "uint64",
  "long",
  "ulong",
  "size_t",
  "ssize_t",
  "float",
  "double",
] as const;

const FRIDA_FUNDAMENTAL_TYPE_ALIASES: Record<string, FridaFundamentalType> = Object.fromEntries(
  [
    ["void", ["void"]],
    ["bool", ["bool", "_Bool", "boolean"]],
    ["char", ["char", "schar", "signed char"]],
    ["uchar", ["uchar", "unsigned char"]],
    ["int8", ["int8", "int8_t"]],
    ["uint8", ["uint8", "uint8_t"]],
    ["int16", ["int16", "int16_t", "short", "signed short", "short int", "signed short int"]],
    ["uint16", ["uint16", "uint16_t", "ushort", "unsigned short", "unsigned short int"]],
    ["int32", ["int32", "int32_t"]],
    ["uint32", ["uint32", "uint32_t"]],
    ["int", ["int", "signed", "signed int"]],
    ["uint", ["uint", "unsigned", "unsigned int"]],
    ["int64", ["int64", "int64_t", "long long", "signed long long", "long long int", "llong"]],
    ["uint64", ["uint64", "uint64_t", "unsigned long long", "unsigned long long int", "ullong"]],
    ["long", ["long", "signed long", "long int"]],
    ["ulong", ["ulong", "unsigned long", "unsigned long int"]],
    ["size_t", ["size_t"]],
    ["ssize_t", ["ssize_t"]],
    ["float", ["float"]],
    ["double", ["double"]],
  ].flatMap(([fridaType, aliases]) => (aliases as string[]).map((alias) => [alias, fridaType as FridaFundamentalType])),
);

/**
 * Constructs a {@link NativeFridaValue} representing a C/C++ pointer type from a
 * normalized type string (e.g. `"char*"`, `"unsigned char**"`).
 *
 * The base type (left of the first `*`) is resolved through
 * {@link FRIDA_FUNDAMENTAL_TYPE_ALIASES} to its canonical form. Unknown base types
 * (e.g. structs) are passed through as-is.
 *
 * @param normalizedType - A normalized pointer type string as produced by
 *   {@link normalizePointerTypes}, e.g. `"char*"` or `"unsigned char**"`.
 * @returns A {@link NativeFridaValue} with `type: "pointer"`, a resolved `pointee`,
 *   and a `depth` equal to the number of indirection levels.
 *
 * @example
 * createPointerType("char*")
 *   => { type: "pointer", pointee: "char", depth: 1 }
 *
 * createPointerType("unsigned char**")
 *   => { type: "pointer", pointee: "uchar", depth: 2 }
 *
 * createPointerType("SomeStruct*")
 *   => { type: "pointer", pointee: "SomeStruct", depth: 1 }
 */
function createPointerType(normalizedType: string): FridaReferenceType {
  const starIndex = normalizedType.indexOf("*");
  const baseType = normalizedType.slice(0, starIndex).trim();
  const depth = normalizedType.length - starIndex;

  const pointee = FRIDA_FUNDAMENTAL_TYPE_ALIASES[baseType] ?? baseType;

  return { pointee, depth };
}

/**
 * normalizes the input string from the frooky config to the canonical Frida type
 * which are mapped to the types listed in {@link https://frida.re/docs/javascript-api/#nativefunction}
 *
 * @example
 * normalizeNativeType("char ")
 *   => { type: "char"}
 *
 * normalizeNativeType(" long long int ")
 *   => { type: "uint64"}
 *
 * normalizeNativeType("_Bool")
 *   => { type: "bool"}
 *
 * normalizeNativeType("boolean")
 *   => { type: "bool"}
 *
 * normalizeNativeType(" char ** ")
 *   => { type: "pointer", pointee: "char", depth: 2 }
 *
 */
export function parseNativeFridaType(type: string): FridaFundamentalType | FridaReferenceType | undefined {
  // basic normalization
  const normalized = type
    .trim()
    .toLowerCase()
    .replace(/\s*\*\s*/g, "*")
    .replace(/\s+/g, " ");

  if (normalized.endsWith("*")) {
    // type pointer
    return createPointerType(normalized);
  }
  // type fundamental
  return FRIDA_FUNDAMENTAL_TYPE_ALIASES[normalized];
}

export type FridaFundamentalType = (typeof FRIDA_FUNDAMENTAL_TYPES)[number];

export type FridaReferenceType = { pointee: FridaFundamentalType; depth: number };
