import type Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { JavaDecoder } from "./javaDecoder";

// ---------------------------------------------------------------------------
// Per-Param cache: the sub-Param used for elements of this array.
// Built once from the array's JNI signature and stashed on the Param via a
// private symbol so subsequent calls skip signature parsing entirely.
// JavaDecoder will populate subParam.decoder on the first element it sees.
// ---------------------------------------------------------------------------
const SUB_PARAM_KEY: unique symbol = Symbol("ArrayDecoder.subParam");
type ParamWithSub = Param & { [SUB_PARAM_KEY]?: Param };

/**
 * Convert a JNI array element signature into a Param-compatible `type` string.
 *   "I"                  -> "int"
 *   "J"                  -> "long"
 *   "Ljava/lang/String;" -> "java.lang.String"
 *   "Ljava.lang.String;" -> "java.lang.String"
 *   "[I"                 -> "[I"   (nested array, kept as-is)
 */
function elementTypeFromSignature(element: string): string {
  if (element.length === 1) {
    switch (element) {
      case "Z":
        return "boolean";
      case "B":
        return "byte";
      case "C":
        return "char";
      case "S":
        return "short";
      case "I":
        return "int";
      case "J":
        return "long";
      case "F":
        return "float";
      case "D":
        return "double";
    }
  }
  // Nested array — keep the JNI signature so JavaDecoder dispatches back to ArrayDecoder
  if (element.startsWith("[")) {
    return element;
  }
  // Object: "Lfoo/bar/Baz;" or "Lfoo.bar.Baz;"
  if (element.startsWith("L") && element.endsWith(";")) {
    return element.substring(1, element.length - 1).replace(/\//g, ".");
  }
  return element;
}

function getOrBuildSubParam(param: Param): Param {
  const p = param as ParamWithSub;
  let sub = p[SUB_PARAM_KEY];
  if (sub === undefined) {
    const element = param.type.substring(1); // strip leading '['
    sub = { ...param, type: elementTypeFromSignature(element) };
    // Ensure no stale cached decoder/implementationType bleeds in from the parent
    sub.decoder = undefined;
    sub.implementationType = undefined;
    p[SUB_PARAM_KEY] = sub;
  }
  return sub;
}

export const ArrayDecoder: Decoder = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    if (input == null) {
      return { type: param.implementationType ?? param.type, name: param.name, value: null };
    }

    const subParam = getOrBuildSubParam(param);
    const len = input.length;
    const out = new Array(len);

    // First element resolves and caches the decoder on subParam via JavaDecoder;
    // all subsequent elements hit JavaDecoder's fast path.
    for (let i = 0; i < len; i++) {
      const el = input[i];
      out[i] = el == null ? null : JavaDecoder.decode(el, subParam).value;
    }

    return {
      type: param.type,
      name: param.name,
      value: out,
    };
  },
};
