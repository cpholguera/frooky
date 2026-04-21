import type Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { JavaDecoder } from "./javaDecoder";

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

function buildElementParam(param: Param): Param {
  const element = param.type.substring(1); // strip leading '['
  const elementParam: Param = { ...param, type: elementTypeFromSignature(element) };
  elementParam.decoder = undefined;
  elementParam.implementationType = undefined;
  return elementParam;
}

export const ArrayDecoder: Decoder<Java.Wrapper> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    const elementParam = buildElementParam(param);
    const len = input.length;
    const out = new Array(len);

    for (let i = 0; i < len; i++) {
      const el = input[i];
      out[i] = el == null ? null : JavaDecoder.decode(el, elementParam).value;
    }

    return {
      type: param.type,
      name: param.name,
      value: out,
    };
  },
};
