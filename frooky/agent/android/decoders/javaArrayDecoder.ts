import type Java from "frida-java-bridge";
import type { BaseDecoder, DecodedValue } from "../../shared/decoders/baseDecoder";
import type { JavaParam } from "../hook/javaParam";
import { JavaDecoder } from "./javaDecoder";

const PRIMITIVE_TYPES = new Set(["int", "long", "short", "byte", "char", "boolean", "float", "double"]);

/**
 * Convert a JNI array element signature into a JavaParam-compatible `type` string.
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
  if (element.startsWith("[")) {
    return element;
  }
  if (element.startsWith("L") && element.endsWith(";")) {
    return element.substring(1, element.length - 1).replace(/\//g, ".");
  }
  return element;
}

export const JavaArrayDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (input: Java.Wrapper, param: JavaParam): DecodedValue => {
    const signature = param.implementationType ?? param.type;
    const elementSignature = signature.startsWith("[") ? signature.substring(1) : signature;
    const elementType = elementTypeFromSignature(elementSignature);

    let value: unknown[];

    if (PRIMITIVE_TYPES.has(elementType)) {
      // Frida unwraps primitive arrays to a JS-iterable directly
      value = Array.from(input as unknown as ArrayLike<unknown>);
    } else {
      // complex java types
      const elementParam: JavaParam = {
        ...param,
        type: elementType,
        decoder: undefined, // prevent inheriting parent's cached decoder
      };
      const len = input.length;
      value = new Array(len);
      for (let i = 0; i < len; i++) {
        const el = input[i];
        value[i] = el == null ? null : JavaDecoder.decode(el, elementParam).value;
      }
    }

    return {
      type: param.type,
      name: param.name,
      value,
    };
  },
};
