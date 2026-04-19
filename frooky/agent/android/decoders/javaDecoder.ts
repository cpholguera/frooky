import type Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { getJavaInstanceDecoder } from "./registry";

// Decode a Java long (arrives as an object wrapping a 64-bit value in Frida)
function decodeLong(input: Java.Wrapper): string | number {
  return input?.toString?.() ?? String(input);
}

// Decode a Java array based on its JNI type signature (e.g. "[I", "[Z", "[Ljava.lang.String;")
function decodeJavaArray(input: Java.Wrapper, param: Param): unknown[] {
  const element = param.type.substring(1); // strip leading '['
  const len = input.length;
  const out: unknown[] = new Array(len);

  switch (element) {
    case "Z": // boolean[]
    case "B": // byte[]
    case "C": // char[]
    case "S": // short[]
    case "I": // int[]
    case "F": // float[]
    case "D": // double[]
      for (let i = 0; i < len; i++) out[i] = input[i];
      return out;

    case "J": // long[]
      for (let i = 0; i < len; i++) out[i] = decodeLong(input[i]);
      return out;

    default: {
      // Object array: "[Ljava.lang.String;" or nested "[[I"
      if (element.startsWith("[")) {
        // nested array
        for (let i = 0; i < len; i++) {
          out[i] = input[i] == null ? null : decodeJavaArray(input[i], param);
        }
        return out;
      }
      // "Lfully.qualified.ClassName;" -> strip L and ;
      const className = element.startsWith("L") && element.endsWith(";") ? element.substring(1, element.length - 1) : element;

      for (let i = 0; i < len; i++) {
        const el = input[i];
        if (el == null) {
          out[i] = null;
        } else if (className === "java.lang.String") {
          out[i] = el.toString();
        } else {
          // recurse through the registry for complex instance types
          out[i] = getJavaInstanceDecoder(className).decode(el, { ...param, type: className });
        }
      }
      return out;
    }
  }
}

export const JavaDecoder: Decoder = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    // use the custom decoder if set
    if (param.options?.decoder) {
      return getJavaInstanceDecoder(param.options.decoder).decode(input, param);
    }

    // it no input is set, return null
    if (input == null) {
      return { type: param.implementationType ?? param.type, name: param.name, value: null };
    }

    const javaScriptType = typeof input;
    if (javaScriptType === "object") {
      // primitive java arrays
      if (param.type[0] === "[") {
        return {
          type: param.type,
          name: param.name,
          value: decodeJavaArray(input, param),
        };
      }

      // long is converted to an object
      if (param.type === "long") {
        return {
          type: param.type,
          name: param.name,
          value: decodeLong(input),
        };
      }

      // Decode all complex java types such as "lang.java.Integer", "java.util.Date", "my.app.MyClass" etc.
      // If the actual implementation is different from the parameter type, we set the implementation type
      // This happens when an interface is used in the parameter declaration but the actual implementation is different
      const implementationType = input.$className;
      if (param.type !== implementationType) {
        param.implementationType = implementationType;
      }
      return getJavaInstanceDecoder(implementationType).decode(input, param);
    }

    // Primitive JS value (already converted by Frida): number, boolean, string etc.
    return {
      type: param.type,
      name: param.name,
      value: input,
    };
  },
};
