import Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { javaDecoderRegistry } from "./javaDecoderRegistry";

export const JavaLongDecoder: Decoder<Java.Wrapper> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => ({
    type: param.type,
    name: param.name,
    value: input == null ? null : input.toString(),
  }),
};

const PrimitiveDecoder: Decoder<Java.Wrapper> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => ({
    type: param.type,
    name: param.name,
    value: input as unknown as DecodedValue["value"],
  }),
};

const FallbackJavaDecoder: Decoder<Java.Wrapper> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    return {
      type: param.implementationType ?? param.type,
      name: param.name,
      value: input.toString(),
    };
  },
};

/**
 * Resolve the concrete Decoder for `input` under `param`.
 * Called only on the first invocation for a given Param; the result is cached
 * on `param.decoder` so subsequent calls skip this dispatch entirely.
 */
function resolveJavaDecoder(input: Java.Wrapper, param: Param): Decoder<Java.Wrapper> {
  // Java array
  if (param.type.startsWith("[")) {
    return javaDecoderRegistry["JavaArrayDecoder"]
  }

  // long arrives as a wrapper object
  if (param.type === "long") {
    return javaDecoderRegistry["JavaLongDecoder"]
  }

  // Object types: use the actual runtime class so interface-typed params are
  // decoded by the concrete implementation's decoder.
  if (typeof input === "object") {
    const implementationType = input.$className;
    if (param.type !== implementationType) {
      param.implementationType = implementationType;
    }
    return javaDecoderRegistry[implementationType]
  }

  // Primitive JS value (already converted by Frida)
  return PrimitiveDecoder;
}

export const JavaDecoder: Decoder<Java.Wrapper> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    // No input: no resolution needed, don't cache
    if (input == undefined) {
      return { type: param.implementationType ?? param.type, name: param.name, value: null };
    }

    // A decoder was already resolved for this Param
    const cachedDecoder = param.decoder;
    if (cachedDecoder) {
      return cachedDecoder.decode(input, param);
    }

    // Resolve once and cache it
    const decoder = resolveJavaDecoder(input, param);
    param.decoder = decoder;
    return decoder.decode(input, param);
  },
};
