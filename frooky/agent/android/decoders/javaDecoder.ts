import type Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { ArrayDecoder } from "./arrayDecoder";
import { getJavaInstanceDecoder } from "./registry";

const LongDecoder: Decoder<Java.Wrapper> = {
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

/**
 * Resolve the concrete Decoder for `input` under `param`.
 * Called only on the first invocation for a given Param; the result is cached
 * on `param.decoder` so subsequent calls skip this dispatch entirely.
 */
function resolveDecoder(input: Java.Wrapper, param: Param): Decoder<Java.Wrapper> {
  // Custom decoder override via options
  const custom = param.options?.decoder;
  if (custom) {
    return getJavaInstanceDecoder(custom);
  }

  // Java array
  if (param.type.startsWith("[")) {
    return ArrayDecoder;
  }

  // long arrives as a wrapper object
  if (param.type === "long") {
    return LongDecoder;
  }

  // Object types: use the actual runtime class so interface-typed params are
  // decoded by the concrete implementation's decoder.
  if (typeof input === "object") {
    const implementationType = input.$className;
    if (param.type !== implementationType) {
      param.implementationType = implementationType;
    }
    return getJavaInstanceDecoder(implementationType);
  }

  // Primitive JS value (already converted by Frida)
  return PrimitiveDecoder;
}

export const JavaDecoder: Decoder<Java.Wrapper> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => {
    // Null input: no resolution needed, don't cache (we have no type signal)
    if (input == null) {
      return { type: param.implementationType ?? param.type, name: param.name, value: null };
    }

    // Fast path: a decoder was already resolved for this Param
    const cached = param.decoder;
    if (cached) {
      return cached.decode(input, param);
    }

    // Slow path: resolve once, cache on the Param, and delegate
    const decoder = resolveDecoder(input, param);
    param.decoder = decoder;
    return decoder.decode(input, param);
  },
};
