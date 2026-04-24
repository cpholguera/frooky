import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { getNativeDecoder } from "./nativeDecoderRegistry";
import { normalizeNativeType } from "./nativeTypeNomalizer";

export const FallbackNativeDecoder: Decoder<NativePointer> = {
  decode: (input: NativePointer, param: Param): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: "<NO DECODER FOUND>",
    };
  },
};

/**
 * Resolve the concrete Decoder for `input` under `param`.
 * Called only on the first invocation for a given Param; the result is cached
 * on `param.decoder` so subsequent calls skip this dispatch entirely.
 */
function lookupNativeDecoder(param: Param): Decoder<NativePointer> {
  // first normalize the type to the Friday types
  const normalizedType = normalizeNativeType(param);
  return getNativeDecoder(normalizedType) ?? FallbackNativeDecoder;
}

export const NativeDecoder: Decoder<NativePointer> = {
  decode: (input: NativePointer, param: Param, quickDecode = false): DecodedValue => {
    // a decoder was already resolved for this Param
    const cachedDecoder = param.decoder;
    if (cachedDecoder) {
      return cachedDecoder.decode(input, param);
    }

    // Resolve the decoder from the frooky parameter declaration and cache it
    const decoder = lookupNativeDecoder(param);
    param.decoder = decoder;
    return decoder.decode(input, param, quickDecode);
  },
};
