import type { Param } from "../../shared/hook/parameter";
import type { NativeParam } from "../hook/nativeParameter";
import type { DecodedValue, Decoder } from "./baseDecoder";
import { getNativeDecoder } from "./nativeDecoderRegistry";
import { normalizeNativeType } from "./nativeTypeNormalizer";

export const FallbackNativeDecoder: Decoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, param: Param): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: `<NO DECODER FOUND> ptr: ${input}`,
    };
  },
};

/**
 * Resolve the concrete Decoder for `input` under `param`.
 * Called only on the first invocation for a given Param; the result is cached
 * on `param.decoder` so subsequent calls skip this dispatch entirely.
 */
function lookupNativeDecoder(nativeParam: NativeParam): Decoder<NativePointer, NativeParam> {
  // first normalize the type to the Friday types
  const normalizedNativeType = normalizeNativeType(nativeParam);
  nativeParam.nativeType = normalizedNativeType;
  return getNativeDecoder(normalizedNativeType) ?? FallbackNativeDecoder;
}

export const NativeDecoder: Decoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, nativeParam: NativeParam, quickDecode = false): DecodedValue => {
    // a decoder was already resolved for this Param
    const cachedDecoder = nativeParam.decoder;
    if (cachedDecoder) {
      return cachedDecoder.decode(input, nativeParam, quickDecode);
    }

    // Resolve the decoder from the frooky parameter declaration and cache it
    const decoder = lookupNativeDecoder(nativeParam);
    nativeParam.decoder = decoder;
    return decoder.decode(input, nativeParam, quickDecode);
  },
};
