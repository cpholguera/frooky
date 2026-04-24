import type { NativeParam } from "../hook/nativeParameter";
import type { BaseDecoder, DecodedValue } from "./baseDecoder";
import { FallbackNativeDecoder, NativeFundamentalValueDecoder } from "./nativeBasicDecoder";
import { FUNDAMENTAL_TYPES, normalizeNativeType } from "./nativeTypeNormalizer";

/*
 * This is the registry for native decoders
 */
const nativeDecoderRegistry: Record<string, BaseDecoder<NativePointer, NativeParam>> = {
  // fundamental value decoders
  ...Object.fromEntries(FUNDAMENTAL_TYPES.map((type) => [type, NativeFundamentalValueDecoder])),
  // fundamental reference decoders
};

export const NativeDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (input: NativePointer, nativeParam: NativeParam, quickDecode = false): DecodedValue => {
    // a decoder was already resolved for this Param
    const cachedDecoder = nativeParam.decoder;
    if (cachedDecoder) {
      return cachedDecoder.decode(input, nativeParam, quickDecode);
    }

    // Resolve the decoder from the frooky parameter declaration and cache it
    const normalizedNativeType = normalizeNativeType(nativeParam);
    nativeParam.nativeType = normalizedNativeType;
    nativeParam.decoder = nativeDecoderRegistry[normalizedNativeType.type] ?? FallbackNativeDecoder;

    return nativeParam.decoder.decode(input, nativeParam, quickDecode);
  },
};
