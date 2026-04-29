import type { BaseDecoder } from "../../shared/decoders/baseDecoder";
import type { DecodedValue } from "../../shared/decoders/decodedValue";
import type { NativeParam } from "./nativeDecodableTypes";
import { NativeFallbackDecoder } from "./nativeFallbackDecoder";
import { NativeReferenceDecoder } from "./nativeReferenceDecoder";
import { normalizeNativeType } from "./nativeTypeNormalizer";
import { NativeValueDecoder } from "./nativeValueDecoder";

export const FUNDAMENTAL_TYPES = ["void", "int", "uint", "long", "ulong", "char", "uchar", "size_t", "ssize_t", "float", "double", "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "bool"] as const;
export type FundamentalType = (typeof FUNDAMENTAL_TYPES)[number];

/*
 * This is the registry for native decoders
 */
const nativeDecoderRegistry: Record<string, BaseDecoder<NativePointer, NativeParam>> = {
  // fundamental value decoders
  ...Object.fromEntries(FUNDAMENTAL_TYPES.map((type) => [type, NativeValueDecoder])),
  // fundamental reference decoder
  pointer: NativeReferenceDecoder,
  // other complex decoders
};

export const NativeDecoder: BaseDecoder<NativePointer, NativeParam> = {
  decode: (input, nativeParam): DecodedValue => {
    // a decoder was already resolved for this Param
    const cachedDecoder = nativeParam.decoder;
    if (cachedDecoder) {
      return cachedDecoder.decode(input, nativeParam);
    }

    // Resolve the decoder from the frooky parameter declaration and cache it
    const normalizedNativeType = normalizeNativeType(nativeParam);
    nativeParam.nativeType = normalizedNativeType;
    nativeParam.decoder = nativeDecoderRegistry[normalizedNativeType.type] ?? NativeFallbackDecoder;

    return nativeParam.decoder.decode(input, nativeParam);
  },
};
