import { BaseDecoder, DecodedValue, DecoderSettings } from "../../shared";
import { NativeDecodableType } from "./nativeDecodableTypes";
import { NativeFallbackDecoder } from "./nativeFallbackDecoder";
import { NativeReferenceDecoder } from "./nativeReferenceDecoder";
import { buildNativeType } from "./nativeTypeNormalizer";
import { NativeValueDecoder } from "./nativeValueDecoder";

export const FUNDAMENTAL_TYPES = [
  "void",
  "int",
  "uint",
  "long",
  "ulong",
  "char",
  "uchar",
  "size_t",
  "ssize_t",
  "float",
  "double",
  "int8",
  "uint8",
  "int16",
  "uint16",
  "int32",
  "uint32",
  "int64",
  "uint64",
  "bool",
] as const;
export type FundamentalType = (typeof FUNDAMENTAL_TYPES)[number];

/*
 * This is the registry for native decoders
 */
const nativeDecoderRegistry: Record<string, BaseDecoder<NativePointer, NativeDecodableType>> = {
  // fundamental value decoders
  ...Object.fromEntries(FUNDAMENTAL_TYPES.map((type) => [type, NativeValueDecoder])),
  // fundamental reference decoder
  pointer: NativeReferenceDecoder,
  // other complex decoders
};

export const NativeDecoder: BaseDecoder<NativePointer, NativeDecodableType> = {
  decode: (value: NativePointer, type: NativeDecodableType, decoderSetting: DecoderSettings, args?: any[]): DecodedValue => {
    // a decoder was already resolved for this Param
    const cachedDecoder = type.decoder;
    if (cachedDecoder) {
      return cachedDecoder.decode(value, type, decoderSetting, args);
    }

    // Resolve the decoder from the frooky parameter declaration and cache it
    const normalizedNativeType = buildNativeType(type);
    type.nativeType = normalizedNativeType;
    type.decoder = nativeDecoderRegistry[normalizedNativeType.type] ?? NativeFallbackDecoder;

    return type.decoder.decode(value, type, decoderSetting, args);
  },
};
