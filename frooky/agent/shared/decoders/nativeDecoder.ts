import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";

const basicTypeDecoderMap: Record<string, Decoder<NativePointer>> = {
  "int8_t":         { decode: (input, param) => ({ type: param.type, value: (input.toInt32() << 24) >> 24 }) },
  "uint8_t":        { decode: (input, param) => ({ type: param.type, value: input.toUInt32() & 0xff }) },
  "int16_t":        { decode: (input, param) => ({ type: param.type, value: (input.toInt32() << 16) >> 16 }) },
  "uint16_t":       { decode: (input, param) => ({ type: param.type, value: input.toUInt32() & 0xffff }) },
  "short":          { decode: (input, param) => ({ type: param.type, value: (input.toInt32() << 16) >> 16 }) },
  "unsigned short": { decode: (input, param) => ({ type: param.type, value: input.toUInt32() & 0xffff }) },
  "int32_t":        { decode: (input, param) => ({ type: param.type, value: input.toInt32() }) },
  "uint32_t":       { decode: (input, param) => ({ type: param.type, value: input.toUInt32() }) },
  "int":            { decode: (input, param) => ({ type: param.type, value: input.toInt32() }) },
  "unsigned int":   { decode: (input, param) => ({ type: param.type, value: input.toUInt32() }) },
  "void *":         { decode: (input, param) => ({ type: param.type, value: input }) },
  "int64_t":        { decode: (input, param) => ({ type: param.type, value: int64(input.toString()) }) },
  "uint64_t":       { decode: (input, param) => ({ type: param.type, value: uint64(input.toString()) }) },
  "long":           { decode: (input, param) => ({ type: param.type, value: int64(input.toString()) }) },
  "unsigned long":  { decode: (input, param) => ({ type: param.type, value: uint64(input.toString()) }) },
  "char *":         { decode: (input, param) => ({ type: param.type, value: input.readCString() }) },
  "char * (utf8)":  { decode: (input, param) => ({ type: param.type, value: input.readUtf8String() }) },
  "char16_t *":     { decode: (input, param) => ({ type: param.type, value: input.readUtf16String() }) },
  "char * (ansi)":  { decode: (input, param) => ({ type: param.type, value: input.readAnsiString() }) },
};


const FallbackNativeDecoder: Decoder<NativePointer> = {
  decode: (input: NativePointer, param: Param): DecodedValue => {
    return {
      type: param.type,
      name: param.name,
      value: input
    };
  },
};
/**
 * Resolve the concrete Decoder for `input` under `param`.
 * Called only on the first invocation for a given Param; the result is cached
 * on `param.decoder` so subsequent calls skip this dispatch entirely.
 */
function lookupNativeDecoder(param: Param): Decoder<NativePointer> {
  const decoder = basicTypeDecoderMap[param.type];
  if (!decoder) {
    return FallbackNativeDecoder;
  } else 
  return decoder;
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
