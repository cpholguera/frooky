import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { nativeDecoderRegistry } from "./nativeDecoderRegistry";

const typeDecoderMap: Record<string, Decoder<NativePointer>> = {
  "int8_t":         { decode: (input, param) => ({ type: param.type, value: input.readS8() }) },
  "uint8_t":        { decode: (input, param) => ({ type: param.type, value: input.readU8() }) },
  "int16_t":        { decode: (input, param) => ({ type: param.type, value: input.readS16() }) },
  "uint16_t":       { decode: (input, param) => ({ type: param.type, value: input.readU16() }) },
  "short":          { decode: (input, param) => ({ type: param.type, value: input.readShort() }) },
  "unsigned short": { decode: (input, param) => ({ type: param.type, value: input.readUShort() }) },
  "int32_t":        { decode: (input, param) => ({ type: param.type, value: input.readS32() }) },
  "uint32_t":       { decode: (input, param) => ({ type: param.type, value: input.readU32() }) },
  "int":            { decode: (input, param) => ({ type: param.type, value: input.readInt() }) },
  "unsigned int":   { decode: (input, param) => ({ type: param.type, value: input.readUInt() }) },
  "float":          { decode: (input, param) => ({ type: param.type, value: input.readFloat() }) },
  "double":         { decode: (input, param) => ({ type: param.type, value: input.readDouble() }) },
  "void *":         { decode: (input, param) => ({ type: param.type, value: input.readPointer() }) },
  "int64_t":        { decode: (input, param) => ({ type: param.type, value: input.readS64() }) },
  "uint64_t":       { decode: (input, param) => ({ type: param.type, value: input.readU64() }) },
  "long":           { decode: (input, param) => ({ type: param.type, value: input.readLong() }) },
  "unsigned long":  { decode: (input, param) => ({ type: param.type, value: input.readULong() }) },
  "char *":         { decode: (input, param) => ({ type: param.type, value: input.readCString() }) },
  "char * (utf8)":  { decode: (input, param) => ({ type: param.type, value: input.readUtf8String() }) },
  "char16_t *":     { decode: (input, param) => ({ type: param.type, value: input.readUtf16String() }) },
  "char * (ansi)":  { decode: (input, param) => ({ type: param.type, value: input.readAnsiString() }) },
};


const FallbackNativeDecoder: Decoder<NativePointer> = {
  decode: (input: NativePointer, param: Param): DecodedValue => {
    return {
      type: param.implementationType ?? param.type,
      name: param.name,
      value: "<NO-DECODER-IMPLEMENTED>"
    };
  },
};
/**
 * Resolve the concrete Decoder for `input` under `param`.
 * Called only on the first invocation for a given Param; the result is cached
 * on `param.decoder` so subsequent calls skip this dispatch entirely.
 */
function resolveNativeDecoder(param: Param): Decoder<NativePointer> {
  const decoder = typeDecoderMap[param.type];
  if (!decoder) {
    return FallbackNativeDecoder;
  } else 
  return decoder;
}


export const NativeDecoder: Decoder<NativePointer> = {
  decode: (input: NativePointer, param: Param, quickDecode = false): DecodedValue => {
    console.log("NATIVE DECODER: ")
    console.log(JSON.stringify(param, null, 2))

    // a decoder was already resolved for this Param
    const cachedDecoder = param.decoder;
    if (cachedDecoder) {
      return cachedDecoder.decode(input, param);
    }
    
    // Resolve the decoder from the frooky parameter declaration and cache it
      const decoder = resolveNativeDecoder(param);
      param.decoder = decoder;
      console.log(decoder)
      return decoder.decode(input, param, quickDecode);
  },
};
