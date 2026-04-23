import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { nativeDecoderRegistry } from "./nativeDecoderRegistry";

const typeDecoderMap: Record<string, Decoder<NativePointer>> = {
  "int8_t":         { decode: (ptr, param) => ({ type: param.type, value: ptr.readS8() }) },
  "uint8_t":        { decode: (ptr, param) => ({ type: param.type, value: ptr.readU8() }) },
  "int16_t":        { decode: (ptr, param) => ({ type: param.type, value: ptr.readS16() }) },
  "uint16_t":       { decode: (ptr, param) => ({ type: param.type, value: ptr.readU16() }) },
  "short":          { decode: (ptr, param) => ({ type: param.type, value: ptr.readShort() }) },
  "unsigned short": { decode: (ptr, param) => ({ type: param.type, value: ptr.readUShort() }) },
  "int32_t":        { decode: (ptr, param) => ({ type: param.type, value: ptr.readS32() }) },
  "uint32_t":       { decode: (ptr, param) => ({ type: param.type, value: ptr.readU32() }) },
  "int":            { decode: (ptr, param) => ({ type: param.type, value: ptr.readInt() }) },
  "unsigned int":   { decode: (ptr, param) => ({ type: param.type, value: ptr.readUInt() }) },
  "float":          { decode: (ptr, param) => ({ type: param.type, value: ptr.readFloat() }) },
  "double":         { decode: (ptr, param) => ({ type: param.type, value: ptr.readDouble() }) },
  "void *":         { decode: (ptr, param) => ({ type: param.type, value: ptr.readPointer() }) },
  "int64_t":        { decode: (ptr, param) => ({ type: param.type, value: ptr.readS64() }) },
  "uint64_t":       { decode: (ptr, param) => ({ type: param.type, value: ptr.readU64() }) },
  "long":           { decode: (ptr, param) => ({ type: param.type, value: ptr.readLong() }) },
  "unsigned long":  { decode: (ptr, param) => ({ type: param.type, value: ptr.readULong() }) },
  "char *":         { decode: (ptr, param) => ({ type: param.type, value: ptr.readCString() }) },
  "char * (utf8)":  { decode: (ptr, param) => ({ type: param.type, value: ptr.readUtf8String() }) },
  "char16_t *":     { decode: (ptr, param) => ({ type: param.type, value: ptr.readUtf16String() }) },
  "char * (ansi)":  { decode: (ptr, param) => ({ type: param.type, value: ptr.readAnsiString() }) },
};


/**
 * Resolve the concrete Decoder for `input` under `param`.
 * Called only on the first invocation for a given Param; the result is cached
 * on `param.decoder` so subsequent calls skip this dispatch entirely.
 */
function resolveNativeDecoder(param: Param): Decoder<NativePointer> {
  const decoder = typeDecoderMap[param.type];
  if (!decoder) {
    throw new Error(`No decoder found for type: ${param.type}`);
  }
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
      return decoder.decode(input, param, quickDecode);
  },
};
