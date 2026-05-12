import { Decoder } from "../../shared/decoders/baseDecoder";
import { Decodable } from "../../shared/decoders/decodable";
import { DecoderResolver } from "../../shared/decoders/decoderResolver";
import { NativeReferenceDecodable, NativeValueDecodable } from "./nativeDecodable";
import { NativeFallbackDecoder } from "./nativeFallbackDecoder";
import { parseNativeFridaType } from "./nativeFridaType";
import { NativeReferenceDecoder } from "./nativeReferenceDecoder";
import { NativeValueDecoder } from "./nativeValueDecoder";

// resolves the decode based on a decodable type
export const NativeDecoderResolver: DecoderResolver<Decodable | NativeReferenceDecodable | NativeValueDecodable, NativePointer> = {
  resolveDecoder(decodable: Decodable): Decoder<Decodable | NativeReferenceDecodable | NativeValueDecodable, NativePointer> {
    const nativeFridaType = parseNativeFridaType(decodable.type);
    if (!nativeFridaType) {
      // it was not possible to resolve a decoder
      return new NativeFallbackDecoder(decodable);
    }
    if (typeof nativeFridaType === "object") {
      // the declared type is a reference (e.g. 'char*')
      return new NativeReferenceDecoder({
        ...decodable,
        fridaType: nativeFridaType,
      } as NativeReferenceDecodable);
    }
    // the declared type is a fundamental (e.g. 'int')
    return new NativeValueDecoder({
      ...decodable,
      fridaType: nativeFridaType,
    } as NativeValueDecodable);
  },
};
