import { Decoder } from "../../shared/decoders/baseDecoder";
import { Decodable } from "../../shared/decoders/decodable";
import { DecoderResolver } from "../../shared/decoders/decoderResolver";
import { NativeFallbackDecoder } from "./nativeFallbackDecoder";
import { parseNativeFridaType } from "./nativeFridaType";
import { NativeReferenceDecoder } from "./nativeReferenceDecoder";
import { NativeValueDecoder } from "./nativeValueDecoder";

// resolves the decode based on a decodable type
export const NativeDecoderResolver: DecoderResolver<NativePointer> = {
  resolveDecoder(decodable: Decodable): Decoder<NativePointer> {
    const nativeFridaType = parseNativeFridaType(decodable.type);
    if (!nativeFridaType) {
      // it was not possible to resolve a decoder
      return new NativeFallbackDecoder(decodable);
    }
    if (typeof nativeFridaType === "object") {
      // the declared type is a reference (e.g. 'char*')
      return new NativeReferenceDecoder(decodable, nativeFridaType);
    } else {
      // the declared type is a fundamental (e.g. 'int')
      return new NativeValueDecoder({
        type: nativeFridaType,
        name: decodable.name,
        settings: decodable.settings,
      });
    }
  },
};
