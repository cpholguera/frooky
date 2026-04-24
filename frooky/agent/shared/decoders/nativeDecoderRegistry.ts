import type { Decoder } from "./decoder";
import { FallbackNativeDecoder } from "./nativeDecoder";
import { NativeFundamentalDecoder } from "./nativeFundamentalDecoder";
import type { NativeType } from "./nativeTypeNomalizer";

/*
 * This is the registry for complex java decoders.
 */
export function getNativeDecoder(type: NativeType): Decoder<NativePointer> {
  if (type.type === "pointer") {
    // return complex decoder
  } else {
    return NativeFundamentalDecoder;
  }
  return FallbackNativeDecoder;
}
