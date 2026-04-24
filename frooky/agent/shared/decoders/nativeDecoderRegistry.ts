import type { NativeParam } from "../hook/nativeParameter";
import type { Decoder } from "./baseDecoder";
import { FallbackNativeDecoder } from "./nativeDecoder";
import { NativeFundamentalDecoder } from "./nativeFundamentalDecoder";
import { FUNDAMENTAL_TYPES, type NativeType } from "./nativeTypeNormalizer";

/*
 * This is the registry for complex java decoders.
 */
export function getNativeDecoder(nativeType: NativeType): Decoder<NativePointer, NativeParam> {
  if ((FUNDAMENTAL_TYPES as readonly string[]).includes(nativeType.type)) {
    return NativeFundamentalDecoder;
  } else if (nativeType.type === "pointer") {
    // return complex decoder
  }
  return FallbackNativeDecoder;
}
