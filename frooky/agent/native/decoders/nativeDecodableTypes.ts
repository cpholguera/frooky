import { DecodableType } from "../../shared/decoders/decodableTypes";
import type { NativeType } from "./nativeTypeNormalizer";

/**
 * Represents a native parameter
 */
export interface NativeDecodableType extends DecodableType {
  /**
   * Normalized type used for native decoding.
   */
  nativeType: NativeType;
}
