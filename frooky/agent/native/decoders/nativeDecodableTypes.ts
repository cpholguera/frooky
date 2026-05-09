import { DecodableType } from "frooky/shared";
import { NativeType } from "./nativeTypeNormalizer";

/**
 * Represents a native parameter
 */
export interface NativeDecodableType extends DecodableType {
  /**
   * Normalized type used for native decoding.
   */
  nativeType: NativeType;
}
