import type { NativeType } from "../decoders/nativeTypeNormalizer";
import type { Param } from "./parameter";

/**
 * Represents a native parameter
 */
export interface NativeParam extends Param {
  /**
   * Normalized type used for native decoding.
   */
  nativeType?: NativeType;
}
