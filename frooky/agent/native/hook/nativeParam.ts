import type { Param } from "../../shared/hook/param";
import type { NativeType } from "../decoders/nativeTypeNormalizer";

/**
 * Represents a native parameter
 */
export interface NativeParam extends Param {
  /**
   * Normalized type used for native decoding.
   */
  nativeType?: NativeType;
}
