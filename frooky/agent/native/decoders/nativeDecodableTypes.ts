import { Param, RetType } from "../../shared/decoders/decodableTypes";
import { NativeType } from "./nativeTypeNormalizer";

/**
 * Represents a native parameter
 */
export interface NativeParam extends Param {
  /**
   * Normalized type used for native decoding.
   */
  nativeType?: NativeType;
}


/**
 * Represents a native parameter
 */
export interface NativeRetType extends RetType {
  /**
   * Normalized type used for native decoding.
   */
  nativeType?: NativeType;
}
