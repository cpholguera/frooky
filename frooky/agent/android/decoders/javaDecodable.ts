import { Decodable } from "../../shared/decoders/decodable";

/**
 * Canonical definition of a parameter to be decoded during function hooking.
 */
export interface JavaDecodable extends Decodable {
  /**
   * type of the actual implementation at runtime. this type can be different from the one declared if the declared one is an interface.
   * If this parameter is set, the decoders will use this type to decode the values.
   */
  implementationType?: string;
}
