import { Decodable } from "../../shared/decoders/decodable";
import { FridaFundamentalType, FridaReferenceType } from "./nativeFridaType";

export interface NativeReferenceDecodable extends Decodable {
  fridaType: FridaReferenceType;
}

export interface NativeValueDecodable extends Decodable {
  fridaType: FridaFundamentalType;
}
