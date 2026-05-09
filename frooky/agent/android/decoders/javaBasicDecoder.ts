import type Java from "frida-java-bridge";
import { BaseDecoder } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { JavaParam } from "../hook/javaParam";

export const JavaLongDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (value, param): DecodedValue => ({
    type: param.type,
    name: param.paramNname,
    value: value.toString(),
  }),
};

export const JavaPrimitiveDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (value, param): DecodedValue => ({
    type: param.type,
    name: param.paramNname,
    value: value,
  }),
};

export const JavaFallbackDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (value, param): DecodedValue => {
    return {
      type: param.implementationType ?? param.type,
      name: param.paramNname,
      value: value.toString(),
    };
  },
};
