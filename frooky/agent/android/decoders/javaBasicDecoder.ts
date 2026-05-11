import type Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { JavaParam } from "../hook/javaParam";

export const JavaLongDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (value, param): DecodedValue => ({
    type: param.type,
    name: param.name,
    value: value.toString(),
  }),
};

export const JavaPrimitiveDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (value, param): DecodedValue => ({
    type: param.type,
    name: param.name,
    value: value,
  }),
};

export const JavaFallbackDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (value, param): DecodedValue => {
    return {
      type: param.implementationType ?? param.type,
      name: param.name,
      value: value.toString(),
    };
  },
};
