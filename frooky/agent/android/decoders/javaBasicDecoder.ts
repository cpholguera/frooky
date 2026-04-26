import type Java from "frida-java-bridge";
import type { BaseDecoder, DecodedValue } from "../../shared/decoders/baseDecoder";
import type { Param } from "../../shared/hook/param";
import type { JavaParam } from "../hook/javaParameter";

export const JavaLongDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => ({
    type: param.type,
    name: param.name,
    value: input.toString(),
  }),
};

export const JavaPrimitiveDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => ({
    type: param.type,
    name: param.name,
    value: input,
  }),
};

export const JavaFallbackDecoder: BaseDecoder<Java.Wrapper, JavaParam> = {
  decode: (input: Java.Wrapper, param: JavaParam): DecodedValue => {
    return {
      type: param.implementationType ?? param.type,
      name: param.name,
      value: input.toString(),
    };
  },
};
