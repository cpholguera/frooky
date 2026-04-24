import type Java from "frida-java-bridge";
import type { DecodedValue, Decoder } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import type { JavaParam } from "../hook/javaParameter";

export const JavaLongDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => ({
    type: param.type,
    name: param.name,
    value: input.toString(),
  }),
};

export const PrimitiveDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (input: Java.Wrapper, param: Param): DecodedValue => ({
    type: param.type,
    name: param.name,
    value: input as unknown as DecodedValue["value"],
  }),
};

export const FallbackJavaDecoder: Decoder<Java.Wrapper, JavaParam> = {
  decode: (input: Java.Wrapper, param: JavaParam): DecodedValue => {
    return {
      type: param.implementationType ?? param.type,
      name: param.name,
      value: input.toString(),
    };
  },
};
