import type Java from "frida-java-bridge";
import type { Param } from "../hook/parameter";

// decoded values
export type DecodedValue = {
  name?: string;
  type?: string;
  error?: Error;
  value: unknown;
};

export type Decoder = {
  decode: (input: Java.Wrapper, param: Param) => DecodedValue;
};
