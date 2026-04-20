import type Java from "frida-java-bridge";
import type { Param } from "../hook/parameter";

// decoded values
export type DecodedValue = {
  type: string;
  name?: string;
  error?: Error;
  value?: unknown;
};

export type Decoder = {
  // decodes an input value, 
  // param contains additional information about the value such as name or type
  // quickDecode is an optional flag, if set, we TRY to minimize Frida <-> Bridge <-> Platform calls 
  // at cost of less information. This will always SKIP fetching the stacktrace
  decode: (input: Java.Wrapper, param: Param, quickDecode?: boolean) => DecodedValue;
};
