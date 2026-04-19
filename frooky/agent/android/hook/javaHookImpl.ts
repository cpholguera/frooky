import Java from "frida-java-bridge";
import { de } from "zod/locales";
import type { DecodedValue } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { JavaDecoder } from "../decoders/javaDecoder";
import { JavaHookEvent } from "../event/javaHookEvent";
import type { JavaHookOp } from "./javaHookRunner";

export type FieldType = {
  fieldType: "static" | "instance";
  instanceId?: number;
};

export function buildFieldType(method: Java.Wrapper): FieldType {
  const fieldType = method === null ? "static" : "instance";
  const instanceId = fieldType === "instance" ? method.hashCode() : undefined;
  return { fieldType, instanceId };
}

export function buildStackTrace(limit: number): string[] {
  const stackTrace: string[] = [];

  const fridaStackTrace = Java.backtrace({ limit: limit });

  for (const frame of fridaStackTrace.frames) {
    stackTrace.push(`${frame.className}.${frame.methodName} (${frame.fileName}:${frame.lineNumber})`);
  }
  1;
  return stackTrace;
}

/**
 * Decodes the arguments passed to this method
 *
 * @param args - The actual argument values passed to the method
 * @param params- The optional frooky parameters for additional context information
 */
export function decodeArgs(args: Java.Wrapper[], params?: Param[]): DecodedValue[] {
  if (args.length === 0) {
    throw Error("Empty args passed");
  }
  if (args.length !== params?.length) {
    throw Error("The actual argument length does not match the declared frooky parameter length");
  }

  const decodedArgs: DecodedValue[] = [];
  try {
    args.forEach((arg: Java.Wrapper, i: number) => {
      console.log(`decoding ARG  ${i}`);
      decodedArgs.push(JavaDecoder.decode(arg, params[i]));
    });
  } catch (e) {
    frooky.log.error(`Error decoding input parameter: ${e}`);
  }
  return decodedArgs;
}

export function buildAndDispatchEvent(javaHookOp: JavaHookOp, decodedArgs: DecodedValue[], returnValue: DecodedValue, stackTrace: string[], fieldType: FieldType): void {
  const event = new JavaHookEvent(javaHookOp.javaClass, javaHookOp.methodName, fieldType);
  event.category = javaHookOp.category;
  event.stackTrace = stackTrace;
  event.args = decodedArgs;
  event.returnValue = returnValue;
  frooky.addEvent(event);
}
