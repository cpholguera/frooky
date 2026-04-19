import Java from "frida-java-bridge";
import type { DecodedValue } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { JavaDecoder } from "../decoders/javaDecoder";
import { JavaHookEvent, type JavaMemberType } from "../event/javaHookEvent";
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
export function decodeArguments(args: Java.Wrapper[], params?: Param[]): DecodedValue[] | undefined {
  if (args.length === 0) return;
  if (args.length !== params?.length) {
    throw Error("The actual argument length does not match the declared frooky parameter length");
  }

  const decoded: DecodedValue[] = [];
  try {
    args.forEach((arg, i) => {
      decoded.push(JavaDecoder.decode(arg, params[i]));
    });
  } catch (e) {
    frooky.log.error(`Error decoding input parameter: ${e}`);
  }
  return decoded;
}

export function buildAndDispatchEvent(javaHookOp: JavaHookOp, memberType: JavaMemberType, instanceId: number | undefined, stackTrace: string[] | undefined, decodedArgs: DecodedValue[]): void {
  const event = new JavaHookEvent(javaHookOp.javaClass, javaHookOp.methodName, memberType);
  event.category = javaHookOp.category;
  event.instanceId = instanceId;
  event.stackTrace = stackTrace;
  event.args = decodedArgs;

  frooky.addEvent(event);
}
