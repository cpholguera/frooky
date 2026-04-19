import type Java from "frida-java-bridge";
import type { DecodedValue } from "../../shared/decoders/decoder";
import type { Param } from "../../shared/hook/parameter";
import { javaDecoder } from "../decoders/javaDecoder";
import { JavaHookEvent, type JavaMemberType } from "../event/javaHookEvent";
import type { JavaHookOp } from "./javaHookRunner";

// export function resolveJavaMemberType(
// 	context: Java.Wrapper,
// 	System: Java.Wrapper,
// ): {
// 	memberType: JavaMemberType;
// 	instanceId: number | undefined;
// } {
// 	if (context?.$className && typeof context.$h === "undefined") {
// 		return { memberType: "class", instanceId: undefined };
// 	}

// 	let instanceId: number | undefined;
// 	try {
// 		instanceId = System.identityHashCode(context);
// 	} catch (e) {
// 		frooky.log.error(`Error in identityHashCode: ${e}`);
// 	}
// 	return { memberType: "instance", instanceId };
// }

export function buildStackTrace(limit: number, Exception: Java.Wrapper): string[] | undefined {
  // TODO: REturn BAC

  if (limit <= 0) return;

  const stackTrace: string[] = [];

  Exception.$new()
    .getStackTrace()
    .forEach((el: any, i: number) => {
      if (i < limit) stackTrace.push(el.toString());
    });

  return stackTrace;
}

/**
 * Decodes the arguments passed to this method
 *
 * @param args - The actual argument values passed to the method
 * @param params- The optional frooky parameters for additional information
 */
export function decodeHookArguments(args: Java.Field[], params?: Param[]): DecodedValue[] | undefined {
  if (args.length === 0) return;
  if (args.length !== params?.length) {
    throw Error("The actual argument length does not match the declared frooky parameters");
  }

  const decoded: DecodedValue[] = [];
  try {
    args.forEach((arg, i) => {
      decoded.push(javaDecoder.decode(arg, params[i]));
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
