import Java from "frida-java-bridge";
import type { MethodName } from "../../shared/hook/hook";
import type { HookOp, HookRunner } from "../../shared/hook/hookRunner";
import type { Param, ParamType } from "../../shared/hook/param";
import { JavaDecoder } from "../decoders/javaDecoder";
import type { JavaHook, JavaMethodDefinition, JavaOverload } from "./javaHook";
import { buildAndDispatchEvent, buildFieldType, buildJavaStackTrace, decodeArgs } from "./javaHookImpl";
import type { JavaParam } from "./javaParam";

// contains everything needed to hook one java method
export interface JavaHookOp extends HookOp {
  javaClass: string;
  methodName: MethodName;
  params: Param[];
  javaMethod: Java.Method;
}

function pushHookOp(hook: JavaHook, methodDefinition: JavaMethodDefinition, params: JavaParam[], javaMethod: Java.Method, javaHookOps: JavaHookOp[]): void {
  javaHookOps.push({
    metadata: hook.metadata,
    settings: hook.settings,
    javaClass: hook.javaClass,
    methodName: methodDefinition.name,
    params,
    javaMethod,
  });
}

function buildParamsFromArgumentTypes(argTypes: Java.Type[]): JavaParam[] {
  return argTypes.reduce((params: JavaParam[], t: Java.Type) => {
    if (t.className) {
      params.push({ type: t.className, implementationType: t.className });
    } else {
      frooky.log.warn(`No Frida type name for the VM type ${t.name} found.`);
    }
    return params;
  }, []);
}

function buildHookOps(hook: JavaHook, handle: Java.MethodDispatcher, methodDefinition: JavaMethodDefinition, javaHookOps: JavaHookOp[]): void {
  if (methodDefinition.overloads?.length) {
    // Only hook explicitly declared overloads
    methodDefinition.overloads.forEach((declaredOverload: JavaOverload) => {
      const paramList: ParamType[] = declaredOverload.params.map((p: Param) => p.type);
      try {
        pushHookOp(hook, methodDefinition, declaredOverload.params, handle.overload(...paramList), javaHookOps);
      } catch (e) {
        frooky.log.warn(`Failed to get overload for method '${methodDefinition.name}' in class '${hook.javaClass}': ${e}.`);
      }
    });
  } else {
    // Hook all overloads
    handle.overloads.forEach((javaMethod: Java.Method) => {
      pushHookOp(hook, methodDefinition, buildParamsFromArgumentTypes(javaMethod.argumentTypes), javaMethod, javaHookOps);
    });
  }
}

// builds a list of java hook operations. Each JavaHookOp contains all information to hook ONE java method
function buildJavaHookOps(hook: JavaHook): JavaHookOp[] {
  if (!hook.methods) {
    frooky.log.warn(`Java hook did not specify an methods.`);
    return [];
  }

  const hookOps: JavaHookOp[] = [];
  for (const method of hook.methods) {
    try {
      const handle: Java.MethodDispatcher = Java.use(hook.javaClass)[method.name];
      buildHookOps(hook, handle, method, hookOps);
    } catch (e) {
      frooky.log.warn(`Failed to resolve method '${method.name}' in class '${hook.javaClass}': ${e}.`);
    }
  }
  return hookOps;
}

// actually hooks the java method
export function registerJavaHookOps(javaHookOp: JavaHookOp) {
  javaHookOp.javaMethod.implementation = function (...args: Java.Wrapper[]) {
    // call the original implementation
    const returnValue = javaHookOp.javaMethod.apply(this, args);
    try {
      // decode the return value
      const returnValueType = { type: javaHookOp.javaMethod.returnType.className ?? "void", implementationType: javaHookOp.javaMethod.returnType.className ?? "void" };
      const decodedReturnValue = JavaDecoder.decode(returnValue, returnValueType);
      // collect the stack trace from Frida
      const stackTrace = javaHookOp.stackTraceLimit > 0 ? buildJavaStackTrace(javaHookOp.stackTraceLimit) : [];
      // collect the field type and (optional) instance hash
      const fieldType = buildFieldType(this as Java.Wrapper);
      // decode the arguments passed to the method
      const decodedArgs = decodeArgs(args, javaHookOp.params);
      // create a frooky hook event and send it to the event cache
      buildAndDispatchEvent(javaHookOp, decodedArgs, decodedReturnValue, stackTrace, fieldType);
    } catch (e) {
      frooky.log.error(`Error during the execution of ${javaHookOp.javaClass}.${javaHookOp.methodName}: ${e}`);
    }
    return returnValue;
  };
}

// builds hook operations and registers them
export class JavaHookRunner implements HookRunner {
  executeHooking(hooks: JavaHook[]): void {
    frooky.log.info(`Executing Android hook operations`);

    var hookOps: JavaHookOp[] = [];

    hooks.forEach((h: JavaHook) => {
      hookOps.push(...buildJavaHookOps(h));
    });

    frooky.log.info(`Hook operations for the following hook built: ${JSON.stringify(hookOps, null, 2)}`);
    frooky.log.info(`Run Android hooking`);

    hookOps.forEach((hookOp: JavaHookOp) => {
      registerJavaHookOps(hookOp);
    });
  }
}
