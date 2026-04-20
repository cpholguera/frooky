import Java from "frida-java-bridge";
import { DEFAULT_STACK_TRACE_LIMIT } from "../../shared/config";
import type { MethodName } from "../../shared/hook/hook";
import type { HookOp, HookRunner } from "../../shared/hook/hookRunner";
import type { Param, ParamType } from "../../shared/hook/parameter";
import { JavaDecoder } from "../decoders/javaDecoder";
import type { JavaHook, JavaMethodDefinition, JavaOverload } from "./javaHook";
import { buildAndDispatchEvent, buildFieldType, buildStackTrace, decodeArgs } from "./javaHookImpl";

// contains everything needed to hook one java method
export interface JavaHookOp extends HookOp {
  javaClass: string;
  methodName: MethodName;
  params: Param[];
  javaMethod: Java.Method;
}

// builds JavaHookOps fro ALL overloads of a certain method
function buildHookOpsForAllOverloads(hook: JavaHook, handle: Java.MethodDispatcher, methodDefinition: JavaMethodDefinition, javaHookOps: JavaHookOp[]): void {
  handle.overloads.forEach((javaMethod: Java.Method) => {
    const params: Param[] = [];
    javaMethod.argumentTypes.forEach((t: Java.Type) => {
      if (t.className) {
        params.push({ type: t.className, implementationType: t.className });
      } else {
        frooky.log.warn(`No Frida type name for the VM type ${t.name} found.`);
      }
    });

    javaHookOps.push({
      javaClass: hook.javaClass,
      methodName: methodDefinition.name,
      params: params,
      javaMethod: javaMethod,
      stackTraceLimit: hook.stackTraceLimit ?? DEFAULT_STACK_TRACE_LIMIT,
      eventFilter: hook.eventFilter,
      category: hook.metadata?.category,
    });
  });
}

// only builds JavaHookOps for overloads which are explicitly declared
function buildHookOpsForDeclaredOverloads(hook: JavaHook, handle: Java.MethodDispatcher, methodDefinition: JavaMethodDefinition, javaHookOps: JavaHookOp[]): void {
  methodDefinition.overloads?.forEach((declaredOverload: JavaOverload) => {
    const paramList: ParamType[] = [];
    declaredOverload.params.forEach((p: Param) => {
      paramList.push(p.type);
    });
    try {
      const javaMethod: Java.Method = handle.overload(...paramList);
      javaHookOps.push({
        javaClass: hook.javaClass,
        methodName: methodDefinition.name,
        params: declaredOverload.params,
        javaMethod: javaMethod,
        stackTraceLimit: hook.stackTraceLimit ?? DEFAULT_STACK_TRACE_LIMIT,
        eventFilter: hook.eventFilter,
        category: hook.metadata?.category,
      });
    } catch (e) {
      frooky.log.warn(`Failed to get overload for method '${methodDefinition.name}' in class '${hook.javaClass}': ${e}.`);
    }
  });
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
      if (!method.overloads) {
        buildHookOpsForAllOverloads(hook, handle, method, hookOps);
      } else {
        buildHookOpsForDeclaredOverloads(hook, handle, method, hookOps);
      }
    } catch (e) {
      frooky.log.warn(`Failed to resolve method '${method.name}' in class '${hook.javaClass}': ${e}.`);
    }
  }
  return hookOps;
}

// actually hooks the java method
export function registerJavaHookOps(javaHookOp: JavaHookOp) {
  javaHookOp.javaMethod.implementation = function (...args: Java.Wrapper[]) {
    const returnValue = javaHookOp.javaMethod.apply(this, args);
    try {
      const decodedReturnValue = JavaDecoder.decode(returnValue, { type: javaHookOp.javaMethod.returnType.className ?? "void", implementationType: javaHookOp.javaMethod.returnType.className ?? "void" });
      const stackTrace = javaHookOp.stackTraceLimit > 0 ? buildStackTrace(javaHookOp.stackTraceLimit) : [];
      const fieldType = buildFieldType(this as Java.Wrapper);
      const decodedArgs = decodeArgs(args, javaHookOp.params);
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
