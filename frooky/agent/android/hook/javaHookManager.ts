import {} from "../../build/hook/javaHook";
import { InputJavaHookCanonical } from "../../shared/frookyConfigParsing/javaHookScope";
import type { HookManager } from "../../shared/hook/hookManager";
import { JavaHook } from "./javaHook";

// function buildParamsFromArgumentTypes(argTypes: Java.Type[]): JavaParam[] {
// return argTypes.reduce((params: JavaParam[], t: Java.Type) => {
//   if (t.className) {
//     params.push({ type: t.className, implementationType: t.className });
//   } else {
//     frooky.log.warn(`No Frida type name for the VM type ${t.name} found.`);
//   }
//   return params;
// }, []);
// }

// actually hooks the java method
// export function registerJavaHookOps(javaHookOp: JavaHookOp) {
// let returnParam: JavaParam;
// javaHookOp.javaMethod.implementation = function (...args: Java.Wrapper[]) {
//   // call the original implementation
//   const returnValue = javaHookOp.javaMethod.apply(this, args);
//   try {
//     // decode the return value
//     if (!returnParam) {
//       const returnType = javaHookOp.javaMethod.returnType.className ?? "void";
//       returnParam = { type: returnType, implementationType: returnType };
//     }
//     const decodedReturnValue = JavaDecoder.decode(returnValue, returnParam, javaHookOp.settings?.decoderSettings);
//     // collect the stack trace from Frida
//     const stackTraceLimit: number = javaHookOp.settings?.stackTraceLimit ? javaHookOp.settings?.stackTraceLimit : DEFAULT_HOOK_SETTINGS.stackTraceLimit;
//     const stackTrace = buildJavaStackTrace(stackTraceLimit);
//     // collect the field type and (optional) instance hash
//     const fieldType = buildFieldType(this as Java.Wrapper);
//     // decode the arguments passed to the method
//     const decodedArgs = decodeArgs(args, javaHookOp.params, javaHookOp.settings?.decoderSettings);
//     // create a frooky hook event and send it to the event cache
//     buildAndDispatchEvent(javaHookOp, decodedArgs, decodedReturnValue, stackTrace, fieldType);
//   } catch (e) {
//     frooky.log.error(`Error during the execution of ${javaHookOp.javaClass}.${javaHookOp.methodName}: ${e}`);
//   }
//   return returnValue;
// };
// }

// function buildJavaHookOps(hook: JavaHookScope, handle: Java.MethodDispatcher, methodDefinition: JavaMethodDefinition, javaHookOps: JavaHookOp[]): void {
// if (methodDefinition.overloads?.length) {
//   // Only hook explicitly declared overloads
//   methodDefinition.overloads.forEach((declaredOverload: JavaOverload) => {
//     // merge decoder settings from the hook into the param options
//     if (hook.settings?.decoderSettings) {
//       declaredOverload.params.forEach((param: JavaParam) => {
//         param.options = param.options ?? {};
//         param.options.decoderSettings = {
//           ...hook.settings?.decoderSettings,
//           ...param.options.decoderSettings,
//         };
//       });
//     }
//     const paramList: Param[] = declaredOverload.params.map((p: Param) => p.type);
//     try {
//       pushHookOp(hook, methodDefinition, declaredOverload.params, handle.overload(...paramList), javaHookOps);
//     } catch (e) {
//       frooky.log.warn(`Failed to get overload for method '${methodDefinition.name}' in class '${hook.javaClass}': ${e}.`);
//     }
//   });
// } else {
//   // Hook all overloads
//   handle.overloads.forEach((javaMethod: Java.Method) => {
//     pushHookOp(hook, methodDefinition, buildParamsFromArgumentTypes(javaMethod.argumentTypes), javaMethod, javaHookOps);
//   });
// }
// }

// builds hook operations and registers them
export class JavaHookResolver implements HookManager<InputJavaHookCanonical, JavaHook> {
  registerHooks(hooks: JavaHook[]): void {
    throw new Error("Method not implemented.");
  }
  async resolveInputHooks(inputHooks: InputJavaHookCanonical[]): Promise<JavaHook[]> {
    frooky.log.warn("JavaHookResolver not yet implemented, skipping.");
    return [];
  }
}
// async executeHooking(javaHookScopes: JavaHookScope[]) {
// frooky.log.info(`Hook the native function`);

/// TODO: Refactor to be like NativeHookRunner

// javaHookScopes.forEach((hookScope: JavaHookScope) => {
//   if (!hookScope.hooks) {
//     frooky.log.warn(`Java hook did not specify an methods.`);
//   } else {
//     hookScope.hooks.forEach((method) => {
//       try {
//         const handle: Java.MethodDispatcher = Java.use(hookScope.javaClass)[method.name];
//         buildJavaHookOps(hookScope, handle, method, hookOps);
//       } catch (e) {
//         frooky.log.warn(`Failed to resolve method '${method.name}' in class '${hookScope.javaClass}': ${e}.`);
//       }
//     });
//   }
// });

// frooky.log.info(`Hook operations for the following hook built: ${JSON.stringify(hookOps, null, 2)}`);
// frooky.log.info(`Run Android hooking`);

// hookOps.forEach((hookOp: JavaHookOp) => {
//   registerJavaHookOps(hookOp);
// });
// }
