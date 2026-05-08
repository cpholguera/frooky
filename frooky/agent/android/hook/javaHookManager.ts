import Java from "frida-java-bridge";
import { JavaHook } from "../../build/hook/javaHook";
import { DecoderSettings } from "../../shared/decoders/decoderSettings";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../../shared/defaultValues";
import type { HookManager } from "../../shared/hook/hookManager";
import { InputParam, normalizeInputParam } from "../../shared/inputParsing/inputDecodableTypes";
import { InputJavaHookNormalized } from "../../shared/inputParsing/inputJavaHookGroup";
import { sleep } from "../../shared/utils";
import { JavaParam } from "./javaParam";

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

// resolve java classes, the method and their overloads
export class JavaHookManager implements HookManager<InputJavaHookNormalized, JavaHook> {
  private resolvedJavaClasses: Record<string, Java.Wrapper> = {};

  private buildParamsFromArgumentTypes(argTypes: Java.Type[], decoderSettings: DecoderSettings): JavaParam[] {
    return argTypes.reduce((params: JavaParam[], type: Java.Type) => {
      if (type.className) {
        params.push({
          type: type.className,
          implementationType: type.className,
          decoderSettings: decoderSettings,
        });
      } else {
        frooky.log.warn(`No Frida type name for the VM type ${type.name} found.`);
      }
      return params;
    }, []);
  }

  private async resolveAndCacheJavaClass(name: string, hookTimeoutMs: number): Promise<Java.Wrapper> {
    frooky.log.info(`Resolving java class ${name} with a timeout of ${hookTimeoutMs}ms.`);
    const deadline = Date.now() + hookTimeoutMs;

    let javaClass: Java.Wrapper | undefined;
    while (true) {
      try {
        javaClass = Java.use(name);
        this.resolvedJavaClasses[name] = javaClass;

        break;
      } catch (_) {
        //  silently ignore errors from Java.use
      }
      if (Date.now() >= deadline) {
        throw new Error(`Java class ${name} could not be loaded within ${hookTimeoutMs}ms. It either does not exist, or is not loaded yet.`);
      }
      await sleep(100);
    }

    return javaClass;
  }

  resolveMethod(javaClass: Java.Wrapper, inputHook: InputJavaHookNormalized): Java.MethodDispatcher {
    try {
      return javaClass[inputHook.method];
    } catch (e) {
      throw Error(`Method ${inputHook.method} was not found in class ${javaClass.$className}.`);
    }
  }

  resolveOverloads(method: Java.MethodDispatcher, inputHook: InputJavaHookNormalized): JavaHook[] {
    const result: JavaHook[] = [];
    if (inputHook.overloads?.length) {
      // Only get declared overloaded methods
      for (const overload of inputHook.overloads) {
        const normalizedParams: JavaParam[] = overload.params.map((inputParam: InputParam) => normalizeInputParam(inputParam) as JavaParam);
        // extract a list of java parameter types e.g. ["int", "java.lang.String", "double"] to be used to look up the overload
        const paramTypes: string[] = normalizedParams.map((param: JavaParam) => param.type);
        try {
          result.push({
            methodName: method.methodName,
            method: method.overload(...paramTypes),
            params: normalizedParams,
            hookSettings: inputHook.hookSettings ?? DEFAULT_HOOK_SETTINGS,
            decoderSettings: inputHook.decoderSettings ?? DEFAULT_DECODER_SETTINGS,
          });
        } catch (e) {
          frooky.log.warn(`Failed to get overload for method '${inputHook.method}(${paramTypes})' in class '${method.holder}': ${e}.`);
        }
      }
    } else {
      // Get all overloaded methods
      for (const javaMethod of method.overloads) {
        const params: JavaParam[] = this.buildParamsFromArgumentTypes(javaMethod.argumentTypes, inputHook.decoderSettings!);
        result.push({
          methodName: method.methodName,
          method: javaMethod,
          params: params,
          hookSettings: inputHook.hookSettings ?? DEFAULT_HOOK_SETTINGS,
          decoderSettings: inputHook.decoderSettings ?? DEFAULT_DECODER_SETTINGS,
        });
      }
    }
    return result;
  }

  async resolveHooks(inputHooks: InputJavaHookNormalized[]): Promise<JavaHook[]> {
    frooky.log.info(`Resolving Java hooks`);

    const promises = inputHooks.map(async (inputHook) => {
      try {
        if (!(inputHook.javaClass in this.resolvedJavaClasses)) {
          await this.resolveAndCacheJavaClass(inputHook.javaClass, inputHook.hookSettings?.hookTimeoutMs ?? DEFAULT_HOOK_SETTINGS.hookTimeoutMs);
        }
        const javaClass = this.resolvedJavaClasses[inputHook.javaClass];
        const method = this.resolveMethod(javaClass, inputHook);
        return this.resolveOverloads(method, inputHook);
      } catch (e) {
        frooky.log.error(`${e}`);
        return null;
      }
    });
    return Promise.all(promises).then((results) => results.filter((r): r is JavaHook[] => r !== null).flat());
  }

  registerHooks(hooks: JavaHook[]): void {
    throw new Error("Method not implemented.");
  }
}
