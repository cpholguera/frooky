import Java from "frida-java-bridge";
import { DecoderSettings } from "../../shared/decoders/decoderSettings";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS, FRIDA_LOOKUP_INTERVAL_MS } from "../../shared/defaultValues";
import type { HookManager } from "../../shared/hook/hookManager";
import { InputParam, normalizeInputParam } from "../../shared/inputParsing/inputDecodableTypes";
import { InputJavaHookNormalized } from "../../shared/inputParsing/inputJavaHookGroup";
import { sleep } from "../../shared/utils";
import { JavaDecoder } from "../decoders/javaDecoder";
import { JavaHook } from "./javaHook";
import { buildAndDispatchEvent, buildFieldType, buildJavaStackTrace, decodeArgs } from "./javaHookImpl";
import { JavaParam } from "./javaParam";

export function registerHook(javaHook: JavaHook) {
  let returnParam: JavaParam;
  javaHook.method.implementation = function (...args: Java.Wrapper[]) {
    // call the original implementation
    const returnValue = javaHook.method.apply(this, args);
    try {
      // decode the return value
      if (!returnParam) {
        const returnType = javaHook.method.returnType.className ?? "void";
        returnParam = { type: returnType, implementationType: returnType, decoderSettings: javaHook.decoderSettings };
      }
      const decodedReturnValue = JavaDecoder.decode(returnValue, returnParam, javaHook.decoderSettings);
      // collect the stack trace from Frida
      const stackTraceLimit: number = javaHook.hookSettings.stackTraceLimit;
      const stackTrace = buildJavaStackTrace(stackTraceLimit);
      // collect the field type and (optional) instance hash
      const fieldType = buildFieldType(this as Java.Wrapper);
      // decode the arguments passed to the method
      const decodedArgs = decodeArgs(args, javaHook.params, javaHook.decoderSettings);
      // create a frooky hook event and send it to the event cache
      buildAndDispatchEvent(javaHook, decodedArgs, decodedReturnValue, stackTrace, fieldType);
    } catch (e) {
      frooky.log.error(`Error during the execution of ${javaHook.method.holder.$className}.${javaHook.methodName}: ${e}`);
    }
    return returnValue;
  };
}

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

    while (true) {
      try {
        if (this.resolvedJavaClasses[name]) {
          frooky.log.info(`Cached module '${name}' found.`);
          return this.resolvedJavaClasses[name];
        }
        this.resolvedJavaClasses[name] = Java.use(name);
        frooky.log.info(`Module '${name}' successfully resolved.`);
        return this.resolvedJavaClasses[name];
      } catch (_) {
        //  silently ignore errors from Java.use
      }
      if (Date.now() >= deadline) {
        throw new Error(`Skipping hooks for java class ${name} as it could not be loaded during a time out of ${hookTimeoutMs}ms.`);
      }
      await sleep(FRIDA_LOOKUP_INTERVAL_MS);
    }
  }

  resolveMethod(javaClass: Java.Wrapper, inputHook: InputJavaHookNormalized): Java.MethodDispatcher {
    const resolvedMethod = javaClass[inputHook.method];
    if (resolvedMethod) {
      return resolvedMethod;
    } else {
      throw Error(`Skipping hook for ${inputHook.method} as it was not found in class ${javaClass.$className}.`);
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
      const hookTimeoutMs = inputHook.hookSettings?.hookTimeoutMs ?? DEFAULT_HOOK_SETTINGS.hookTimeoutMs;
      try {
        if (!(inputHook.javaClass in this.resolvedJavaClasses)) {
          await this.resolveAndCacheJavaClass(inputHook.javaClass, hookTimeoutMs);
        }
        const javaClass = this.resolvedJavaClasses[inputHook.javaClass];
        const method = this.resolveMethod(javaClass, inputHook);

        return this.resolveOverloads(method, inputHook);
      } catch (e) {
        frooky.log.warn(`${e}`);
      }
    });
    return Promise.all(promises).then((results) => results.filter((r): r is JavaHook[] => r !== null).flat());
  }

  registerHooks(hooks: JavaHook[]): void {
    for (const hook of hooks) {
      registerHook(hook);
    }
  }
}
