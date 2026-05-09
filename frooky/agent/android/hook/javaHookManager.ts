import Java from "frida-java-bridge";
import {
  DecoderSettings,
  DEFAULT_DECODER_SETTINGS,
  DEFAULT_HOOK_SETTINGS,
  HookManager,
  InputJavaHookNormalized,
  InputParam,
  normalizeInputParam,
} from "../../shared";
import { JavaDecoder } from "../decoders/javaDecoder";
import { JavaHook } from "./javaHook";
import { buildAndDispatchEvent, buildFieldType, buildJavaStackTrace, decodeJavaArgs } from "./javaHookImpl";
import { JavaParam } from "./javaParam";

// resolve java classes, the method and their overloads
export class JavaHookManager extends HookManager<InputJavaHookNormalized, JavaHook> {
  async resolveHooks(inputHooks: InputJavaHookNormalized[], timeout: number): Promise<Promise<JavaHook[] | null>[]> {
    frooky.log.info(`Resolving Java hooks`);

    const uniqueClasses: string[] = [...new Map(inputHooks.map((inputHook) => [inputHook.javaClass, inputHook])).keys()];
    return uniqueClasses.flatMap((javaClass) => {
      const javaClassPromise = this.resolveJavaClass(javaClass, timeout).catch((e) => {
        frooky.log.warn(`${e}`);
        return null;
      });
      return inputHooks
        .filter((inputHook) => inputHook.javaClass === javaClass)
        .map(async (inputHook): Promise<JavaHook[] | null> => {
          const resolvedJavaClass = await javaClassPromise;
          if (!resolvedJavaClass) return null;
          try {
            const method = this.resolveMethod(resolvedJavaClass, inputHook);
            frooky.log.debug(`Java method '${resolvedJavaClass.$className}.${method.methodName}' found: ${method.handle}.`);
            return this.resolveOverloads(method, inputHook);
          } catch (e) {
            frooky.log.warn(`${e}`);
            return null;
          }
        });
    });
  }

  registerHooks(javaHooks: JavaHook[]): JavaHook[] {
    for (const javaHook of javaHooks) {
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
          const decodedArgs = decodeJavaArgs(args, javaHook.params, javaHook.decoderSettings);
          // create a frooky hook event and send it to the event cache
          buildAndDispatchEvent(javaHook, decodedArgs, decodedReturnValue, stackTrace, fieldType);
        } catch (e) {
          frooky.log.error(`Error during the execution of ${javaHook.method.holder.$className}.${javaHook.methodName}: ${e}`);
        }
        return returnValue;
      };
    }
    return javaHooks;
  }

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

  private async resolveJavaClass(javaClassName: string, timeout: number): Promise<Java.Wrapper> {
    frooky.log.info(`Resolving java class ${javaClassName} with a timeout of ${timeout}ms.`);
    return this.pollUntilResolved(
      () => {
        try {
          frooky.log.debug(`Trying to resolve Java class '${javaClassName}'.`);

          const resolvedJavaClass = Java.use(javaClassName);
          frooky.log.info(`Java class '${javaClassName}' resolved.`);
          return resolvedJavaClass;
        } catch (_) {
          frooky.log.debug(`Java class '${javaClassName}' not resolved yet.`);
          return null;
        }
      },
      javaClassName,
      timeout,
    );
  }

  private resolveMethod(javaClass: Java.Wrapper, inputHook: InputJavaHookNormalized): Java.MethodDispatcher {
    const resolvedMethod = javaClass[inputHook.method];
    if (resolvedMethod) {
      return resolvedMethod;
    } else {
      throw Error(`Skipping hook for ${inputHook.method}. This method does not exist in class ${javaClass.$className}.`);
    }
  }

  private resolveOverloads(method: Java.MethodDispatcher, inputHook: InputJavaHookNormalized): JavaHook[] {
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
          frooky.log.warn(`Skipping overload for method '${inputHook.method}(${paramTypes})'. The overload does not exist.`);
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
}
