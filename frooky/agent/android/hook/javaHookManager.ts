import Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { Param, RetType } from "../../shared/decoders/decodable";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../../shared/defaultValues";
import { DecoderSettings } from "../../shared/frookySettings";
import { DecodedArgs, HookManager, ParamDecoders } from "../../shared/hook/hookManager";
import { InputParam, normalizeInputParam } from "../../shared/inputParsing/inputDecodableTypes";
import { InputJavaHookNormalized } from "../../shared/inputParsing/inputJavaHookGroup";
import { JavaDecodable } from "../decoders/javaDecodable";
import { JavaDecoderResolver } from "../decoders/javaDecoderResolver";
import { JavaHookEvent } from "../event/javaHookEvent";
import { JavaHook } from "./javaHook";

export type FieldType = {
  fieldType: "static" | "instance";
  instanceId?: number;
};

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
            return this.resolveOverloads(method, inputHook);
          } catch (e) {
            frooky.log.warn(e instanceof Error ? e.message : String(e));
            return null;
          }
        });
    });
  }

  private resolveParamDecoders(params: Param[]): ParamDecoders<JavaDecodable, Java.Wrapper> {
    const paramDecoders: ParamDecoders<JavaDecodable, Java.Wrapper> = {
      enter: [],
      exit: [],
    };
    for (const param of params) {
      const { decodeAt, ...decodable } = param;
      if (param.decodeAt === "both" || param.decodeAt === "enter") {
        paramDecoders.enter.push(JavaDecoderResolver.resolveDecoder(decodable));
      } else if (param.decodeAt === "exit") {
        paramDecoders.exit.push(JavaDecoderResolver.resolveDecoder(decodable));
      }
    }
    return paramDecoders;
  }

  private resolveRetTypeDecoder(retType: RetType): Decoder<JavaDecodable, Java.Wrapper> {
    return JavaDecoderResolver.resolveDecoder(retType);
  }

  registerHooks(hooks: JavaHook[]): JavaHook[] {
    const hookManager = this;
    for (const hook of hooks) {
      let stackTrace: string[];

      // // resolve the decoders used for this hook and cache it locally
      let cachedParamDecoders: ParamDecoders<JavaDecodable, Java.Wrapper>;
      if (hook.params) {
        cachedParamDecoders = this.resolveParamDecoders(hook.params);
      }
      // const cachedRetTypeDecoder = this.resolveRetTypeDecoder(hook.method.returnType.type);
      let decodedArgs: DecodedArgs = {
        enter: [],
        exit: [],
      };

      // resolve the return type
      let retTypeDecoder: Decoder<JavaDecodable, Java.Wrapper>;
      if (hook.method.returnType.className) {
        const retType = {
          type: hook.method.returnType.className,
          decoderSettings: hook.decoderSettings,
        };
        retTypeDecoder = this.resolveRetTypeDecoder(retType);
      }

      hook.method.implementation = function (...args: Java.Wrapper[]) {
        try {
          // decode arguments onEnter
          if (hook.params) {
            decodedArgs.enter = hookManager.decodeJavaArgs(args, cachedParamDecoders.enter);
          }
        } catch (e) {
          frooky.log.error(`Error during the 'onEnter' argument decoding of ${hook.method.holder.$className}.${hook.methodName}: ${e}`);
        }
        // call the original implementation
        const returnValue = hook.method.apply(this, args);
        try {
          // decode arguments onExit
          if (hook.params) {
            decodedArgs.exit = hookManager.decodeJavaArgs(args, cachedParamDecoders.exit);
          }

          // decode the return value
          let decodedRetValue: DecodedValue | undefined;
          if (retTypeDecoder) {
            decodedRetValue = retTypeDecoder.decode(returnValue);
          }

          // collect the stack trace from Frida
          const stackTraceLimit: number = hook.hookSettings.stackTraceLimit;
          const stackTrace = hookManager.buildJavaStackTrace(stackTraceLimit);

          // collect the field type and (optional) instance hash
          const fieldType = hookManager.buildFieldType(this as Java.Wrapper);

          frooky.addEvent(new JavaHookEvent(hook, fieldType, decodedArgs, decodedRetValue, stackTrace));
        } catch (e) {
          frooky.log.error(`Error during the execution of ${hook.method.holder.$className}.${hook.methodName}: ${e}`);
        }
        return returnValue;
      };
    }
    return hooks;
  }

  private buildParamsFromArgumentTypes(argTypes: Java.Type[], decoderSettings: DecoderSettings): Param[] {
    return argTypes.reduce((params: Param[], type: Java.Type) => {
      if (type.className) {
        params.push({
          type: type.className,
          decodeAt: "enter",
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
        const normalizedParams: Param[] = overload.params.map((inputParam: InputParam) => normalizeInputParam(inputParam) as Param);
        // extract a list of java parameter types e.g. ["int", "java.lang.String", "double"] to be used to look up the overload
        const paramTypes: string[] = normalizedParams.map((param: Param) => param.type);
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
        const params: Param[] = this.buildParamsFromArgumentTypes(javaMethod.argumentTypes, inputHook.decoderSettings!);
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
  /**
   * Decodes the arguments passed to this method
   *
   * @param args - The actual argument values passed to the method
   * @param params- The optional frooky parameters for additional context information
   */
  private decodeJavaArgs(args: Java.Wrapper[], decoderCache: Decoder<JavaDecodable, Java.Wrapper>[]): DecodedValue[] {
    const decodedArgs: DecodedValue[] = [];
    decoderCache.forEach((decoder: Decoder<JavaDecodable, Java.Wrapper>, i: number) => {
      decodedArgs.push(decoder.decode(args[i]));
    });
    return decodedArgs;
  }

  // private decodeJavaArgs(args: Java.Wrapper[], params: Param[], settings?: DecoderSettings): DecodedValue[] {
  //   if (args.length === 0) {
  //     throw Error("Empty args passed");
  //   }
  //   if (args.length !== params?.length) {
  //     throw Error("The actual argument length does not match the declared frooky parameter length");
  //   }

  //   const decodedArgs: DecodedValue[] = [];
  //   try {
  //     args.forEach((arg: Java.Wrapper, i: number) => {
  //       decodedArgs.push(JavaDecoderResolver.decode(arg, params[i]));
  //     });
  //   } catch (e) {
  //     frooky.log.error(`Error decoding input parameter: ${e}`);
  //   }
  //   return decodedArgs;
  // }

  private buildFieldType(method: Java.Wrapper): FieldType {
    const fieldType = method === null ? "static" : "instance";
    const instanceId = fieldType === "instance" ? method.hashCode() : undefined;
    return { fieldType, instanceId };
  }

  private buildJavaStackTrace(limit: number): string[] {
    const fridaStackTrace = Java.backtrace({ limit: limit });

    return Array.from({ length: Math.min(limit, fridaStackTrace.frames.length) }, (_, i) => {
      const frame = fridaStackTrace.frames[i];
      return `${frame.className}.${frame.methodName} (${frame.fileName}:${frame.lineNumber})`;
    });
  }
}
