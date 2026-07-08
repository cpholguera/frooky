import Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { Param } from "../../shared/decoders/decodable";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { DEFAULT_DECODER_SETTINGS, DEFAULT_HOOK_SETTINGS } from "../../shared/defaultValues";
import { DecoderSettings } from "../../shared/frookySettings";
import { DecodedArgs, HookManager, ParamDecoder } from "../../shared/hook/hookManager";
import { InputParam, normalizeInputParam } from "../../shared/inputParsing/inputDecodableTypes";
import { InputJavaHookNormalized } from "../../shared/inputParsing/inputJavaHookGroup";
import { PlatformStackTrace } from "../../shared/platformStackTrace";
import { FilterMismatchError } from "../../shared/utils";
import { JavaDecoderResolver } from "../decoders/javaDecoderResolver";
import { JavaHook } from "./javaHook";
import { JavaHookEvent } from "./javaHookEvent";

export type FieldType = {
  fieldType: "static" | "instance";
  instanceId?: number;
};

// resolve java classes, the method and their overloads
export class AndroidHookManager extends HookManager<InputJavaHookNormalized, JavaHook, Java.Wrapper> {
  constructor(platformStackTrace: PlatformStackTrace) {
    super(JavaDecoderResolver, platformStackTrace);
  }
  async resolveHooks(inputHooks: InputJavaHookNormalized[], timeout: number): Promise<Promise<JavaHook[] | null>[]> {
    frooky.log.debug(`Resolving Java hooks`);

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

  registerHooks(hooks: JavaHook[]): number {
    const hookManager = this;
    let countSuccessfulHooks = 0;

    for (const hook of hooks) {
      // resolve the decoders used for this hook and cache it locally
      let inArgDecoders: ParamDecoder<Java.Wrapper>[];
      let outArgDecoders: ParamDecoder<Java.Wrapper>[];
      if (hook.params) {
        const argDecoders = this.resolveParamDecoders(hook.params);
        inArgDecoders = argDecoders.filter((argDecoder) => argDecoder.direction === "in" || argDecoder.direction === "inout");
        outArgDecoders = argDecoders.filter((argDecoder) => argDecoder.direction === "out" || argDecoder.direction === "inout");
      }
      let decodedArgs: DecodedArgs = {
        in: [],
        out: [],
      };

      // resolve the return type
      let retTypeDecoder: Decoder<Java.Wrapper>;
      if (hook.method.returnType.className) {
        const retType = {
          type: hook.method.returnType.className,
          settings: hook.decoderSettings,
        };
        retTypeDecoder = this.resolveRetTypeDecoder(retType);
      }

      hook.method.implementation = function (...args: Java.Wrapper[]) {
        // collect the stack trace and filter
        let stackTrace: string[];
        try {
          stackTrace = hookManager.stackTrace.build(hook.hookSettings.stackTraceLimit, hook.hookSettings.stackTraceFilter);
        } catch (e) {
          if (e instanceof FilterMismatchError) {
            // call the original implementation and return immediately
            return hook.method.apply(this, args);
          }
          throw e; // // re-throw stack trace build error
        }

        // decode arguments onEnter
        if (hook.params) {
          try {
            decodedArgs.in = hookManager.decodeArgs(args, inArgDecoders);
          } catch (e) {
            if (!(e instanceof FilterMismatchError)) {
              frooky.log.error(`Decoder error during 'onEnter' argument decoding of ${hook.method.holder.$className}.${hook.methodName}: ${e}`);
            }
            // call the original implementation and return immediately
            return hook.method.apply(this, args);
          }
        }

        // call the original implementation
        let returnValue;
        try {
          returnValue = hook.method.apply(this, args);
        } catch (e) {
          frooky.log.error(`Error during execution of hooked method: ${e}`);
          throw e; // re-throw so the app behaves normally
        }

        // decode arguments onLeave
        if (hook.params) {
          try {
            decodedArgs.out = hookManager.decodeArgs(args, outArgDecoders);
          } catch (e) {
            if (!(e instanceof FilterMismatchError)) {
              frooky.log.error(`Decoder error during 'onLeave' argument decoding of ${hook.method.holder.$className}.${hook.methodName}: ${e}`);
            }
            return returnValue;
          }
        }

        // decode the return value
        let decodedRetValue: DecodedValue | undefined;
        try {
          if (retTypeDecoder) {
            decodedRetValue = retTypeDecoder.decode(returnValue);
          }
        } catch (e) {
          frooky.log.error(`Decoder error during return value decoding of ${hook.method.holder.$className}.${hook.methodName}: ${e}`);
          return returnValue;
        }

        // collect the field type
        const fieldType = hookManager.buildFieldType(this as Java.Wrapper);

        // add the event to the event log
        frooky.addEventToLog(new JavaHookEvent(hook, fieldType, decodedArgs, decodedRetValue, stackTrace));

        return returnValue;
      };

      countSuccessfulHooks++;
    }
    return countSuccessfulHooks;
  }

  private buildParamsFromArgumentTypes(argTypes: Java.Type[], decoderSettings: DecoderSettings): Param[] {
    return argTypes.reduce((params: Param[], type: Java.Type) => {
      if (type.className) {
        params.push({
          type: type.className,
          direction: "in",
          settings: decoderSettings,
        });
      } else {
        frooky.log.warn(`No Frida type name for the VM type ${type.name} found.`);
      }
      return params;
    }, []);
  }

  private async resolveJavaClass(javaClassName: string, timeoutSeconds: number): Promise<Java.Wrapper> {
    frooky.log.debug(`Resolving java class ${javaClassName} with a timeout of ${timeoutSeconds} seconds.`);
    return this.pollUntilResolved(
      () => {
        try {
          frooky.log.debug(`Trying to resolve Java class '${javaClassName}'.`);

          const resolvedJavaClass = Java.use(javaClassName);
          frooky.log.debug(`Java class '${javaClassName}' resolved.`);
          return resolvedJavaClass;
        } catch (_) {
          frooky.log.debug(`Java class '${javaClassName}' not resolved yet.`);
          return null;
        }
      },
      javaClassName,
      timeoutSeconds,
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
  private decodeJavaArgs(args: Java.Wrapper[], decoderCache: Decoder<Java.Wrapper>[]): DecodedValue[] {
    const decodedArgs: DecodedValue[] = [];
    decoderCache.forEach((decoder: Decoder<Java.Wrapper>, i: number) => {
      decodedArgs.push(decoder.decode(args[i]));
    });
    return decodedArgs;
  }

  private buildFieldType(method: Java.Wrapper): FieldType {
    const isStatic =
      method === null || method === undefined || method.$handle === null || method.$handle === undefined || method.$className === undefined;

    const fieldType = isStatic ? "static" : "instance";
    const instanceId = fieldType === "instance" ? method.hashCode() : undefined;
    return { fieldType, instanceId };
  }
}
