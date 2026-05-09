import { DecodedValue, HookManager, InputNativeHookNormalized } from "../../shared";
import { NativeDecoder } from "../decoders/nativeDecoder";
import { NativeHook } from "./nativeHook";
import { buildAndDispatchEvent, buildNativeStackTrace, decodeNativeArgs } from "./nativeHookImpl";

export class NativeHookManager extends HookManager<InputNativeHookNormalized, NativeHook> {
  public async resolveHooks(inputHooks: InputNativeHookNormalized[], timeout: number): Promise<Promise<NativeHook[] | null>[]> {
    frooky.log.info(`Resolving native hooks`);

    const uniqueModules: string[] = [...new Map(inputHooks.map((inputHook) => [inputHook.module, inputHook])).keys()];

    return uniqueModules.flatMap((moduleName) => {
      const modulePromise = this.resolveModule(moduleName, timeout).catch((e) => {
        frooky.log.warn(`${e}`);
        return null;
      });

      return inputHooks
        .filter((inputHook) => inputHook.module === moduleName)
        .map(async (inputHook): Promise<NativeHook[] | null> => {
          const resolvedModule = await modulePromise;
          if (!resolvedModule) return null;
          try {
            const symbolAddress = this.resolveSymbol(inputHook.symbol, resolvedModule);
            frooky.log.info(`Address of function symbol '${inputHook.symbol}' found: ${symbolAddress}.`);
            return [
              {
                module: resolvedModule,
                symbolName: inputHook.symbol,
                symbolAddress,
                params: inputHook.params,
                retType: inputHook.retType,
                hookSettings: inputHook.hookSettings,
                decoderSettings: inputHook.decoderSettings,
              },
            ] as NativeHook[];
          } catch (e) {
            frooky.log.warn(`${e}`);
            return null;
          }
        });
    });
  }

  public registerHooks(hooks: NativeHook[]): NativeHook[] {
    for (const hook of hooks) {
      let stackTrace: string[];
      let decodedArgs: DecodedValue[];
      let decodedReturnValue: DecodedValue;
      Interceptor.attach(hook.symbolAddress, {
        onEnter: function (args: NativePointer[]) {
          // collect the stack trace from Frida
          const stackTraceLimit: number = hook.hookSettings.stackTraceLimit;
          stackTrace = buildNativeStackTrace(this.context, stackTraceLimit);
          // decode the arguments passed to this function
          if (hook.params) {
            decodedArgs = decodeNativeArgs(args, hook.params);
          }
        },
        onLeave: (returnValue: InvocationReturnValue) => {
          // decode the return value
          if (hook.retType) {
            decodedReturnValue = NativeDecoder.decode(returnValue, hook.retType, hook.decoderSettings);
          } else {
            decodedReturnValue = { type: "void", value: null };
          }
          // create a frooky hook event and send it to the event cache
          buildAndDispatchEvent(hook, decodedArgs, decodedReturnValue, stackTrace);
        },
      });
    }
    return hooks;
  }

  private resolveSymbol(symbol: string, module: Module): NativePointer {
    try {
      frooky.log.debug(`Resolving symbol '${symbol}' in module '${module.name}'.`);
      return module.getExportByName(symbol);
    } catch (e) {
      throw Error(`Skipping hook for native function '${symbol}'. This symbol does not exist in module '${module.name}'.`);
    }
  }

  private async resolveModule(moduleName: string, timeout: number): Promise<Module> {
    frooky.log.info(`Resolving native module ${moduleName} with a timeout of ${timeout} seconds.`);
    return this.pollUntilResolved(
      () => {
        try {
          frooky.log.debug(`Trying to resolve module '${moduleName}'.`);
          const module = Process.getModuleByName(moduleName);
          frooky.log.info(`Module '${moduleName}' successfully loaded.`);
          return module;
        } catch (_) {
          frooky.log.debug(`Module '${moduleName}' not resolved yet.`);
          return null;
        }
      },
      moduleName,
      timeout,
    );
  }
}
