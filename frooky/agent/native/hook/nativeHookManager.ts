import { Decoder, DecoderArgs } from "../../shared/decoders/baseDecoder";
import { Param, RetType } from "../../shared/decoders/decodable";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { DecodedArgs, HookManager, ParamDecoders } from "../../shared/hook/hookManager";
import { InputNativeHookNormalized } from "../../shared/inputParsing/inputNativeHookGroup";
import { NativeDecoderResolver } from "../decoders/nativeDecoderResolver";
import { NativeHook } from "./nativeHook";
import { NativeHookEvent } from "./nativeHookEvent";

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
    const hookManager = this;
    for (const hook of hooks) {
      let stackTrace: string[];

      // resolve the decoders used for this hook and cache it locally
      let paramDecoders: ParamDecoders<NativePointer>;
      if (hook.params) {
        paramDecoders = this.resolveParamDecoders(hook.params);
      }
      let retTypeDecoder: Decoder<NativePointer>;
      if (hook.retType) {
        retTypeDecoder = this.resolveRetTypeDecoder(hook.retType);
      }
      let decodedArgs: DecodedArgs = {
        enter: [],
        exit: [],
      };

      Interceptor.attach(hook.symbolAddress, {
        onEnter: function (args: NativePointer[]) {
          // build stack trace
          const stackTraceLimit: number = hook.hookSettings.stackTraceLimit;
          stackTrace = hookManager.buildNativeStackTrace(this.context, stackTraceLimit);

          if (hook.params) {
            // decode arguments onEnter
            this.savedArgs = [];
            for (let i = 0; i < hook.params.length; i++) {
              this.savedArgs[i] = args[i];
            }
            decodedArgs.enter = hookManager.decodeNativeArgs(args, paramDecoders.enter, hook.params);
          }
        },
        onLeave: function (returnValue: InvocationReturnValue) {
          if (hook.params) {
            // decode arguments onExit
            decodedArgs.exit = hookManager.decodeNativeArgs(this.savedArgs, paramDecoders.exit, hook.params);
          }

          let decodedRetValue: DecodedValue | undefined;
          if (hook.retType) {
            decodedRetValue = retTypeDecoder.decode(returnValue);
          }

          frooky.addEvent(new NativeHookEvent(hook, decodedArgs, decodedRetValue, stackTrace));
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

  private buildNativeStackTrace(ctx: CpuContext, limit: number): string[] {
    const stackTrace: string[] = [];
    try {
      const btFull = Thread.backtrace(ctx, Backtracer.FUZZY);
      const count = Math.min(limit, btFull.length);
      for (let i = 0; i < count; i++) {
        try {
          stackTrace.push(DebugSymbol.fromAddress(btFull[i]).toString());
        } catch (e) {
          frooky.log.error(`Error during stack trace capture: ${e}`);
        }
      }
    } catch (e) {
      frooky.log.warn(`Native backtrace unavailable: ${e}`);
    }
    return stackTrace;
  }

  private resolveParamDecoders(params: Param[]): ParamDecoders<NativePointer> {
    const paramDecoders: ParamDecoders<NativePointer> = {
      enter: [],
      exit: [],
    };
    for (const param of params) {
      const { decodeAt, ...decodable } = param;
      if (decodeAt === "both" || decodeAt === "enter") {
        paramDecoders.enter.push(NativeDecoderResolver.resolveDecoder(decodable));
      }
      if (decodeAt === "both" || decodeAt === "exit") {
        paramDecoders.exit.push(NativeDecoderResolver.resolveDecoder(decodable));
      }
    }
    return paramDecoders;
  }

  private resolveRetTypeDecoder(retType: RetType): Decoder<NativePointer> {
    return NativeDecoderResolver.resolveDecoder(retType);
  }

  private decodeNativeArgs(args: NativePointer[], decoderCache: Decoder<NativePointer>[], params?: Param[]): DecodedValue[] {
    const decodedArgs: DecodedValue[] = [];
    decoderCache.forEach((decoder: Decoder<NativePointer>, i: number) => {
      // TODO: Should be generalized to be reused by android and ios code
      let decoderArgs: DecoderArgs<NativePointer>[] = [];
      if (params && params[i].settings.decoderArgs.length > 0) {
        for (const argName of params[i].settings.decoderArgs) {
          params.forEach((param: Param, j: number) => {
            if (param.name === argName) {
              decoderArgs.push({
                arg: args[j],
                decoder: NativeDecoderResolver.resolveDecoder(param),
                name: param.name,
              });
            }
          });
        }
      }
      decodedArgs.push(decoder.decode(args[i], decoderArgs));
    });
    return decodedArgs;
  }
}
