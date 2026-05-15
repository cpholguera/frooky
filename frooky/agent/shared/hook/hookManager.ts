import { Decoder } from "../decoders/baseDecoder";
import { DecodedValue } from "../decoders/decodedValue";
import { HOOK_LOOKUP_INTERVAL_MS } from "../defaultValues";
import { Hook } from "./hook";

export type ParamDecoders<TValue> = {
  in: Decoder<TValue>[];
  out: Decoder<TValue>[];
};

export type DecodedArgs = {
  in?: DecodedValue[];
  out?: DecodedValue[];
};

export abstract class HookManager<TInputHook, THooks extends Hook> {
  public abstract resolveHooks(inputHooks: TInputHook[], timeout: number): Promise<Promise<THooks[] | null>[]>;
  public abstract registerHooks(hooks: THooks[]): number;

  protected async pollUntilResolved<T>(fn: () => T | null, label: string, timeoutSeconds: number): Promise<T> {
    if (timeoutSeconds < 0) throw Error(`Timeout must not be less than 0.`);
    const deadline = Date.now() + timeoutSeconds * 1000;
    while (Date.now() < deadline) {
      const result = fn();
      if (result !== null) return result;
      await new Promise((r) => setTimeout(r, HOOK_LOOKUP_INTERVAL_MS));
    }
    throw Error(`frida resolver timed out resolving '${label}' after ${timeoutSeconds} seconds.`);
  }
}
