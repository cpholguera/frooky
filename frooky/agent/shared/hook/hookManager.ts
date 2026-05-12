import { Decoder } from "../decoders/baseDecoder";
import { Decodable } from "../decoders/decodable";
import { DecodedValue } from "../decoders/decodedValue";
import { HOOK_LOOKUP_INTERVAL_MS } from "../defaultValues";
import { Hook } from "./hook";

export type ParamDecoders<TDecodable extends Decodable, TValue> = {
  enter: Decoder<TDecodable, TValue>[];
  exit: Decoder<TDecodable, TValue>[];
};

export type DecodedArgs = {
  enter?: DecodedValue[];
  exit?: DecodedValue[];
};

export abstract class HookManager<TInputHook, THooks extends Hook> {
  public abstract resolveHooks(inputHooks: TInputHook[], timeout: number): Promise<Promise<THooks[] | null>[]>;
  public abstract registerHooks(hooks: THooks[]): THooks[];

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
