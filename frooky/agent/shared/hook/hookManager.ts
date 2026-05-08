import { Hook } from "./hook";

export abstract class HookManager<TInputHook, THooks extends Hook> {
  abstract resolveHooks(inputHooks: TInputHook[], timeout: number): Promise<Promise<THooks | null>[]>;
  abstract registerHook(hook: THooks): THooks;
}
