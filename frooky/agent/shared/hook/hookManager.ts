import { Hook } from "./hook";

export interface HookManager<TInputHook, THooks extends Hook> {
  resolveHooks(inputHooks: TInputHook[], moduleName?: string): Promise<THooks[]>;
  registerHooks(hooks: THooks[]): void;
}
