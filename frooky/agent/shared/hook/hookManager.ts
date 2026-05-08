import { Hook } from "./hook";

export interface HookManager<TInputHook, THooks extends Hook> {
  resolveHooks(inputHooks: TInputHook[]): Promise<THooks[]>;
  registerHooks(hooks: THooks[]): void;
}
