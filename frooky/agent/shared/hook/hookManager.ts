import { Hook } from "./hook";

export interface HookManager<TInputHookCanonical, THooks extends Hook> {
  resolveInputHooks(inputHooks: TInputHookCanonical[]): Promise<THooks[]>;
  registerHooks(hooks: THooks[]): void;
}
