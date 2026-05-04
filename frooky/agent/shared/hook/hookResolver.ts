import { Hook } from "./hook";

export interface HookResolver<TInputHookCanonical, THooks extends Hook> {
  resolveInputHooks(inputHooks: TInputHookCanonical[]): Promise<THooks[]>;
}
