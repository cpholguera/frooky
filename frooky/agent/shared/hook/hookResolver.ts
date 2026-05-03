import { Hook } from "./hook";

export interface HookResolver<TInputHookCanonical, THooks extends Hook> {
  resolve(inputHooks: TInputHookCanonical[]): Promise<THooks[]>;
}
