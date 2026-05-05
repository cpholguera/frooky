import { DecoderSettings } from "../decoders/decoderSettings";
import { FrookyConfig } from "../frookyConfig";
import { HookSettings } from "./hookSettings";

export interface HookValidator<TInputHook, TInputHookCanonical, THookScope> {
  validateHooks(inputFrookyConfig: FrookyConfig, globalHookSettings: HookSettings, globalDecoderSettings: DecoderSettings): TInputHookCanonical[];
  validateAndNormalizeInputHook(
    inputHook: TInputHook,
    hookScopeHookSettings: HookSettings,
    hookScopeDecoderSettings: DecoderSettings,
    className?: string,
    moduleName?: string,
  ): TInputHookCanonical | undefined;

  getPlatformHookScopes(inputFrookyConfig: FrookyConfig): THookScope[];
}
