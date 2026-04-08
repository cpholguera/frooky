import type { FrookyConfig, HookMetadata, Platform } from "frooky";
import { type HookValidatorResult, validateHooks } from "./hookValidator";


export interface ConfigValidationResult {
    metadata?: HookMetadata;
    hookParsingResult: HookValidatorResult;
}

export function validateFrookyConfig(frookyConfig: FrookyConfig, platform: Platform): ConfigValidationResult{
    frooky.log.info(`Validating frooky configuration for platform ${platform}`)

    // validate metadata
    if (frookyConfig.metadata){
        frooky.log.info(`frooky config metadata:\n${JSON.stringify(frookyConfig.metadata, null, 2)}`)
    } else {
       frooky.log.warn("This frooky configuration does not have metadata. Consider adding them for better results.")
    }
 
    // validate hooks
    const result = validateHooks(frookyConfig, platform);
    
    // skip adding metadata if all hooks were invalid
    if (result.totalHooks === result.totalErrors) {
        frooky.log.warn("No hook was valid. Make sure that the hooks are compatible to your platform.")
    }

    frooky.log.info("Hook configuration successfully validated.")

    return { hookParsingResult: result, metadata: frookyConfig.metadata };
}