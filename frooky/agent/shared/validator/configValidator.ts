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
    const result = validateHooks(frookyConfig);

    frooky.log.info("Hook configuration successfully validated.")

    return { hookParsingResult: result, metadata: frookyConfig.metadata };
}