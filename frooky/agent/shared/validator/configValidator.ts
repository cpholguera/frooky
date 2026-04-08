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
        if(frookyConfig.metadata.platform?.toLowerCase() !== platform.toLocaleLowerCase()){
            frooky.log.warn(`The declared platform (${frookyConfig.metadata.platform}) in the frooky configuration does not match the actual platform (${platform}). Not all hooks may be valid.`)
        }
    } else {
       frooky.log.warn("This frooky configuration does not have metadata. Consider adding them for better results.")
    }
 
    // validate hooks
    const result = validateHooks(frookyConfig, platform);
    
    frooky.log.info("Hook configuration validated.")

    // if all hooks are invalid, return an empty ConfigValidationResult
    if (result.totalHooks === result.totalErrors) {
        return { hookParsingResult: result }
    } else {
        return { hookParsingResult: result, metadata: frookyConfig.metadata };
    }
}