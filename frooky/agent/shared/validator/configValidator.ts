import type { FrookyConfig, Platform } from "frooky";
import { type HookValidatorResult, validateHooks } from "./hookValidator";


export function validateFrookyConfig(frookyConfig: FrookyConfig, platform: Platform): HookValidatorResult{
    frooky.log.info(`Validating frooky configuration for platform ${platform}`)

    // validate configuration metadata
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
    return result
}