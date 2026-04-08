import type { FrookyConfig, Platform } from "frooky";
import { type HookValidatorResult, validateHooks } from "./hookValidator";


export function validateFrookyConfig(frookyConfig: FrookyConfig, platform: Platform): HookValidatorResult{
    frooky.log.info(`Validating frooky configuration for platform ${platform}`)

    if(!frookyConfig){
        throw Error("No or empty frooky configuration provided.")
    }

    // validate configuration metadata
    if (frookyConfig.metadata){
        frooky.log.info(`frooky config metadata:\n${JSON.stringify(frookyConfig.metadata, null, 2)}`)
        if(frookyConfig.metadata.platform?.toLowerCase() !== platform.toLocaleLowerCase()){
            frooky.log.warn(`The platform declared in the frooky configuration does not match the actual platform (${platform}). Not all hooks may be valid.`)
        }
    } else {
       frooky.log.warn("This frooky configuration does not have metadata. Consider adding them for better results.")
    }
 
    // validate hooks

    let hookValidatorResult: HookValidatorResult;
    if(frookyConfig.hooks){
        hookValidatorResult = validateHooks(frookyConfig.hooks, platform, frookyConfig.metadata);

        frooky.log.info("Hook configuration validated.")
        return hookValidatorResult 

    } else {
        throw Error("Config file does not have any hooks declared.")
    }
    

}