import type { FrookyConfig, Platform } from "frooky";
import { log } from "shared/logger";

export function validateFrookyConfig(frookyConfig: FrookyConfig, platform: Platform){
    log.info(`Validating frooky configuration for platform ${platform}`)

    if (frookyConfig.metadata){
        log.info(`  frooky config metadata: ${JSON.stringify(frookyConfig.metadata)}`)
    } else {
        log.warn("  This frooky configuration does not have metadata. Consider adding them for better results.")
    }
    if (!frookyConfig.hooks){
        throw new Error("frooky configuration without any hook.");
    }

    log.info("  Hook configuration successfully validated.")
}