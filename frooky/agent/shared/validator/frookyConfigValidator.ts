import type { FrookyConfig, Platform } from "frooky";

export function validateFrookyConfig(frookyConfig: FrookyConfig, platform: Platform){
    frooky.log.info(`Validating frooky configuration for platform ${platform}`)

    if (frookyConfig.metadata){
        frooky.log.info(`  frooky config metadata: ${JSON.stringify(frookyConfig.metadata)}`)
    } else {
        frooky.log.warn("  This frooky configuration does not have metadata. Consider adding them for better results.")
    }
    if (!frookyConfig.hooks){
        throw new Error("frooky configuration without any hook.");
    }

    frooky.log.info("  Hook configuration successfully validated.")
}