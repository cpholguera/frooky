import type { FrookyConfig, Platform } from "frooky";
import { frookyConfigSchema } from "./zodSchemas/frookyConfig.zod";

export function validateFrookyConfig(frookyConfig: FrookyConfig, platform: Platform){
    frooky.log.info(`Validating frooky configuration for platform ${platform}`)

    try {
        frookyConfigSchema.parse(frookyConfig)
    } catch (error) {
        frooky.log.error(`Invalid frooky configuration: ${error}`);
    }

    if (frookyConfig.metadata){
        frooky.log.info(`frooky config metadata: ${JSON.stringify(frookyConfig.metadata)}`)
    } else {
        frooky.log.warn("This frooky configuration does not have metadata. Consider adding them for better results.")
    }

    frooky.log.info("  Hook configuration successfully validated.")
}