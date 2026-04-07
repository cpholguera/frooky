import type { Hook } from "frooky";
import { log } from "shared/logger";

export function validateHook(hook: Hook){
    log.info("Validating hook")
    log.info(`  Hook: ${hook}`)
}