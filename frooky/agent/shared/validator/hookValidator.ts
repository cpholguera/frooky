import type { Hook } from "frooky";

export function validateHook(hook: Hook){
    frooky.log.info("Validating hook")
    frooky.log.info(`  Hook: ${hook}`)
}