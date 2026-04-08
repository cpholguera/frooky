/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
    {"name":"parameter","input":"types/parameter.ts","output":"types/parameter.zod.ts"},
    {"name":"returnType","input":"types/returnType.ts","output":"types/returnType.zod.ts"},

    {"name":"baseHook",  "input":"types/hook/baseHook.ts","output":"types/hook/baseHook.zod.ts"},
    {"name":"javaHook",  "input":"types/hook/javaHook.ts","output":"types/hook/javaHook.zod.ts"},
    {"name":"objcHook",  "input":"types/hook/objcHook.ts","output":"types/hook/objcHook.zod.ts"},
    {"name":"nativeHook","input":"types/hook/nativeHook.ts","output":"types/hook/nativeHook.zod.ts"}
]