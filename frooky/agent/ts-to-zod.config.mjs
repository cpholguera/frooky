/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
    {"name":"parameter","input":"types/parameter.d.ts","output":"types/parameter.zod.ts"},
    {"name":"returnType","input":"types/returnType.d.ts","output":"types/returnType.zod.ts"},

    {"name":"baseHook",  "input":"types/hook/baseHook.d.ts","output":"types/hook/baseHook.zod.ts"},
    {"name":"javaHook",  "input":"types/hook/javaHook.d.ts","output":"types/hook/javaHook.zod.ts"},
    {"name":"objcHook",  "input":"types/hook/objcHook.d.ts","output":"types/hook/objcHook.zod.ts"},
    {"name":"nativeHook","input":"types/hook/nativeHook.d.ts","output":"types/hook/nativeHook.zod.ts"}
]