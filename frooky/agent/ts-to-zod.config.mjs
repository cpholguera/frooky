/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
    {"name":"parameter","input":"types/parameter.d.ts","output":"shared/validator/zodSchemas/parameter.zod.ts"},
    {"name":"returnType","input":"types/returnType.d.ts","output":"shared/validator/zodSchemas/returnType.zod.ts"},

    {"name":"baseHook",  "input":"types/hook/baseHook.d.ts","output":"shared/validator/zodSchemas/hook/baseHook.zod.ts"},
    {"name":"javaHook",  "input":"types/hook/javaHook.d.ts","output":"shared/validator/zodSchemas/hook/javaHook.zod.ts"},
    {"name":"objcHook",  "input":"types/hook/objcHook.d.ts","output":"shared/validator/zodSchemas/hook/objcHook.zod.ts"},
    {"name":"nativeHook","input":"types/hook/nativeHook.d.ts","output":"shared/validator/zodSchemas/hook/nativeHook.zod.ts"},

    {"name":"frookyConfig","input":"types/frookyConfig.d.ts","output":"shared/validator/zodSchemas/frookyConfig.zod.ts"},

]