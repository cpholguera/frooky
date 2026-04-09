/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
    {"name":"parameter_internal","input":"types/parameter.ts","output":"types/yamlParsing/zodSchemas/parameter.internal.zod.ts"},
    {"name":"parameter","input":"types/yamlParsing/parameter.ts","output":"types/yamlParsing/zodSchemas/parameter.yaml.zod.ts"},

    {"name":"baseHook",  "input":"types/hook/baseHook.ts","output":"types/yamlParsing/zodSchemas/baseHook.internal.zod.ts"},

    {"name":"javaHook_internal",  "input":"types/hook/javaHook.ts","output":"types/yamlParsing/zodSchemas/javaHook.internal.zod.ts"},
    {"name":"javaHook",  "input":"types/yamlParsing/hook/javaHook.ts","output":"types/yamlParsing/zodSchemas/javaHook.yaml.zod.ts"},

    {"name":"objcHook_internal",  "input":"types/hook/objcHook.ts","output":"types/yamlParsing/zodSchemas/objcHook..internal.zod.ts"},
    {"name":"objcHook",  "input":"types/yamlParsing/hook/objcHook.ts","output":"types/yamlParsing/zodSchemas/objcHook.yaml.zod.ts"},

    {"name":"nativeHook","input":"types/hook/nativeHook.ts","output":"types/yamlParsing/zodSchemas/nativeHook.internal.zod.ts"}

]