/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
    {
        "name": "parameter",
        "input": "shared/hook/parameter.ts",
        "output": "shared/hookFileParsing/zodSchemas/parameter.zod.ts"
    },
    {
        "name": "parameter_yaml_parsing",
        "input": "shared/hookFileParsing/parameterInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/parameter.input.zod.ts"
    },
    {
        "name": "hook",
        "input": "shared/hook/hook.ts",
        "output": "shared/hookFileParsing/zodSchemas/hook.zod.ts"
    },
    {
        "name": "javaHook",
        "input": "android/hook/javaHook.ts",
        "output": "shared/hookFileParsing/zodSchemas/javaHook.zod.ts"
    },
    {
        "name": "javaHook_yaml_parsing",
        "input": "shared/hookFileParsing/javaHookInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/javaHook.input.zod.ts"
    },
    {
        "name": "objcHook",
        "input": "ios/hook/objcHook.ts",
        "output": "shared/hookFileParsing/zodSchemas/objcHook.zod.ts"
    },
    {
        "name": "objcHook_yaml_parsing",
        "input": "shared/hookFileParsing/objcHookInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/objcHook.input.zod.ts"
    },
    {
        "name": "nativeHook",
        "input": "shared/hook/nativeHook.ts",
        "output": "shared/hookFileParsing/zodSchemas/nativeHook.internal.zod.ts"
    },
    {
        "name": "nativeHook_yaml_parsing",
        "input": "shared/hookFileParsing/nativeHookInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/nativeHook.input.zod.ts"
    }
]
