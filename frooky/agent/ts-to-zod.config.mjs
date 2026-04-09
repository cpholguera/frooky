/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
    {
        "name": "parameter",
        "input": "shared/hook/parameter.ts",
        "output": "shared/inputParsing/zodSchemas/parameter.zod.ts"
    },
    {
        "name": "parameter_yaml_parsing",
        "input": "shared/inputParsing/parameterInput.ts",
        "output": "shared/inputParsing/zodSchemas/parameter.yaml.parsing.zod.ts"
    },
    {
        "name": "hook",
        "input": "shared/hook/hook.ts",
        "output": "shared/inputParsing/zodSchemas/hook.zod.ts"
    },
    {
        "name": "javaHook",
        "input": "android/hook/javaHook.ts",
        "output": "shared/inputParsing/zodSchemas/javaHook.zod.ts"
    },
    {
        "name": "javaHook_yaml_parsing",
        "input": "shared/inputParsing/javaHookInput.ts",
        "output": "shared/inputParsing/zodSchemas/javaHook.yaml.parsing.zod.ts"
    },
    {
        "name": "objcHook",
        "input": "ios/hook/objcHook.ts",
        "output": "shared/inputParsing/zodSchemas/objcHook.zod.ts"
    },
    {
        "name": "objcHook_yaml_parsing",
        "input": "shared/inputParsing/objcHookInput.ts",
        "output": "shared/inputParsing/zodSchemas/objcHook.yaml.parsing.zod.ts"
    },
    {
        "name": "nativeHook",
        "input": "shared/hook/nativeHook.ts",
        "output": "shared/inputParsing/zodSchemas/nativeHook.internal.zod.ts"
    },
    {
        "name": "nativeHook_yaml_parsing",
        "input": "shared/inputParsing/nativeHookInput.ts",
        "output": "shared/inputParsing/zodSchemas/nativeHook.yaml.parsing.zod.ts"
    }
]
