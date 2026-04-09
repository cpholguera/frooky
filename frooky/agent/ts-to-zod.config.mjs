/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
    {
        "name": "parameter",
        "input": "shared/parameter.ts",
        "output": "shared/yamlParsing/zodSchemas/parameter.zod.ts"
    },
    {
        "name": "parameter_yaml_parsing",
        "input": "shared/yamlParsing/parameterYamlParsing.ts",
        "output": "shared/yamlParsing/zodSchemas/parameter.yaml.parsing.zod.ts"
    },
    {
        "name": "hook",
        "input": "shared/hook/hook.ts",
        "output": "shared/yamlParsing/zodSchemas/hook.zod.ts"
    },
    {
        "name": "javaHook",
        "input": "android/hook/javaHook.ts",
        "output": "shared/yamlParsing/zodSchemas/javaHook.zod.ts"
    },
    {
        "name": "javaHook_yaml_parsing",
        "input": "shared/yamlParsing/javaHookYamlParsing.ts",
        "output": "shared/yamlParsing/zodSchemas/javaHook.yaml.parsing.zod.ts"
    },
    {
        "name": "objcHook",
        "input": "ios/hook/objcHook.ts",
        "output": "shared/yamlParsing/zodSchemas/objcHook.zod.ts"
    },
    {
        "name": "objcHook_yaml_parsing",
        "input": "shared/yamlParsing/objcHookYamlParsing.ts",
        "output": "shared/yamlParsing/zodSchemas/objcHook.yaml.parsing.zod.ts"
    },
    {
        "name": "nativeHook",
        "input": "shared/hook/nativeHook.ts",
        "output": "shared/yamlParsing/zodSchemas/nativeHook.internal.zod.ts"
    },
    {
        "name": "nativeHook_yaml_parsing",
        "input": "shared/yamlParsing/nativeHookYamlParsing.ts",
        "output": "shared/yamlParsing/zodSchemas/nativeHook.yaml.parsing.zod.ts"
    }
]
