/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
    {
        "name": "param",
        "input": "shared/hook/param.ts",
        "output": "shared/hookFileParsing/zodSchemas/param.zod.ts"
    },
    {
        "name": "param_yaml_parsing",
        "input": "shared/hookFileParsing/paramInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/param.input.zod.ts"
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
        "input": "native/hook/nativeHook.ts",
        "output": "shared/hookFileParsing/zodSchemas/nativeHook.internal.zod.ts"
    },
    {
        "name": "nativeHook_yaml_parsing",
        "input": "shared/hookFileParsing/nativeHookInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/nativeHook.input.zod.ts"
    },
    {
        "name": "frooky_config",
        "input": "shared/frookyConfig.ts",
        "output": "shared/hookFileParsing/zodSchemas/frookyConfig.zod.ts"
    },
    {
        "name": "settings_yaml_parsing",
        "input": "shared/hookFileParsing/settingsInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/settingsInput.zod.ts"
    },
    {
        "name": "decoder_setting",
        "input": "shared/decoders/decoderSettings.ts",
        "output": "shared/hookFileParsing/zodSchemas/decoderSettings.zod.ts"
    }
]
