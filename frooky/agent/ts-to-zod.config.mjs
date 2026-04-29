/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
    // source: shared/hook
    {
        "name": "hook",
        "input": "shared/hook/hook.ts",
        "output": "shared/hookFileParsing/zodSchemas/hook.zod.ts"
    },

    // source: shared/hookFileParsing
    {
        "name": "param_yaml_input_parsing",
        "input": "shared/hookFileParsing/decodableTypesInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/decodableTypesInput.zod.ts"
    },
    {
        "name": "javaHook_yaml_input_parsing",
        "input": "shared/hookFileParsing/javaHookInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/javaHookInput.zod.ts"
    },
    {
        "name": "objcHook_yaml_input_parsing",
        "input": "shared/hookFileParsing/objcHookInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/objcHookInput.zod.ts"
    },
    {
        "name": "nativeHook_yaml_input_parsing",
        "input": "shared/hookFileParsing/nativeHookInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/nativeHookInputInput.zod.ts"
    },
    {
        "name": "settings_yaml_input_parsing",
        "input": "shared/hookFileParsing/settingsInput.ts",
        "output": "shared/hookFileParsing/zodSchemas/settingsInput.zod.ts"
    },

    // source: shared/decoders/
    {
        "name": "decoder_setting",
        "input": "shared/decoders/decoderSettings.ts",
        "output": "shared/hookFileParsing/zodSchemas/decoderSettings.zod.ts"
    },

    // source: various rest
    {
        "name": "javaHook",
        "input": "android/hook/javaHook.ts",
        "output": "shared/hookFileParsing/zodSchemas/javaHook.zod.ts"
    },

    {
        "name": "objcHook",
        "input": "ios/hook/objcHook.ts",
        "output": "shared/hookFileParsing/zodSchemas/objcHook.zod.ts"
    },

    {
        "name": "nativeHook",
        "input": "native/hook/nativeHook.ts",
        "output": "shared/hookFileParsing/zodSchemas/nativeHook.internal.zod.ts"
    },

    {
        "name": "frooky_config",
        "input": "shared/frookyConfig.ts",
        "output": "shared/hookFileParsing/zodSchemas/frookyConfig.zod.ts"
    },


]
