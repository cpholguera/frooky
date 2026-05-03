/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [

    // 1. Internal Types
    // These types are only used internally, but ZOD needs them as reference wen validating te INPUT YAMLs

    {
        "name": "decoder_settings",
        "input": "shared/decoders/decoderSettings.ts",
        "output": "shared/frookyConfigParsing/zodSchemas/decoderSettings.zod.ts"
    },

    {
        "name": "hook_settings",
        "input": "shared/hook/hookSettings.ts",
        "output": "shared/frookyConfigParsing/zodSchemas/hookSettings.zod.ts"
    },

    {
        "name": "hook_metadata",
        "input": "shared/frookyMetadata.ts",
        "output": "shared/frookyConfigParsing/zodSchemas/frookyMetadata.zod.ts"
    },


    // 2. Types used in the input YAMLs. They usually have less strict requirements or multiple ways of declaring a method, function parameter etc.
    // These are the types used to validate the input YAML
   {
        "name": "hook_decoder_settings_input",
        "input": "shared/frookyConfigParsing/settingsInput.ts",
        "output": "shared/frookyConfigParsing/zodSchemas/settingsInput.zod.ts"
    },
    
    {
        "name": "java_hook_scope",
        "input": "shared/frookyConfigParsing/javaHookScope.ts",
        "output": "shared/frookyConfigParsing/zodSchemas/javaHookScope.zod.ts"
    },
    
    {
        "name": "native_hook_scope",
        "input": "shared/frookyConfigParsing/nativeHookScope.ts",
        "output": "shared/frookyConfigParsing/zodSchemas/nativeHookScope.zod.ts"
    },

    {
        "name": "decodable_types_input",
        "input": "shared/frookyConfigParsing/decodableTypesInput.ts",
        "output": "shared/frookyConfigParsing/zodSchemas/decodableTypesInput.zod.ts"
    }
]
