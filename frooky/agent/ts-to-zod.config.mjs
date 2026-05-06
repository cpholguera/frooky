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
        "output": "shared/inputParsing/zodSchemas/decoderSettings.zod.ts"
    },

    {
        "name": "hook_settings",
        "input": "shared/hook/hookSettings.ts",
        "output": "shared/inputParsing/zodSchemas/hookSettings.zod.ts"
    },

    {
        "name": "hook_metadata",
        "input": "shared/frookyMetadata.ts",
        "output": "shared/inputParsing/zodSchemas/frookyMetadata.zod.ts"
    },


    // 2. Types used in the input YAMLs. They usually have less strict requirements or multiple ways of declaring a method, function parameter etc.
    // These are the types used to validate the input YAML
   {
        "name": "hook_decoder_settings_input",
        "input": "shared/inputParsing/inputSettings.ts",
        "output": "shared/inputParsing/zodSchemas/inputSettings.zod.ts"
    },
    
    {
        "name": "java_hook_scope",
        "input": "shared/inputParsing/inputJavaHookGroup.ts",
        "output": "shared/inputParsing/zodSchemas/inputJavaHookGroup.zod.ts"
    },
    
    {
        "name": "native_hook_scope",
        "input": "shared/inputParsing/inputNativeHookGroup.ts",
        "output": "shared/inputParsing/zodSchemas/inputNativeHookGroup.zod.ts"
    },

    {
        "name": "decodable_types_input",
        "input": "shared/inputParsing/inputDecodableTypes.ts",
        "output": "shared/inputParsing/zodSchemas/inputDecodableTypes.zod.ts"
    }
]
