/**
 * ts-to-zod configuration.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [

    // 1. Internal Types
    // These types are only used internally, but ZOD needs them as reference wen validating te INPUT YAMLs

    {
        "name": "frooky_settings",
        "input": "shared/frookySettings.ts",
        "output": "shared/inputParsing/zodSchemas/frookySettings.zod.ts"
    },

    {
        "name": "logger",
        "input": "shared/logger.ts",
        "output": "shared/inputParsing/zodSchemas/logger.zod.ts"
    },


    // 2. Types used in the input YAMLs. They usually have less strict requirements or multiple ways of declaring a method, function parameter etc.
    // These are the types used to validate the input YAML
    
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
    },

    {
        "name": "frooky_config",
        "input": "shared/frookyConfig.ts",
        "output": "shared/inputParsing/zodSchemas/frookyConfig.zod.ts"
    },

    {
        "name": "frooky_metadata",
        "input": "shared/frookyMetadata.ts",
        "output": "shared/inputParsing/zodSchemas/frookyMetadata.zod.ts"
    },
    {
        "name": "hook_decoder_settings_input",
        "input": "shared/inputParsing/inputSettings.ts",
        "output": "shared/inputParsing/zodSchemas/inputSettings.zod.ts"
    },
]
