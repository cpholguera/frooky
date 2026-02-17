import * as Frooky from 'frooky'

import {
    wifiHook,
    locationHook,
    urlHook,
    intentHook,
    intentFlagsHook,
    activityHook,
    sqliteHook,
    cipherHook,
    bufferHook,
    webViewHook
} from "../typeScript/01_android"
import {
    openHook,
    readHook,
    encryptHook,
    sslWriteHook,
    opensslHook,
    customDecoderHook,
    outputParamHook
} from "./03_native"
import {
    userDefaultsObjCHook,
    nsDataHook,
    urlHook as urlObjCHook,
    laContextHook,
    keychainHook as keychainObjCHook,
    coreDataHook,
    urlSessionHook,
    dataProcessingHook
} from "./02_objc"


// ============================================================================
// Android test configuration with all Java and native hooks
// ============================================================================
const androidHooks: Frooky.FrookyConfig = {
    metadata: {
        name: 'Android Hook Type Tests',
        platform: 'Android',
        description: 'Test suite for Java and native hook configurations on Android',
        author: 'Frooky Development Team',
        version: 'v1'
    },
    hooks: [
        // Java hooks
        wifiHook,
        locationHook,
        urlHook,
        intentHook,
        intentFlagsHook,
        activityHook,
        sqliteHook,
        cipherHook,
        bufferHook,
        webViewHook,
        // Native hooks (Android)
        openHook,
        readHook,
        encryptHook,
        sslWriteHook,
        opensslHook,
        customDecoderHook,
        outputParamHook
    ]
}

// ============================================================================
// iOS test configuration with all Swift and Objective-C hooks
// ============================================================================
const iosHooks: Frooky.FrookyConfig = {
    metadata: {
        name: 'iOS Hook Type Tests',
        platform: 'iOS',
        description: 'Test suite for Swift and Objective-C hook configurations on iOS',
        author: 'Frooky Development Team',
        version: 'v1'
    },
    hooks: [
        // Objective-C hooks
        userDefaultsObjCHook,
        nsDataHook,
        urlObjCHook,
        laContextHook,
        keychainObjCHook,
        coreDataHook,
        urlSessionHook,
        dataProcessingHook
    ]
}

// ============================================================================
// Minimal configuration without metadata (testing optional fields)
// ============================================================================
const minimalAndroidHooks: Frooky.FrookyConfig = {
    hooks: [
        wifiHook,
        intentHook
    ]
}

const minimalIosHooks: Frooky.FrookyConfig = {
    hooks: [
        userDefaultsObjCHook,
        laContextHook
    ]
}

// ============================================================================
// Configuration with partial metadata
// ============================================================================
const partialMetadataHooks: Frooky.FrookyConfig = {
    metadata: {
        name: 'Partial Metadata Test',
        platform: 'Android'
        // Other fields intentionally omitted to test optional properties
    },
    hooks: [
        wifiHook,
        openHook
    ]
}

// Export for use in Frida agent
export { 
    androidHooks, 
    iosHooks,
    minimalAndroidHooks,
    minimalIosHooks,
    partialMetadataHooks
}
