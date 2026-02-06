import * as Frooky from 'frooky'
import {
    wifiHook,
    locationHook,
    urlHook,
    intentHook
} from "./01_android"
import {
    openHook,
    readHook
} from "./02_native"
import {
    userDefaultsHook,
    fileManagerHook,
} from "./03_swift"
import {
    userDefaultsObjCHook,
    nsDataHook
} from "./04_objc"


// ============================================================================
// Complete configuration with multiple hooks
// ============================================================================
const androidHooks: Frooky.Hooks = {
    category: 'NETWORK',
    hooks: [
        wifiHook,
        locationHook,
        urlHook,
        intentHook,
        openHook,
        readHook
    ]
}

const iosHooks: Frooky.Hooks = {
    category: 'STORAGE',
    hooks: [
        userDefaultsHook,
        fileManagerHook,
        userDefaultsObjCHook,
        nsDataHook
    ]
}

// Export for use in Frida agent
export { androidHooks, iosHooks }
