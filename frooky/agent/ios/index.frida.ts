// // This file is used when the agent is run by frida. Hooks embedded into the agent at build time.
// // !!!! Don't change this file, the build script will insert the actual frooky config here
// import ObjC from "frida-objc-bridge";
// import type { FrookyConfig } from "frooky";
// import { FrookyApp } from "../FrookyApp";

// var frookyConfigs: FrookyConfig[];

// if (ObjC.available) {
// //%%% REPLACE START
//     frookyConfigs = { } as FrookyConfig[];
// //%%% REPLACE STOP

//     globalThis.frooky = new FrookyApp("iOS", 3, "device");
//     frookyConfigs.forEach(frookyConfig => {
//         frooky.loadFrookyConfig(frookyConfig);
//     });
//     frooky.prepareHookOperation();
//     frooky.executeHookOperations();

// } else {
//   console.error("[!] The agent is not run on an iOS device. Make sure to run this version of the frooky agent on iOS.")
// }

throw Error("This is the PoC branch for the agent refactoring. At the moment, iOS is not yet implemented.");
