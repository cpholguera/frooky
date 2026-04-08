// // This file is used when the agent is run by frooky. Hooks are dynamically loaded using rpc at runtime.

// import ObjC from "frida-objc-bridge";
// import type { FrookyConfig } from "frooky";
// import { FrookyApp } from "../FrookyApp";

// if (ObjC.available) {
//   rpc.exports = {
//     runFrookyAgent(frookyConfig: FrookyConfig) {
//       globalThis.frooky = new FrookyApp("iOS");
//       frooky.loadFrookyConfig(frookyConfig);

//       frooky.prepareHookOperation();
//       frooky.executeHookOperations();

//     }
//   };
// } else {
//   console.error("[!] The agent is not run on an iOS device. Make sure to run this version of the frooky agent on iOS.")
// }


throw Error("This is the PoC branch for the agent refactoring. At the moment, iOS is not yet implemented.")