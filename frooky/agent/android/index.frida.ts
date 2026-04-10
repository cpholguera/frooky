// This file is used when the agent is run by frida. Hooks embedded into the agent at build time.
// !!!! Don't change this file, the build script will insert the actual frooky config here

import Java from "frida-java-bridge";
import type { FrookyConfig } from "frooky";
import { FrookyApp } from "../FrookyApp";
import { JavaHookRunner } from "./hook/javaHookRunner";

var frookyConfigs: FrookyConfig[];

if (Java.available) {

//%%% REPLACE START
	frookyConfigs = {} as FrookyConfig[];
//%%% REPLACE STOP

	globalThis.frooky = new FrookyApp("Android", new JavaHookRunner(),  3, "device");
	frookyConfigs.forEach(frookyConfig => {
		frooky.loadFrookyConfig(frookyConfig);
	});


	Java.perform(() => {
		frooky.executeHookOperations();
	}) 

} else {
	console.error("[!] The agent is not run on an Android device. Make sure to run this version of the frooky agent on Android.")
}