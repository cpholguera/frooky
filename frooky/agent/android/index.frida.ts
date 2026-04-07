// This file is used when the agent is run by frida. Hooks embedded into the agent at build time.
// !!!! Don't change this file, the build script will insert the actual frooky config here

import type { FrookyConfig } from "frooky";
import { FrookyApp } from "../FrookyApp";

var frookyConfigs: FrookyConfig[]

//%%% REPLACE START
frookyConfigs = { } as FrookyConfig[];
//%%% REPLACE STOP

globalThis.frooky = new FrookyApp("Android", 3, "device");
frookyConfigs.forEach(frookyConfig => {
    frooky.addFrookyConfig(frookyConfig);
});
frooky.run(); 