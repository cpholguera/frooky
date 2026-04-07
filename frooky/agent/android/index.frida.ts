// This file is used when the agent is run by frida. Hooks embedded into the agent at build time.

import type { FrookyConfig } from "frooky";
import { FrookyApp } from "../Frooky";

// !!!! Don't change this line, the build script will insert the actual frooky config here
const frookyConfig = { } as FrookyConfig;

globalThis.frooky = new FrookyApp("Android", 3, "device");
frooky.addFrookyConfig(frookyConfig);
frooky.run(); 