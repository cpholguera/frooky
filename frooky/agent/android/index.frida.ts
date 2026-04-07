// This file is used when the agent is run by frida. Hooks embedded into the agent at build time.

import { frookyConfig } from "../shared/_frookyConfig";
import { FrookyApp } from "../shared/Frooky";

globalThis.frooky = new FrookyApp("android", true);
frooky.loadFrookyConfig(frookyConfig);
frooky.run();