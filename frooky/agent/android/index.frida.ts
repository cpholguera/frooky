// This file is used when the agent is run by frida. Hooks embedded into the agent at build time.

import { target } from './_hooks.ts';
import "../shared/Frooky.ts"

frooky.init(target, "android", true); 
