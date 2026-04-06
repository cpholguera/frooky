// run-tests.js

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import frida from "frida";
import minimist from "minimist";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const argv = minimist(process.argv.slice(2), {
  string: ["platform", "appIdentifier"],
  boolean: ["help", "usb"],
  alias: {
    p: "platform",
    h: "help",
    u: "usb",
  },
});

const help = argv.help;
const usb = argv.usb;
const platform = argv.platform;
const appIdentifier = Number.isFinite(Number(argv.appIdentifier)) ? Number(argv.appIdentifier) : argv.appIdentifier;

if (help) {
  showHelp();
}

validateInput(argv);

async function runTests() {
  let session;
  let device;
  let pid;
  let wasSpawned = false;

  device = usb ? await frida.getUsbDevice() : await frida.getLocalDevice();

  if (Number.isFinite(appIdentifier)) {
    // Attach to an already-running process by PID
    pid = appIdentifier;
    session = await device.attach(pid);
  } else {
    // String input supports both bundle/package identifier (spawn) and process name (attach)
    try {
      pid = await device.spawn(appIdentifier);
      wasSpawned = true;
      session = await device.attach(pid);
    } catch {
      const processes = await device.enumerateProcesses();
      const target = processes.find((proc) => proc.name === appIdentifier) || processes.find((proc) => proc.name.toLowerCase() === String(appIdentifier).toLowerCase()) || processes.find((proc) => proc.name.toLowerCase().includes(String(appIdentifier).toLowerCase()));

      if (!target) {
        throw new Error(`Unable to spawn or attach to process using '${appIdentifier}'. If attaching by name, launch the app first.`);
      }

      pid = target.pid;
      session = await device.attach(pid);
    }
  }

  const distDir = path.join(__dirname, "dist");
  const agentPath = path.join(distDir, `agent-test-${platform}.js`);

  const script = await session.createScript(fs.readFileSync(agentPath, "utf8"));

  let testComplete = false;
  let exitCode = 1;

  script.message.connect((message) => {
    if (message.type === "send") {
      const payload = message.payload;

      if (payload.type === "test-result") {
        const printResult = (result) => {
          const indent = "  ".repeat(result.depth ?? 0);
          if (result.passed) {
            console.log(`${indent}✅ PASS: ${result.name}`);
          } else {
            const error = result.error ? `: ${result.error}` : "";
            console.error(`${indent}❌ FAIL: ${result.name}${error}`);
          }
          for (const child of result.children ?? []) {
            printResult(child);
          }
        };
        printResult(payload.result);
      } else if (payload.type === "test-complete") {
        testComplete = true;

        if (payload.success) {
          console.log("\n✅ PASS: All tests passed.");
          exitCode = 0;
        } else {
          console.error("\n❌ FAIL: Some tests failed.");
          exitCode = 1;
        }
      }
    } else if (message.type === "error") {
      console.error("Script error:", message.stack);
      testComplete = true;
      exitCode = 1;
    }
  });

  await script.load();
  if (wasSpawned) {
    await device.resume(pid);
  }

  // Wait for test completion (with timeout)
  const timeout = 30000;
  const startTime = Date.now();

  while (!testComplete && Date.now() - startTime < timeout) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  if (!testComplete) {
    console.error("Tests timed out");
    exitCode = 1;
  }

  await session.detach();
  process.exit(exitCode);
}

runTests().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

function showHelp() {
  console.log(`
    Options:
    -p, --platform <name>         Platform (android, ios)
    --appIdentifier <value>       Required: pid, bundle/package id, or app name
    -u, --usb                     Use USB device mode
    -h, --help                    Show this help message

    Examples:
    npm run test:android -- --appIdentifier org.owasp.mastestapp
    npm run test:android -- --appIdentifier 4926
    npm run test:android -- --appIdentifier MASTestApp
    npm run test:ios:usb -- --appIdentifier org.owasp.mastestapp.MASTestApp-iOS
    npm run test:ios:local -- --appIdentifier 39417
    `);
  process.exit(0);
}

function validateInput(argv) {
  const validPlatforms = ["android", "ios"];
  if (!validPlatforms.includes(argv.platform)) {
    console.error(`Platform must be one of: ${validPlatforms.join(", ")}`);
    process.exit(1);
  }
  if (!argv.appIdentifier) {
    console.error("App Identifier (--appIdentifier) is required");
    process.exit(1);
  }
}
