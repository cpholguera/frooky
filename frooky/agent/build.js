import fs from 'fs';
import { execSync, spawn } from 'child_process';
import path from 'path';
import chokidar from 'chokidar';
import minimist from 'minimist';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const argv = minimist(process.argv.slice(2), {
    boolean: ['watch', 'compress', 'verbose', 'keep-build-dir'],
    string: ['target', 'platform', 'type-check'],
    alias: {
        t: 'target',
        p: 'platform',
        w: 'watch',
        c: 'compress',
        v: 'verbose',
        h: 'help',
    },
    default: {
        t: 'frooky',
        w: false,
        c: true,
        'keep-build-dir': false,
        'type-check': 'full'
    }
});

// args
const targetOption = argv.target;
const platfromOption = argv.platform;
const typeCheckOption = argv['type-check'];
const keepBuildDirOption = argv['keep-build-dir'];
const watchOption = argv.watch;
const compressOption = argv.compress;
const helpOption = argv.help;
const verbose = argv.verbose;
const hooksFilePaths = argv._;

// config paths
const sourceDir = path.join(__dirname, platfromOption);
const distDir = path.join(__dirname, 'dist');
const buildDir = path.join(distDir, 'build');
const combinedHookPath = path.join(buildDir, '_hooks.ts');
const agentPath = path.join(distDir, `agent-${platfromOption}-${targetOption}.js`)


if (helpOption) {
    showHelp();
}
validateInput();

try {
    setupBuildDir();

    if (watchOption) {
        await runWatch()
    } else {
        runCompileAgent();
    }
} catch (e){ 
    console.error(`Error: ${e}`)
} finally {
    if (!keepBuildDirOption) {
        cleanupBuildDir();
    } 
}


function cleanupBuildDir() {
    fs.rmSync(buildDir, { recursive: true, force: true });
}

// TODO: Patch when fixing https://github.com/cpholguera/frooky/issues/29
// Function to merge and generate _hooks.ts
function generateHooksFile() {
    const mergedHooks = {
        category: null,
        hooks: []
    };
    hooksFilePaths.forEach(file => {
        try {
            const content = fs.readFileSync(file, 'utf8');
            const json = JSON.parse(content);

            // Use the first category found
            if (!mergedHooks.category && json.category) {
                mergedHooks.category = json.category;
            }

            // Merge hooks arrays
            if (json.hooks && Array.isArray(json.hooks)) {
                mergedHooks.hooks = mergedHooks.hooks.concat(json.hooks);
            }
        } catch (error) {
            console.error(`Error reading ${file}:`, error.message);
            process.exit(1);
        }
    });

    const tsContent = `export const target = ${JSON.stringify(mergedHooks, null, 2)};\n`;

    try {
        fs.writeFileSync(combinedHookPath, tsContent);
        if (verbose) { console.log(`Hook compiling sucessful. Location: ${combinedHookPath}`) }
    } catch (error) {
        console.error('Error writing hooks.ts:', error.message);
        process.exit(1);
    }
}


function showHelp() {
    console.log(`
    Options:
    -t, --target <name>       Target environment (frooky, frida) [default: frooky]
    -p, --platform <name>     Platform (android, ios)
    --type-check <name>       Sets TypeScript type checking (full, none) [default: full]
    -w, --watch               Re-Compiles agent.js every time code or hooks chagne [default: false]
    -c, --compress            Compress agent.js [default: false]
    -v, --verbose             Verbose output [default: false]
    --keep-build-dir          Keeps the build directory after compiling the agent [default: false]
    -h, --help                Show this help message

    Arguments:
    [hook-files...]           Paths to hook files to process.
    `);
    process.exit(0);
}

function validateInput() {
    // validate target
    const validPlatforms = ['android', 'ios'];
    if (!validPlatforms.includes(platfromOption)) {
        console.error(`Platform must be one of: ${validPlatforms.join(', ')}`);
        process.exit(1);
    }

    // validate target
    const validTargets = ['frooky', 'frida'];
    if (!validTargets.includes(targetOption)) {
        console.error(`Target must be one of: ${validTargets.join(', ')}`);
        process.exit(1);
    }

    // validate hooks files
    if (targetOption === 'frida') {
        if (hooksFilePaths.length == 0) {
            console.error(`No hook files provide. Provide one or more hook.json files.`);
            process.exit(1);
        }
        hooksFilePaths.forEach(file => {
            if (!fs.existsSync(file)) {
                console.error(`Hook file not found: ${file}`);
                process.exit(1);
            }
            if (path.extname(file).toLowerCase() !== '.json') {
                console.error(`Invalid file type: ${file}. Only .json files are allowed.`);
                process.exit(1);
            }
        });
    }
}

function setupBuildDir() {
    // create target dir /
    if (!fs.existsSync(distDir)) {
        fs.mkdirSync(distDir);
    }

    // create build dir /
    if (!fs.existsSync(buildDir)) {
        fs.mkdirSync(buildDir);
    }

    // copy code to build dir
    fs.cpSync(path.join(__dirname, platfromOption), `${buildDir}`, { recursive: true });

    // Remove the index file we're NOT using
    const unusedTarget = targetOption === 'frida' ? 'frooky' : 'frida';
    const unusedIndexPath = path.join(buildDir, `index.${unusedTarget}.ts`);
    if (fs.existsSync(unusedIndexPath)) {
        fs.unlinkSync(unusedIndexPath);
    }

    if (targetOption == 'frida') {
        generateHooksFile();
    }

}

function runCompileAgent() {
    const command = `frida-compile ${path.join(buildDir, `index.${targetOption}.ts`)} \
        -o ${agentPath} \
        -T ${typeCheckOption}\
        ${compressOption ? ' -c' : ''}`;

    execSync(command, { stdio: 'inherit' });
    if (verbose) { console.log(`Agent compiling sucessful. Location: ${agentPath}`) }
}

function runWatch() {
    return new Promise((resolve, reject) => {
        // Start frida-compile in watch mode
        const fridaProcess = spawn('frida-compile', [
            `${path.join(buildDir, `index.${targetOption}.ts`)}`,
            '-o', agentPath,
            '-w',
            '-T', typeCheckOption,
            ...(compressOption ? ['-c'] : [])
        ].filter(Boolean), { stdio: 'inherit'});

        // Watch hook files for changes
        const watcherHooks = chokidar.watch(hooksFilePaths, {
            persistent: true,
            ignoreInitial: true
        });
        watcherHooks.on('change', () => {
            if(verbose){console.log('Hook files changed, regenerating hooks.')}
            generateHooksFile();
        });

        // Watch for changes in the source files
        const watcherSource = chokidar.watch(sourceDir, {
            persistent: true,
            ignoreInitial: true
        });
        watcherSource.on('change', () => {
            if(verbose){console.log('Hook files changed, regenerating hooks.')}
            cleanupBuildDir();
            setupBuildDir();
        });

        process.on('SIGINT', () => {
            if(verbose){console.log('Stop watching for file changes.')}
            fridaProcess.kill();
            watcherHooks.close();
            watcherSource.close();
            resolve();
        });

        fridaProcess.on('error', (err) => {
            watcher.close();
            reject(err);
        });
    });
}
