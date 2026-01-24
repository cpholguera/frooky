const fs = require('fs');
const { execSync, spawn } = require('child_process');
const path = require('path');
const chokidar = require('chokidar');

// TODO: add verbose flags (see https://github.com/cpholguera/frooky/issues/27)
const platform = process.argv[2]; // 'android' or 'ios'
const hookFiles = process.argv.slice(3).filter(arg => !arg.startsWith('-'));
const isWatchMode = process.env.npm_lifecycle_event?.startsWith('watch-');

if (!platform || hookFiles.length === 0) {
    console.error('Usage: node build.js <platform> <hook-file-1> [hook-file-2] ...');
    process.exit(1);
}

// Verify all hook files exist
hookFiles.forEach(file => {
    if (!fs.existsSync(file)) {
        console.error(`Hook file not found: ${file}`);
        process.exit(1);
    }
});

const tmpDir = path.join(__dirname, 'tmp');
if (!fs.existsSync(tmpDir)) {
    fs.mkdirSync(tmpDir);
}

const hooksFilePath = path.join(tmpDir, '_hooks.ts');

// TODO: Patch wen fixing https://github.com/cpholguera/frooky/issues/29
// Function to merge and generate _hooks.ts
function generateHooksFile() {
    const mergedHooks = {
        category: null,
        hooks: []
    };

    console.log(`Comining hooks...`);

    hookFiles.forEach(file => {
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

    console.log(`Combined ${mergedHooks.hooks.length} hook(s)`);

    // Generate TypeScript file
    const tsContent = `export const target = ${JSON.stringify(mergedHooks, null, 2)};\n`;

    try {
        fs.writeFileSync(hooksFilePath, tsContent);
        console.log(`Generated ${hooksFilePath}`);
    } catch (error) {
        console.error('Error writing _hooks.ts:', error.message);
        process.exit(1);
    }
}

// Generate initial hooks file
generateHooksFile();

if (isWatchMode) {
    // Watch mode: use spawn for frida-compile and chokidar for hook files
    console.log(`Starting watch mode for ${platform} agent...`);
    console.log(`Watching hook files: ${hookFiles.join(', ')}`);

    // Start frida-compile in watch mode
    const fridaProcess = spawn('frida-compile', [
        `${platform}/index.ts`,
        '-o', 'tmp/_agent.js',
        '-w',
        '-T', 'none'                // TODO remove -T none after migration
    ], { stdio: 'inherit' });

    // Watch hook files for changes
    const watcher = chokidar.watch(hookFiles, {
        persistent: true,
        ignoreInitial: true
    });

    watcher.on('change', (filePath) => {
        console.log(`\nHook file changed: ${filePath}`);
        generateHooksFile();
        // frida-compile will automatically detect _hooks.ts change and rebuild
    });

    // Handle process termination
    process.on('SIGINT', () => {
        console.log('\nStopping watch mode...');
        watcher.close();
        fridaProcess.kill();
        process.exit(0);
    });

} else {
    // Single build mode
    const command = `frida-compile ${platform}/index.ts -o tmp/_agent.js -T none`;      // TODO remove -T none after migration

    try {
        console.log(`Building ${platform} agent...`);
        execSync(command, { stdio: 'inherit' });
        console.log('Build complete');
    } catch (error) {
        console.error('Build failed:', error.message);
        process.exit(1);
    }
}
