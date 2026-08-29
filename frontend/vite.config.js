import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export var MAX_JAVASCRIPT_CHUNK_BYTES = 500 * 1024;
export function vendorChunk(id) {
    var normalized = id.split('\\').join('/');
    var has = function (fragment) { return normalized.indexOf(fragment) !== -1; };
    if (normalized.slice(-12) === '/src/App.tsx'
        || normalized.slice(-11) === '/src/api.ts')
        return 'app-shell';
    if (normalized.slice(-17) === '/src/admin-api.ts')
        return 'admin-api';
    if (normalized.slice(-12) === '/src/oidc.ts')
        return 'oidc';
    if (normalized.slice(-27) === '/src/AuthenticatedShell.tsx')
        return 'authenticated-shell';
    if (!has('/node_modules/'))
        return undefined;
    if (has('/node_modules/react/')
        || has('/node_modules/react-dom/')
        || has('/node_modules/react-router')
        || has('/node_modules/scheduler/'))
        return 'react-runtime';
    if (has('/node_modules/oidc-client-ts/'))
        return 'oidc';
    var isAntDesignRuntime = (has('/node_modules/@rc-component/')
        || has('/node_modules/rc-')
        || has('/node_modules/@ant-design/')
        || has('/node_modules/antd/'));
    if (isAntDesignRuntime) {
        if (has('/node_modules/@rc-component/') || has('/node_modules/rc-'))
            return 'antd-components';
        return undefined;
    }
    return undefined;
}
function enforceChunkBudget() {
    return {
        name: 'enforce-javascript-chunk-budget',
        generateBundle: function (_options, bundle) {
            var oversized = [];
            for (var fileName in bundle) {
                var output = bundle[fileName];
                if (output.type !== 'chunk')
                    continue;
                var bytes = new TextEncoder().encode(output.code).byteLength;
                if (bytes > MAX_JAVASCRIPT_CHUNK_BYTES) {
                    oversized.push({ name: output.fileName, bytes: bytes });
                }
            }
            oversized.sort(function (left, right) { return right.bytes - left.bytes; });
            if (oversized.length > 0) {
                var summary = oversized
                    .map(function (output) { return "".concat(output.name, "=").concat(output.bytes); })
                    .join(', ');
                this.error("JavaScript chunk budget exceeded (".concat(MAX_JAVASCRIPT_CHUNK_BYTES, " bytes): ").concat(summary));
            }
            var chunks = {};
            var pending = [];
            for (var fileName in bundle) {
                var output = bundle[fileName];
                if (output.type !== 'chunk')
                    continue;
                chunks[output.fileName] = output;
                if (output.isEntry)
                    pending.push(output.fileName);
            }
            var eagerFiles = {};
            var eagerOrder = [];
            while (pending.length > 0) {
                var fileName = pending.pop();
                if (!fileName || eagerFiles[fileName])
                    continue;
                var chunk = chunks[fileName];
                if (!chunk)
                    continue;
                eagerFiles[fileName] = true;
                eagerOrder.push(fileName);
                pending.push.apply(pending, chunk.imports);
            }
            var leakedFiles = eagerOrder.filter(function (fileName) {
                var chunk = chunks[fileName];
                return chunk && Object.keys(chunk.modules).some(function (id) {
                    var normalized = id.split('\\').join('/');
                    return normalized.indexOf('/node_modules/antd/') !== -1
                        || normalized.indexOf('/node_modules/@ant-design/') !== -1
                        || normalized.indexOf('/node_modules/@rc-component/') !== -1
                        || normalized.indexOf('/node_modules/rc-') !== -1;
                });
            }).sort();
            if (leakedFiles.length > 0) {
                this.error("Administrator UI runtime leaked into eager JavaScript: ".concat(leakedFiles.join(', ')));
            }
        },
    };
}
export default defineConfig({
    plugins: [react(), enforceChunkBudget()],
    build: {
        manifest: true,
        rollupOptions: {
            output: {
                manualChunks: vendorChunk,
                onlyExplicitManualChunks: true,
            },
        },
    },
    server: {
        port: 5173,
        proxy: {
            '/api': 'http://127.0.0.1:8000',
        },
    },
});
