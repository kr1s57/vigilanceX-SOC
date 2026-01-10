import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// v3.0: Production build mode with obfuscation
const isProduction = process.env.VITE_BUILD_MODE === 'production'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8080',
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    // v3.0: Disable sourcemaps in production for security
    sourcemap: !isProduction,
    // v3.0: Use Terser for obfuscation in production
    minify: isProduction ? 'terser' : 'esbuild',
    terserOptions: isProduction ? {
      compress: {
        drop_console: true,      // Remove console.log statements
        drop_debugger: true,     // Remove debugger statements
        pure_funcs: ['console.log', 'console.debug', 'console.info', 'console.warn'],
        passes: 2,               // Multiple compression passes
      },
      mangle: {
        toplevel: true,          // Mangle top-level variable names
        // Note: Removed properties mangling - it breaks React internals
        // (__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner)
      },
      format: {
        comments: false,         // Remove all comments
      },
    } : undefined,
    rollupOptions: {
      output: {
        // v3.0: Split chunks for better caching
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          ui: ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu', '@radix-ui/react-select'],
          charts: ['recharts'],
        },
        // v3.0: Obfuscate chunk names in production
        ...(isProduction && {
          chunkFileNames: 'assets/[hash].js',
          entryFileNames: 'assets/[hash].js',
          assetFileNames: 'assets/[hash].[ext]',
        }),
      },
    },
  },
})
