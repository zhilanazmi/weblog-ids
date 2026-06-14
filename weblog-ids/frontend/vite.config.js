import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Konfigurasi Vite. Port 5173 (default) sengaja dipertahankan karena backend
// sudah mengizinkan origin http://localhost:5173 di CORS.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
});
