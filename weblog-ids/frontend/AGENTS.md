# AGENTS.md — Frontend WebLog-IDS

Panduan untuk agent (AI) yang bekerja di folder `frontend/`. Baca dulu file ini
sebelum mengubah kode. Sesuaikan semua perubahan dengan konvensi yang sudah
berjalan.

## 1. Gambaran Umum

Frontend **WebLog-IDS**: dashboard React yang menampilkan hasil deteksi intrusi
dari backend. Tiga halaman: **Dashboard** (ringkasan + grafik + alert terbaru,
refresh otomatis), **Hasil Deteksi** (tabel + filter + paginasi + export CSV),
dan **Alert Realtime** (menerima push alert serangan via WebSocket). Backend
wajib berjalan di `http://localhost:8000` (CORS backend sudah mengizinkan
origin `http://localhost:5173`).

Spesifikasi sistem lihat `../../prd-weblog-ids.md` (repositori root). Konvensi
backend lihat `../backend/AGENTS.md`.

## 2. Tech Stack

- **React 18.3.1** + **react-dom** (JSX, **tanpa TypeScript** — semua file `.jsx`)
- **Vite 5.4.8** + **@vitejs/plugin-react** (ESM, `"type": "module"`)
- **react-router-dom 6.26.2** (`BrowserRouter`, `Routes`, `NavLink`, `Navigate`)
- **recharts 2.12.7** (Pie/Bar chart, `ResponsiveContainer`)
- **Tanpa** framework CSS — CSS polos di `src/index.css` (tema gelap, CSS
  variables). **Tanpa** ESLint/Prettier/TypeScript. **Tanpa** framework test.

Versi terkunci di `package.json`. **Jangan tambah dependency** tanpa alasan
kuat (preferensi: dependensi yang sudah ada + stdlib browser).

## 3. Struktur Direktori

```
frontend/
├── index.html              # Shell HTML (<div id="root">), load /src/main.jsx
├── vite.config.js          # Port 5173 (dipertahankan untuk CORS backend)
├── package.json            # scripts: dev / build / preview
└── src/
    ├── main.jsx            # Entry: BrowserRouter + StrictMode + render App
    ├── App.jsx             # Navbar + Routes (3 halaman + fallback Navigate)
    ├── index.css           # Gaya global (CSS variables, kelas reusable)
    ├── api/
    │   └── api.js          # Konfigurasi BASE_URL/WS_URL + helper fetch terpusat
    ├── pages/              # Satu file per halaman (route level)
    │   ├── Dashboard.jsx       # "/" — ringkasan + grafik + alert terbaru
    │   ├── DetectionResults.jsx# "/detections" — tabel + filter + paginasi
    │   └── RealtimeAlerts.jsx  # "/alerts" — WebSocket alert realtime
    └── components/         # Komponen presentasi reusable (stateless/bottom-up)
        ├── SummaryCards.jsx
        ├── AttackTypeChart.jsx     # Pie chart
        ├── TopIpChart.jsx          # Bar chart vertikal
        ├── RuleTriggeredChart.jsx  # Bar chart horizontal
        └── AlertTable.jsx          # Tabel ringkas alert
```

Pemisahan: `pages/` = halaman yang memuat data (pakai hooks fetch/state);
`components/` = presentasi murni, terima data lewat props, TIDAK boleh fetch
sendiri.

## 4. Cara Menjalankan

```bash
# Install dependency (sekali)
npm install

# Dev server (http://localhost:5173, hot reload)
npm run dev

# Build produksi -> dist/
npm run build

# Preview hasil build
npm run preview
```

**Prasyarat**: backend berjalan di `http://localhost:8000`. Tanpa backend,
halaman akan menampilkan pesan error (bukan layar kosong) — lihat penanganan
error di tiap page.

## 5. Konfigurasi & Kontrak Backend

Semua akses backend terpusat di `src/api/api.js` lewat `BASE_URL`/`WS_URL`.
**Jangan hardcode** URL backend di komponen — impor dari `api.js`.

| Env var Vite | Default | Keterangan |
|---|---|---|
| `VITE_API_BASE_URL` | `http://localhost:8000` | Base URL REST backend |
| `VITE_WS_URL` | turunan `BASE_URL` (http→ws) + `/ws/alerts` | URL WebSocket alert |

Override via `.env` (Vite hanya men-expose var ber-prefix `VITE_`):
```
VITE_API_BASE_URL=http://192.168.1.10:8000
```

### Helper fetch (`api.js`)
- `getJSON(path)` — fetch JSON terpusat, **melempar `Error`** bila `!res.ok`
  (pesan berisi HTTP status). Komponen menangkapnya di `try/catch` lalu
  menampilkan `.msg.error`.
- Semua endpoint diekspos sebagai fungsi bernama (`fetchSummary`, `fetchDetections`,
  `exportCsvUrl`, dst). Tambah endpoint baru = tambah fungsi di sini, JANGAN
  panggil `fetch` langsung di komponen.

### Kontrak respons backend
Backend mengembalikan `{ count, data, ... }`. Komponen selalu baca
`res.data || []` (bukan `res` langsung) agar aman bila kosong.

| Endpoint | Bentuk data |
|---|---|
| `GET /api/health` | `{ status: "ok" }` |
| `GET /api/dashboard/summary` | `{ total_logs, total_normal, total_xss, total_sqli, total_multiple, total_alert, watcher_running }` |
| `GET /api/dashboard/attack-types` | `data: [{ label, jumlah }]` |
| `GET /api/dashboard/top-attacker-ip?limit=` | `data: [{ ip, jumlah }]` |
| `GET /api/dashboard/rule-triggered?limit=` | `data: [{ rule_code, jumlah }]` |
| `GET /api/detections?limit&offset&label=` | `data: [{ id, timestamp, ip, method, request_uri, decoded_payload, label, severity, matched_rules, recommendation }]` |
| `GET /api/detections/latest?n=` | `data: [...]` (sama) |
| `GET /api/reports/export-csv?label=` | unduhan CSV (bukan JSON) |
| `WS /ws/alerts` | push JSON alert (field sama + `matched_rules` array) |

Domain nilai: label `Normal`/`XSS`/`SQLi`/`Multiple`; severity
`none`/`low`/`medium`/`high`. `matched_rules` dari DB bisa berupa string JSON
(`'["XSS-001"]'`) atau array (WebSocket) — selalu pakai helper `formatRules`
untuk menampilkannya.

## 6. Pola Kode (WAJIB diikuti)

- **Ekstensi `.jsx`** untuk semua file yang berisi JSX. `api.js` tetap `.js`
  (tidak ada JSX).
- **Komentar Bahasa Indonesia**, format `//` di atas file menjelaskan tujuan
  komponen + kontrak props/data (mis. `// data: [{ ip, jumlah }] dari GET ...`).
  Komentar menjelaskan "mengapa" (justifikasi), bukan "apa". JANGAN tulis
  komentar Inggris kecuali menyesuaikan kode lama yang sudah begitu.
- **Functional component + hooks** saja. Deklarasi pakai
  `export default function Nama({ props }) {}`. Tidak ada class component.
- **Props destructuring** langsung di parameter: `({ summary })`, `({ data })`.
- **State di page, props ke komponen**. Page pakai `useState`/`useEffect`/
  `useCallback`/`useRef`; komponen presentasi sebaiknya stateless.
- **`useCallback` untuk fungsi fetch** yang dipakai di `useEffect` agar
  referensi stabil (lihat `Dashboard.loadAll`, `DetectionResults.load`).
  `useEffect` wajib punya cleanup bila pakai interval/timer/WebSocket.
- **Penanganan state konsisten**: tiap page punya `loading`, `error`, dan
  tampilkan `.msg.loading` / `.msg.error` (lihat CSS). Jangan biarkan layar
  kosong saat error — tampilkan pesan.
- **Data kosong**: cek `!data || data.length === 0` lalu tampilkan fallback
  `<p className="label">Belum ada data.</p>` (lihat komponen chart).

### Pola polling (Dashboard)
```jsx
const loadAll = useCallback(async () => { /* Promise.all([...]) */ }, []);
useEffect(() => {
  loadAll();
  const id = setInterval(loadAll, 5000);  // refresh 5 detik
  return () => clearInterval(id);          // cleanup wajib
}, [loadAll]);
```

### Pola WebSocket (RealtimeAlerts)
- Buka koneksi saat mount, tutup saat unmount (cleanup `useEffect`).
- Simpan `WebSocket`, timer reconnect, dan flag `mounted` di `useRef` agar
  bertahan antar render tanpa picu re-render.
- `onmessage`: sisipkan alert di **atas** array, batasi ke 100
  (`.slice(0, 100)`), beri `_id` unik lokal untuk `key` React.
- Reconnect otomatis: `onclose` jadwalkan `setTimeout(connect, 3000)` hanya bila
  masih mounted; `onerror` panggil `ws.close()` agar `onclose` yang menangani.
- Saat menambah koneksi realtime, ikuti pola cleanup ini untuk hindari timer/
  socket bocor.

### Pola paginasi (DetectionResults)
Offset-based, `PAGE_SIZE = 20`. Ganti filter label -> `setOffset(0)`. Tombol
"Berikutnya" nonaktif saat `rows.length < PAGE_SIZE`.

## 7. Helper `formatRules`

`matched_rules` dari backend bisa berupa string JSON atau array. Helper
`formatRules(matched)` ada di **tiga** file (`AlertTable.jsx`,
`DetectionResults.jsx`, `RealtimeAlerts.jsx`) — sengaja diduplikasi ringan agar
komponen tetap mandiri. Bila logikanya berubah, perbarui ketiganya (atau bila
sudah makin kompleks, baru pertimbangkan ekstrak ke `src/utils/`).

## 8. Gaya & Styling

- Satu file CSS global: `src/index.css`. **Tanpa** CSS Modules / styled-components.
-Selektor berbasis `className`. Kelas reusable: `panel`, `card`, `badge`,
  `msg error`, `msg loading`, `dot on/off`, `wrap` (text wrap), `sev-*`,
  `label-*`.
- **Variabel CSS** di `:root` mendefinisikan palet tema gelap + warna severity
  (`--high`/`--medium`/`--low`/`--normal`). Warna severity konsisten lintas
  komponen — pakai variabel, jangan hardcoded hex baru.
- Warna per label seragam: `AttackTypeChart.COLORS` (`Normal` hijau, `XSS`
  ungu, `SQLi` jingga, `Multiple` merah). Bila tambah chart label, ikuti peta
  warna ini agar konsisten.
- Chart recharts selalu dibungkus `<ResponsiveContainer width="100%"
  height={260}>` + cek data kosong dulu. Sumbu/`stroke` pakai warna tema
  (`#94a3b8`, `#334155`).

## 9. Routing

Didefinisikan di `App.jsx` dengan `react-router-dom`. Tiga route + fallback:
- `/` → `Dashboard`
- `/detections` → `DetectionResults`
- `/alerts` → `RealtimeAlerts`
- `*` → `Navigate to="/"` (fallback rute tak dikenal)

`NavLink` otomatis menambah class `active` pada menu aktif. `BrowserRouter`
dipasang di `main.jsx`. Saat tambah halaman: buat file di `pages/`, daftarkan
`<Route>` + `<NavLink>` di `App.jsx`.

## 10. Verifikasi

Tidak ada linter/test resmi. Verifikasi:

1. **Build check** (menangkap error import/syntax JSX):
   ```bash
   npm run build
   ```
2. **Manual**: jalankan `npm run dev` + backend, buka `http://localhost:5173`,
   cek tiap halaman merender data, filter/paginasi/export berfungsi, dan
   alert realtime muncul saat ada serangan (picu log di backend / pakai
   `ws_client_test.py` di backend untuk simulasi).
3. **Cek koneksi backend**: `GET /api/health` lewat browser/`curl`.

Saat selesai mengubah kode, **wajib** jalankan `npm run build` untuk memastikan
tidak ada error compile sebelum dianggap selesai.
