# Panduan BAB IV — Hasil dan Pembahasan (WebLog-IDS)

Dokumen ini merangkum **apa yang harus dimasukkan ke BAB IV** skripsi, diselaraskan dengan:

- `BAB I.md` (rumusan masalah, tujuan, ruang lingkup, metodologi)
- Implementasi sistem **WebLog-IDS** (`weblog-ids/`)
- Skema evaluasi **confusion matrix 4×4 + One-vs-Rest strict**

Gunakan file ini sebagai *outline* dan *checklist* saat menulis BAB IV di dokumen skripsi (Word/LaTeX). Angka, screenshot, dan tabel diisi dari hasil eksperimen aktual.

---

## 0. Prinsip Menulis BAB IV

BAB IV **menjawab janji BAB I dengan bukti**, bukan mengulang teori.

| Dari BAB I | Yang dibuktikan di BAB IV |
|---|---|
| RM1: optimasi rule-based di level log (transparan, adaptif, latensi rendah) | Pipeline + ruleset + bukti realtime |
| RM2: pengaruh decoding/normalisasi terhadap deteksi obfuscation/encoding | Contoh payload encoded + (opsional) uji dengan/tanpa preprocess |
| RM3: performa akurasi, precision, recall, F1 | Confusion matrix 4×4 + metrik OvR |
| Tujuan: pola serangan, ruleset, prototipe Python, evaluasi | Screenshot, tabel, pembahasan |
| Metodologi: praproses → rule → klasifikasi → evaluasi | Alur hasil uji yang konsisten |

**Yang tidak perlu di BAB IV:**

- Ulang panjang teori XSS/SQLi (BAB II)
- Listing kode penuh
- Tutorial instalasi detail (BAB III / lampiran)
- Metrik training ML (sistem rule-based, bukan ML)

---

## 1. Kerangka Subbab yang Disarankan

```text
BAB IV HASIL DAN PEMBAHASAN
  4.1 Lingkungan dan Skenario Pengujian
  4.2 Hasil Implementasi Sistem
  4.3 Hasil Preprocessing: Decoding dan Normalisasi
  4.4 Hasil Deteksi dan Klasifikasi
  4.5 Hasil Evaluasi Performa
      4.5.1 Skema evaluasi
      4.5.2 Confusion matrix 4×4
      4.5.3 Metrik per kelas (One-vs-Rest)
      4.5.4 Metrik overall
      4.5.5 Interpretasi hasil
  4.6 Pembahasan terhadap Rumusan Masalah
```

Mapping singkat:

```text
Latar + tujuan prototipe     →  4.2
RM2 decoding/normalisasi     →  4.3
Karakteristik pola serangan  →  4.2 ruleset + 4.4 contoh deteksi
RM3 + tujuan evaluasi        →  4.5
Semua RM + mitigasi          →  4.6
```

---

## 2. Detail Isi per Subbab

### 4.1 Lingkungan dan Skenario Pengujian

Agar metrik di §4.5 dapat dipertanggungjawabkan, jelaskan lingkungan uji terkendali (sesuai ruang lingkup BAB I).

**Isi minimal:**

1. **Spesifikasi lingkungan**
   - OS: Ubuntu Server
   - Web server: Nginx
   - Aplikasi target: DVWA
   - Backend: Python, FastAPI, MySQL
   - Frontend: React (Vite)
   - Path log: `/var/log/nginx/dvwa_access.log`

2. **Skenario pengujian**
   - Peneliti mengirim request **normal** dan payload **XSS / SQLi** ke DVWA
   - Nginx mencatat request ke access log
   - WebLog-IDS memproses log secara realtime (atau dari file log uji)
   - Sistem memberi **label prediksi**
   - Peneliti memberi **label aktual (ground truth)** lewat halaman Evaluasi

3. **Dataset evaluasi**
   - Jumlah total log yang diproses (opsional)
   - Jumlah record yang **sudah dilabeli** (`actual_label` tidak kosong) — **wajib disebut**
   - Distribusi kelas aktual (Normal, XSS, SQLi, Multiple)

**Template tabel lingkungan (isi sendiri):**

| Komponen | Spesifikasi |
|---|---|
| OS | Ubuntu Server … |
| Web server | Nginx … |
| Target uji | DVWA |
| Backend | FastAPI + Python … |
| Database | MySQL (`weblog_ids`) |
| Frontend | React + Vite |
| File log | `/var/log/nginx/dvwa_access.log` |

**Template tabel dataset labeled:**

| Label aktual | Jumlah |
|---|---|
| Normal | … |
| XSS | … |
| SQLi | … |
| Multiple | … |
| **Total labeled** | **N** |

---

### 4.2 Hasil Implementasi Sistem

Menjawab tujuan: *menghasilkan prototipe aplikasi berbasis Python yang membaca, mem-parsing, memproses, dan memberi penandaan/alert secara otomatis.*

**Jangan dump seluruh kode.** Cukup bukti sistem jadi + penjelasan singkat.

#### 4.2.1 Arsitektur yang diimplementasikan

```text
Nginx / DVWA
      ↓
/var/log/nginx/dvwa_access.log
      ↓
Realtime Log Watcher
      ↓
Nginx Log Parser
      ↓
Preprocessor (URL decode + normalisasi)
      ↓
Rule Matching Engine (regex XSS & SQLi)
      ↓
Classifier (Normal / XSS / SQLi / Multiple)
      ↓
MySQL (access_logs + detection_results)
      ↓
REST API + WebSocket
      ↓
Dashboard React (alert, grafik, evaluasi)
```

#### 4.2.2 Modul yang berhasil dibangun

| Modul | Fungsi | Bukti di sistem |
|---|---|---|
| Log watcher | Baca baris log baru (mirip `tail -f`) | Status watcher running di dashboard |
| Nginx parser | Parse combined log | Field IP, method, URI, status, dll. |
| Preprocessor | Recursive URL-decode + normalisasi | Payload decoded di hasil deteksi |
| Rule engine | Cocokkan regex dari JSON | `matched_rules` (XSS-xxx / SQLI-xxx) |
| Classifier | Label + severity + rekomendasi | Label Normal/XSS/SQLi/Multiple |
| Database | Simpan log & hasil deteksi | Tabel `access_logs`, `detection_results` |
| REST API | Dashboard, deteksi, export, evaluasi | Endpoint `/api/*` |
| WebSocket | Alert realtime | Halaman Alert Realtime |
| Frontend | Visualisasi | 4 halaman dashboard |
| Evaluasi | CM 4×4 + OvR | Halaman Evaluasi + `evaluation_runs` |

#### 4.2.3 Ruleset yang disusun

Menjawab tujuan *menyusun ruleset* dan mendukung RM1 (transparan & adaptif: rule di file JSON, bisa ditambah tanpa mengubah kode).

**Rule XSS** (`weblog-ids/backend/rules/xss_rules.json`):

| ID | Nama | Severity | Pola (ringkas) |
|---|---|---|---|
| XSS-001 | XSS Script Tag | high | tag `<script>...</script>` |
| XSS-002 | XSS Event Handler | medium | `onerror=`, `onload=`, dll. |
| XSS-003 | XSS JavaScript URI | high | `javascript:` |
| XSS-004 | XSS Alert Function | medium | `alert(`, `prompt(`, `confirm(` |

**Rule SQLi** (`weblog-ids/backend/rules/sqli_rules.json`):

| ID | Nama | Severity | Pola (ringkas) |
|---|---|---|---|
| SQLI-001 | … | … | tautologi / `OR 1=1` (sesuai file) |
| SQLI-002 | … | … | … |
| SQLI-003 | … | … | komentar SQL `--`, `#`, `/*` |
| SQLI-004 | … | … | time-based `sleep(`, `benchmark(` |
| SQLI-005 | … | … | `information_schema` |

> Isi ulang tabel SQLi dari file rule aktual sebelum dimasukkan ke skripsi. Tambahkan 1–2 kalimat **alasan pemilihan pola** (pola payload umum di log DVWA / referensi OWASP).

#### 4.2.4 Screenshot wajib

1. Dashboard (summary cards + grafik)
2. Hasil Deteksi (tabel + filter)
3. Alert Realtime (contoh alert serangan)
4. Halaman Evaluasi (labeling + matrix + metrik)
5. (Opsional) export CSV / status health API

Setiap gambar: nomor gambar, judul, dan 1–2 kalimat penjelasan.

---

### 4.3 Hasil Preprocessing: Decoding dan Normalisasi

**Menjawab RM2 secara langsung.** Bagian ini sering dilupakan; jangan dilewati.

#### 4.3.1 Tahapan praproses (sesuai implementasi)

1. **Recursive URL-decode** — hingga stabil atau maksimal 3 putaran (`MAX_DECODE_ROUND`), menangani double/triple encoding  
2. **Normalisasi** — lowercase, rapikan whitespace  
3. **Build payload** — gabungkan bagian request relevan untuk diinspeksi rule engine  

#### 4.3.2 Tabel contoh kasus (wajib)

| No | Payload di log (encoded) | Setelah decode + normalisasi | Rule terpicu | Tanpa decode |
|---|---|---|---|---|
| 1 | `%3Cscript%3Ealert(1)%3C%2Fscript%3E` | `<script>alert(1)</script>` | XSS-001, XSS-004 | Tidak cocok / lolos |
| 2 | `1%27%20or%201%3D1--` | `1' or 1=1--` | SQLI-… | Tidak cocok / lolos |
| 3 | double encode, mis. `%253Cscript...` | `<script>...` | XSS-… | Tidak cocok / lolos |
| 4 | request normal `/login.php` | `/login.php` | — | Normal |

Isi baris dengan **sampel log nyata** dari eksperimen Anda.

#### 4.3.3 Arah pembahasan

- Tanpa decoding, string `%3Cscript%3E` tidak cocok dengan pola `<script>`  
- Decoding membuka payload yang disamarkan lewat encoding  
- Normalisasi membuat matching lebih konsisten (case, spasi)  
- **Kesimpulan RM2:** decoding dan normalisasi meningkatkan kemampuan deteksi terhadap payload yang di-obfuscate lewat teknik encoding  

**Opsional (lebih kuat di sidang):** bandingkan metrik atau jumlah deteksi *dengan preprocess* vs *tanpa preprocess* pada dataset yang sama.

---

### 4.4 Hasil Deteksi dan Klasifikasi

#### 4.4.1 Label keluaran sistem

| Label | Arti |
|---|---|
| `Normal` | Tidak ada rule yang terpicu |
| `XSS` | Hanya rule XSS |
| `SQLi` | Hanya rule SQLi |
| `Multiple` | Rule XSS dan SQLi terpicu sekaligus |

Severity: `none` / `low` / `medium` / `high` (diambil dari severity tertinggi rule yang terpicu).

#### 4.4.2 Contoh hasil deteksi per kelas

Tampilkan beberapa baris representatif (bukan seluruh database):

| No | IP | Request / payload (ringkas) | Rule | Prediksi | Severity |
|---|---|---|---|---|---|
| 1 | … | … | — | Normal | none |
| 2 | … | `<script>…` | XSS-001 | XSS | high |
| 3 | … | `' OR 1=1--` | SQLI-… | SQLi | … |
| 4 | … | payload campuran | XSS-… + SQLI-… | Multiple | … |

#### 4.4.3 Statistik pendukung (dari dashboard)

- Distribusi jenis serangan (pie/bar)
- Top attacker IP
- Rule yang paling sering terpicu

Ini mendukung pembahasan “karakteristik dan pola request HTTP” (tujuan penelitian).

#### 4.4.4 Catatan label Multiple

`Multiple` adalah **kelas tersendiri**, bukan bonus deteksi XSS+SQLi. Pada evaluasi strict, prediksi `Multiple` saat aktual `XSS` dihitung sebagai kesalahan kelas (FN untuk XSS), bukan true positive XSS.

---

### 4.5 Hasil Evaluasi Performa

**Inti kuantitatif BAB IV** — menjawab RM3 dan tujuan evaluasi.

#### 4.5.1 Skema evaluasi

Jelaskan agar konsisten dengan implementasi (`evaluation/evaluator.py`):

| Komponen | Sumber |
|---|---|
| Label prediksi | `detection_results.label` (classifier) |
| Label aktual | `detection_results.actual_label` (manual peneliti) |
| Record yang dihitung | Hanya yang sudah punya `actual_label` |
| Bentuk matrix | **4×4** |
| Kelas (urutan) | XSS, SQLi, Normal, Multiple |
| Skema | **One-vs-Rest strict** |

**Strict multi-class:**

- Satu record hanya masuk **satu sel** confusion matrix  
- Diagonal = prediksi benar  
- Off-diagonal = kesalahan klasifikasi  
- `Multiple` bukan partial credit untuk XSS/SQLi  

**Definisi OvR per kelas C:**

- **TP** = aktual C dan prediksi C  
- **FP** = aktual bukan C dan prediksi C  
- **FN** = aktual C dan prediksi bukan C  
- **TN** = aktual bukan C dan prediksi bukan C  

**Rumus metrik:**

```text
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 × (Precision × Recall) / (Precision + Recall)
Accuracy  = (jumlah diagonal matrix) / (total labeled)
Macro-P/R/F1 = rata-rata precision/recall/F1 keempat kelas
```

Jika denominator 0, nilai metrik diset 0 (sesuai implementasi `_safe_div`).

**Alasan ground truth manual:** pengujian terkendali di DVWA; peneliti mengetahui request normal vs serangan yang dikirim.

#### 4.5.2 Confusion matrix 4×4

**Template (isi angka dari Run Evaluation):**

```text
                 Prediksi
               XSS   SQLi   Normal   Multiple
Aktual XSS      a      b       c         d
      SQLi      e      f       g         h
    Normal      i      j       k         l
  Multiple      m      n       o         p
```

| Aktual \ Prediksi | XSS | SQLi | Normal | Multiple |
|---|---:|---:|---:|---:|
| XSS | | | | |
| SQLi | | | | |
| Normal | | | | |
| Multiple | | | | |

**Interpretasi singkat yang perlu ditulis:**

- Diagonal tinggi → klasifikasi baik  
- XSS/SQLi → Normal → **false negative** (serangan lolos) — kritis untuk IDS  
- Normal → XSS/SQLi → **false positive** (false alarm)  
- XSS → Multiple (atau sebaliknya) → kesalahan pemilihan kelas pada skema strict  

#### 4.5.3 Metrik per kelas (OvR)

| Kelas | TP | FP | TN | FN | Precision | Recall | F1 | FPR* | FNR* |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| XSS | | | | | | | | | |
| SQLi | | | | | | | | | |
| Normal | | | | | | | | | |
| Multiple | | | | | | | | | |

\*FPR = FP/(FP+TN), FNR = FN/(FN+TP) — disarankan karena metodologi BAB I menyebut *false positive rate*.

#### 4.5.4 Metrik overall

| Metrik | Nilai |
|---|---:|
| Total data labeled | |
| Accuracy | |
| Macro-Precision | |
| Macro-Recall | |
| Macro-F1 | |

Sumber di sistem: halaman Evaluasi / tabel `evaluation_runs` / export evaluasi.

#### 4.5.5 Interpretasi hasil (wajib, bukan hanya angka)

Arah pembahasan (sesuaikan angka aktual):

1. **Recall XSS/SQLi** — seberapa banyak serangan tertangkap; FN tinggi = banyak serangan lolos  
2. **Precision** — seberapa “bersih” alert; precision rendah = banjir false alarm  
3. **F1** — keseimbangan precision dan recall per kelas  
4. **Accuracy overall** — proporsi prediksi benar; hati-hati jika data tidak seimbang  
5. **Macro-F1** — rata-rata performa keempat kelas (lebih adil jika distribusi tidak seimbang)  
6. **Kelas Multiple** — sering sedikit datanya; jelaskan dampaknya pada metrik  

**Prioritas untuk IDS** (siap jawab sidang):

- **Recall serangan penting** (sedikit FN)  
- **Precision juga penting** (sedikit FP / false alarm)  
- Idealnya keduanya seimbang (F1 tinggi)

---

### 4.6 Pembahasan terhadap Rumusan Masalah

Subbab penutup yang mengikat kembali ke BAB I. Penguji sering mengecek bagian ini.

#### Jawaban RM1 — Optimasi rule-based level log

- Ruleset disimpan di JSON → **transparan** dan **adaptif** (bisa ditambah/diubah tanpa mengubah kode inti)  
- Pipeline realtime: log watcher + pemrosesan baris + WebSocket alert → mendukung **latensi rendah**  
- Bukti: status watcher, alert muncul saat serangan, daftar rule terpicu di dashboard  

#### Jawaban RM2 — Pengaruh decoding dan normalisasi

- Payload di access log sering URL-encoded  
- Recursive decode + normalisasi membuka pola XSS/SQLi sebelum rule matching  
- Bukti: tabel kasus §4.3  
- Tanpa preprocess, rule regex lemah terhadap obfuscation berbasis encoding  

#### Jawaban RM3 — Performa deteksi

- Ringkas accuracy, macro-F1, serta precision/recall per kelas dari §4.5  
- Bandingkan dengan ekspektasi prototipe rule-based di lingkungan DVWA  
- Sebut jenis kesalahan dominan (FN vs FP) dan implikasinya  

#### Keterbatasan hasil (jujur = nilai plus)

- Hanya mendeteksi pola yang ada di ruleset  
- Obfuscasi berat / encoding di luar recursive decode dapat lolos  
- Ground truth manual bergantung ketelitian labeling peneliti  
- Lingkungan DVWA, bukan traffic produksi penuh  
- Skema strict 4-kelas membuat `Multiple` ketat (bukan bonus TP XSS/SQLi)  
- Rule-based tidak “belajar” serangan zero-day baru tanpa penambahan rule  

#### Implikasi mitigasi (sesuai judul penelitian)

- Sistem memberi **peringatan dini** (alert realtime) dan **rekomendasi mitigasi** (validasi input, output encoding, prepared statement, pemeriksaan IP/endpoint)  
- Hasil deteksi dapat mendukung integrasi lanjutan dengan WAF/IPS atau kebijakan keamanan organisasi  
- Evaluasi kuantitatif memberi dasar perbaikan ruleset secara terukur  

---

## 3. Checklist Konten BAB IV

| # | Konten | Wajib? | Sumber di project |
|---|---|---|---|
| 1 | Lingkungan uji (Ubuntu, Nginx, DVWA) | Ya | BAB I ruang lingkup + panduan deploy |
| 2 | Alur sistem yang diimplementasi | Ya | `detection_pipeline.py`, PRD |
| 3 | Daftar ruleset XSS/SQLi | Ya | `rules/xss_rules.json`, `sqli_rules.json` |
| 4 | Contoh decode payload encoded | Ya (RM2) | `preprocessor.py` + sample log |
| 5 | Screenshot dashboard / deteksi / alert / evaluasi | Ya | Frontend |
| 6 | Jumlah data labeled + distribusi kelas | Ya | Halaman Evaluasi / DB |
| 7 | Confusion matrix 4×4 | Ya | `evaluation/evaluator.py` / UI |
| 8 | TP/FP/TN/FN + Precision/Recall/F1 per kelas | Ya | Export evaluasi / UI |
| 9 | Accuracy + macro metrics | Ya | `evaluation_runs` |
| 10 | Pembahasan RM1–RM3 + keterbatasan | Ya | Narasi skripsi |
| 11 | Uji latensi realtime | Disarankan | Timestamp log vs munculnya alert |
| 12 | Uji dengan vs tanpa preprocessing | Disarankan | Eksperimen tambahan |

---

## 4. Urutan Kerja Praktis

1. **Siapkan eksperimen** — kirim traffic normal + XSS + SQLi ke DVWA; pastikan log terbaca sistem.  
2. **Labeling ground truth** — isi Label Aktual di halaman Evaluasi untuk sampel yang cukup dan seimbang.  
3. **Run Evaluation** — simpan screenshot matrix + metrik; export CSV bila ada.  
4. **Tulis §4.5 dulu** (angka + interpretasi).  
5. **Tulis §4.3** (contoh decoding dari log nyata).  
6. **Tulis §4.2** (implementasi + screenshot + ruleset).  
7. **Tulis §4.1** (lingkungan + N data).  
8. **Tutup §4.6** (jawab RM1–RM3 + keterbatasan + mitigasi).  

---

## 5. Siap Jawab Sidang (ringkas)

| Pertanyaan | Jawaban inti |
|---|---|
| Kenapa WebSocket? | Server perlu *push* alert segera; HTTP request-response tidak cocok untuk notifikasi realtime. |
| Kenapa `actual_label`? | Label sistem = prediksi; performa butuh ground truth; di DVWA peneliti yang tahu request yang dikirim. |
| Kenapa matrix 4×4? | Empat kelas keluaran: XSS, SQLi, Normal, Multiple. |
| Kenapa Multiple tidak dihitung benar untuk XSS? | Strict multi-class: aktual XSS hanya benar jika prediksi XSS; Multiple = kelas salah. |
| Metrik paling penting untuk IDS? | Recall (sedikit FN) penting; precision juga penting agar tidak banyak false alarm. |

Referensi teknis lebih lengkap: `panduan-presentasi-evaluasi-ovr-weblog-ids.md`, `eval.txt`, `pertanyaan-teknis.txt`.

---

## 6. Template Narasi Singkat (bisa dikembangkan)

### Untuk §4.3 (RM2)

> Payload serangan pada access log Nginx sering tersimpan dalam bentuk URL-encoded. Sistem melakukan recursive URL decoding hingga maksimal tiga putaran, diikuti normalisasi huruf kecil dan whitespace. Sebagai contoh, payload `%3Cscript%3Ealert(1)%3C%2Fscript%3E` dinormalisasi menjadi `<script>alert(1)</script>` sehingga rule XSS-001 dan XSS-004 dapat terpicu. Tanpa tahap decoding, pola regex berbasis karakter khusus HTML/SQL tidak cocok dengan string ter-encode, sehingga indikasi serangan berpotensi lolos. Dengan demikian, decoding dan normalisasi berperan meningkatkan kemampuan deteksi terhadap serangan yang disamarkan melalui teknik encoding.

### Untuk §4.5.5 (RM3 — sesuaikan angka)

> Evaluasi dilakukan pada *N* record berlabel aktual menggunakan confusion matrix 4×4 dan skema One-vs-Rest strict. Sistem memperoleh accuracy sebesar *A* dan macro-F1 sebesar *F*. Kelas XSS memperoleh precision *P_x* dan recall *R_x*, sedangkan kelas SQLi memperoleh precision *P_s* dan recall *R_s*. Temuan ini menunjukkan bahwa [sebutkan: mayoritas serangan tertangkap / masih ada FN / FP pada request normal]. Kesalahan dominan terjadi pada [sebutkan sel off-diagonal utama], yang selanjutnya menjadi dasar penyempurnaan ruleset.

### Untuk §4.6 penutup

> Berdasarkan hasil implementasi dan evaluasi, pendekatan rule-based pada level log akses Nginx yang dilengkapi preprocessing decoding/normalisasi, pipeline realtime, serta dashboard evaluasi mampu mendeteksi indikasi XSS dan SQL Injection secara terukur. Sistem tidak hanya menghasilkan penandaan dan alert, tetapi juga merekomendasikan langkah mitigasi serta menyediakan metrik performa sebagai dasar perbaikan aturan deteksi.

---

## 7. File Terkait di Repository

| File | Kegunaan |
|---|---|
| `BAB I.md` | Acuan rumusan masalah & tujuan |
| `prd-weblog-ids.md` | Spesifikasi sistem lengkap |
| `eval.txt` | Ringkasan skema evaluasi strict |
| `panduan-presentasi-evaluasi-ovr-weblog-ids.md` | Detail CM 4×4 & OvR untuk sidang |
| `pertanyaan-teknis.txt` | Jawaban cepat sidang |
| `weblog-ids/backend/evaluation/evaluator.py` | Implementasi rumus evaluasi |
| `weblog-ids/backend/rules/*.json` | Ruleset final untuk tabel BAB IV |
| `weblog-ids/backend/services/preprocessor.py` | Bukti alur decoding |

---

*Dokumen panduan ini dibuat untuk mendukung penulisan BAB IV skripsi WebLog-IDS. Angka dan screenshot harus diisi dari hasil eksperimen aktual sebelum dimasukkan ke naskah final.*
