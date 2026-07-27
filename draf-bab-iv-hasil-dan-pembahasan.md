# BAB IV  
# HASIL DAN PEMBAHASAN

Bab ini menyajikan hasil implementasi dan pengujian sistem deteksi intrusi berbasis analisis log akses web server Nginx dengan pendekatan *rule-based* untuk serangan *Cross-Site Scripting* (XSS) dan *SQL Injection* (SQLi). Paparan disusun secara berurutan mulai dari lingkungan pengujian, hasil implementasi prototipe, pengaruh *preprocessing* (decoding dan normalisasi), hasil deteksi dan klasifikasi, hingga evaluasi performa menggunakan metrik akurasi, *precision*, *recall*, dan *F1-score*. Pembahasan diarahkan untuk menjawab rumusan masalah serta tujuan penelitian yang telah ditetapkan pada Bab I.

---

## 4.1 Lingkungan dan Skenario Pengujian

### 4.1.1 Lingkungan Pengujian

Pengujian sistem dilaksanakan pada lingkungan uji terkontrol sesuai ruang lingkup penelitian. Konfigurasi perangkat lunak yang digunakan disajikan pada Tabel 4.1.

**Tabel 4.1** Spesifikasi lingkungan pengujian

| Komponen | Spesifikasi |
|---|---|
| Sistem operasi server | Ubuntu Server [PERLU BUKTI: versi, misalnya 22.04 LTS] |
| Web server | Nginx [PERLU BUKTI: versi] |
| Aplikasi target uji | Damn Vulnerable Web Application (DVWA) [PERLU BUKTI: versi / security level] |
| Runtime backend | Python [PERLU BUKTI: versi, mis. 3.10+] |
| Kerangka backend | FastAPI + Uvicorn |
| Basis data | MySQL [PERLU BUKTI: versi], skema `weblog_ids` |
| Antarmuka dashboard | React + Vite |
| Sumber data deteksi | Access log Nginx (format *combined log*) |
| Path file log | `/var/log/nginx/dvwa_access.log` |

[PERLU BUKTI: spesifikasi perangkat keras server (CPU, RAM, penyimpanan) bila diminta format laporan institusi.]

Pemilihan DVWA sebagai target uji didasarkan pada ketersediaan modul kerentanan XSS dan SQLi yang dapat dipicu secara terkendali, sehingga penentuan *ground truth* (label aktual) dapat dilakukan oleh peneliti. Lingkungan tersebut tidak dimaksudkan untuk merepresentasikan kompleksitas penuh aplikasi web berskala produksi, melainkan untuk memfasilitasi pengujian deteksi pada skenario yang dapat diulang dan diverifikasi.

### 4.1.2 Skenario Pengumpulan Data dan Labeling

Proses pengujian mengikuti alur sebagai berikut.

1. Peneliti mengirimkan permintaan HTTP normal dan permintaan berpayload XSS atau SQLi ke DVWA melalui antarmuka atau klien HTTP.
2. Nginx mencatat setiap permintaan pada file access log dalam format *combined log*.
3. Modul *log watcher* pada sistem membaca baris log baru, kemudian meneruskannya ke *pipeline* deteksi (parsing, *preprocessing*, pencocokan rule, klasifikasi, dan penyimpanan).
4. Sistem menyimpan label prediksi beserta metadata deteksi pada basis data.
5. Peneliti memberikan label aktual secara manual pada halaman Evaluasi untuk sampel yang dijadikan data evaluasi.
6. Modul evaluasi membandingkan label prediksi dengan label aktual, membentuk *confusion matrix* 4×4, serta menghitung metrik *One-vs-Rest* (OvR) secara *strict*.

Hanya rekaman yang telah memiliki label aktual yang diikutsertakan dalam perhitungan metrik. Rekaman tanpa label aktual tidak dimasukkan ke dalam evaluasi agar *ground truth* tidak ambigu.

**Tabel 4.2** Distribusi data evaluasi berdasarkan label aktual

| Label aktual | Jumlah rekaman | Persentase (%) |
|---|---:|---:|
| Normal | [PERLU BUKTI] | [PERLU BUKTI] |
| XSS | [PERLU BUKTI] | [PERLU BUKTI] |
| SQLi | [PERLU BUKTI] | [PERLU BUKTI] |
| Multiple | [PERLU BUKTI] | [PERLU BUKTI] |
| **Total labeled** | **[PERLU BUKTI: N]** | **100** |

[PERLU BUKTI: rentang waktu pengumpulan log; jumlah total baris log yang diproses sebelum labeling; kriteria pemilihan sampel yang dilabeli.]

---

## 4.2 Hasil Implementasi Sistem

### 4.2.1 Arsitektur Sistem yang Diimplementasikan

Prototipe yang dibangun, selanjutnya disebut WebLog-IDS, mengintegrasikan pemantauan log secara *realtime*, deteksi berbasis aturan, penyimpanan hasil, serta penyajian informasi melalui antarmuka web. Alur pemrosesan disajikan pada Gambar 4.1.

```text
Nginx / DVWA
      ↓
Access log (/var/log/nginx/dvwa_access.log)
      ↓
Realtime Log Watcher
      ↓
Parser Combined Log Nginx
      ↓
Preprocessor (URL decoding + normalisasi)
      ↓
Rule Matching Engine (regex XSS & SQLi)
      ↓
Classifier (Normal / XSS / SQLi / Multiple)
      ↓
Basis data MySQL
      ↓
REST API dan WebSocket
      ↓
Dashboard (ringkasan, hasil deteksi, alert, evaluasi)
```

**Gambar 4.1** Alur pemrosesan WebLog-IDS  
[PERLU BUKTI: ganti blok teks di atas dengan diagram formal (draw.io/Visio) pada naskah final.]

Berbeda dengan pendekatan unggah berkas log secara *batch*, komponen *log watcher* membaca penambahan baris pada file log secara berkelanjutan (perilaku serupa `tail -f`). Setiap baris baru diproses tanpa menghentikan layanan, sehingga penandaan dan *alert* dapat dihasilkan seiring munculnya aktivitas pada web server.

### 4.2.2 Modul Fungsional yang Dihasilkan

Implementasi menghasilkan modul-modul yang saling terhubung. Ringkasan fungsi dan keluaran tiap modul disajikan pada Tabel 4.3.

**Tabel 4.3** Modul fungsional WebLog-IDS

| Modul | Fungsi utama | Keluaran / bukti operasional |
|---|---|---|
| *Log watcher* | Memantau file access log dan membaca baris baru | Status *watcher* pada dashboard; [PERLU BUKTI: tangkapan layar status] |
| *Nginx parser* | Mengekstraksi field *combined log* (IP, waktu, method, URI, status, *user-agent*, dan sebagainya) | Rekaman pada tabel `access_logs` |
| *Preprocessor* | Melakukan *recursive* URL-decode dan normalisasi URI/payload | Field `decoded_payload` dan `normalized_payload` |
| *Rule engine* | Mencocokkan payload ternormalisasi dengan pola regex pada *ruleset* | Daftar `matched_rules` |
| *Classifier* | Menetapkan label, *severity*, dan rekomendasi mitigasi | Label `Normal` / `XSS` / `SQLi` / `Multiple` |
| Lapisan basis data | Menyimpan log dan hasil deteksi | Skema `access_logs`, `detection_results`, `evaluation_runs` |
| REST API | Menyediakan data dashboard, deteksi, ekspor, dan evaluasi | Endpoint `/api/*` |
| WebSocket | Mendorong notifikasi serangan ke antarmuka | Halaman Alert Realtime |
| Antarmuka web | Menampilkan ringkasan, tabel deteksi, *alert*, dan evaluasi | Empat halaman dashboard |

[PERLU BUKTI: tangkapan layar Dashboard, Hasil Deteksi, Alert Realtime, dan Evaluasi; nomor gambar pada naskah final.]

### 4.2.3 Ruleset Deteksi XSS dan SQL Injection

*Ruleset* disusun sebagai berkas JSON terpisah agar pola deteksi dapat ditinjau, ditambah, atau diubah tanpa memodifikasi kode inti mesin pencocokan. Pendekatan ini mendukung transparansi audit aturan dan adaptasi terhadap pola serangan baru pada tingkat konfigurasi.

**Tabel 4.4** *Ruleset* deteksi XSS

| ID | Nama aturan | *Severity* | Karakteristik pola yang dideteksi |
|---|---|---|---|
| XSS-001 | XSS Script Tag | high | Penggunaan pasangan *tag* `<script>…</script>` pada permintaan |
| XSS-002 | XSS Event Handler | medium | *Event handler* JavaScript (`onerror=`, `onload=`, `onclick=`, dan sejenisnya) |
| XSS-003 | XSS JavaScript URI | high | Skema URI `javascript:` |
| XSS-004 | XSS Alert Function | medium | Pemanggilan fungsi `alert(`, `prompt(`, atau `confirm(` |

**Tabel 4.5** *Ruleset* deteksi SQL Injection

| ID | Nama aturan | *Severity* | Karakteristik pola yang dideteksi |
|---|---|---|---|
| SQLI-001 | SQLi Union Select | high | Pola `UNION SELECT` |
| SQLI-002 | SQLi Boolean Based | high | Tautologi boolean, misalnya perbandingan angka dengan operator `OR`/`AND` |
| SQLI-003 | SQLi Comment Pattern | medium | Komentar SQL (`--`, `#`, `/*`, `*/`) |
| SQLI-004 | SQLi Time Based | high | Fungsi penundaan (`sleep`, `benchmark`, `pg_sleep`, `waitfor delay/time`) |
| SQLI-005 | SQLi Information Schema | high | Akses ke `information_schema` |
| SQLI-006 | SQLi DB Version Enumeration | high | Enumerasi versi/konfigurasi basis data (`@@version`, `version()`, dan sejenisnya) |
| SQLI-007 | SQLi Oracle Keyword | high | Kata kunci khas Oracle (`rownum`, `dba_users`, dan sejenisnya) |
| SQLI-008 | SQLi Boolean Parenthesized | high | Boolean SQLi dengan tanda kurung, misalnya `or ('1'='1)` |
| SQLI-009 | SQLi SQLMap Marker | medium | *Marker* templat SQLMap (`__TIME__`, dan sejenisnya) |
| SQLI-010 | SQLi Select From Statement | medium | Struktur `SELECT … FROM` pada payload |

Pola-pola di atas dipilih karena merepresentasikan karakteristik payload XSS dan SQLi yang sering muncul pada parameter permintaan HTTP dan terekam pada *query string* access log. Pencocokan dilakukan dengan ekspresi reguler bersifat *case-insensitive* terhadap *normalized payload*.

[PERLU BUKTI: bila terdapat iterasi penyempurnaan rule (penambahan/pengetatan pola untuk menekan *false positive*), uraikan versi *ruleset* awal vs akhir beserta alasan perubahan.]

[PERLU BUKTI: tujuan penelitian menyebut “aturan penguat/pengecualian untuk menekan *false positive*”. Jika belum diimplementasikan sebagai *exception rule* terpisah, nyatakan secara eksplisit bahwa penekanan FP dilakukan melalui penyesuaian pola regex dan peninjauan sampel, bukan melalui modul *whitelist* khusus—agar tidak *overclaim*.]

### 4.2.4 Mekanisme Klasifikasi, Severity, dan Rekomendasi

Berdasarkan himpunan rule yang terpicu, sistem menetapkan label sebagai berikut.

1. Tidak ada rule terpicu → **Normal**
2. Hanya rule bertipe XSS → **XSS**
3. Hanya rule bertipe SQLi → **SQLi**
4. Rule XSS dan SQLi terpicu bersamaan → **Multiple**

Tingkat *severity* diambil dari nilai tertinggi di antara rule yang terpicu (`none`, `low`, `medium`, `high`). Untuk label non-Normal, sistem menghasilkan teks rekomendasi mitigasi yang disesuaikan dengan jenis indikasi (misalnya validasi masukan dan *output encoding* untuk XSS; *prepared statement* dan validasi parameter untuk SQLi), serta menyertakan konteks alamat IP dan *request URI* terkait.

Label **Multiple** diperlakukan sebagai kelas tersendiri pada tahap evaluasi. Perlakuan tersebut mencegah perhitungan *true positive* ganda terhadap XSS dan SQLi untuk satu rekaman yang sama.

### 4.2.5 Antarmuka dan Notifikasi Realtime

Antarmuka pengguna menyediakan empat halaman utama: (1) Dashboard ringkasan dan grafik, (2) Hasil Deteksi dengan filter serta ekspor CSV, (3) Evaluasi dengan pelabelan aktual dan perhitungan metrik, serta (4) Alert Realtime berbasis WebSocket. Penggunaan WebSocket dipilih agar server dapat mendorong notifikasi serangan ke klien segera setelah *pipeline* menetapkan label serangan, tanpa menunggu *polling* periodik dari klien.

[PERLU BUKTI: contoh *payload* pesan WebSocket; tangkapan layar alert; bila memungkinkan, selisih waktu antara *timestamp* log dan kemunculan alert sebagai indikasi latensi operasional.]

---

## 4.3 Hasil Preprocessing: Decoding dan Normalisasi

### 4.3.1 Tahapan Preprocessing

Access log Nginx menyimpan *request URI* sebagaimana diterima web server, termasuk bentuk URL-encoded. Payload XSS dan SQLi yang dikirim penyerang sering kali tidak muncul dalam bentuk karakter mentah (misalnya `<` atau `'`), melainkan dalam bentuk `%3C`, `%27`, atau bahkan *double encoding*. Apabila pencocokan rule dilakukan langsung terhadap string ter-encode, pola regex yang dirancang untuk struktur serangan pada bentuk ter-decode berpotensi gagal terpicu.

Oleh karena itu, sebelum *rule matching*, sistem menerapkan dua tahap utama sebagai berikut.

1. **Recursive URL decoding**  
   String URI didekode berulang menggunakan skema URL-decode hingga tidak lagi berubah atau hingga batas maksimal tiga putaran. Batas tersebut ditujukan untuk menangani *double*/*triple encoding* tanpa *loop* tak terbatas.

2. **Normalisasi**  
   Hasil decode diubah ke huruf kecil, *whitespace* dirapikan menjadi spasi tunggal, dan spasi berlebih dihilangkan. Normalisasi bertujuan meningkatkan konsistensi pencocokan terhadap variasi kapitalisasi dan spasi.

Selanjutnya, *normalized payload* yang berasal dari `request_uri` (path dan *query string*) digunakan sebagai masukan *rule engine*. Fokus pada `request_uri` didasarkan pada kecenderungan payload XSS/SQLi muncul pada parameter permintaan yang terekam di access log.

### 4.3.2 Contoh Transformasi Payload

Tabel 4.6 menyajikan contoh transformasi payload dari bentuk terekam di log menuju bentuk yang diinspeksi rule. Contoh disusun berdasarkan pola encoding yang umum dan skenario uji pada modul kerentanan DVWA.

**Tabel 4.6** Contoh decoding dan normalisasi payload

| No | Bentuk pada access log (ringkas) | Setelah decode | Setelah normalisasi | Rule yang diharapkan terpicu |
|---|---|---|---|---|
| 1 | `…?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E` | `…?name=<script>alert(1)</script>` | `…?name=<script>alert(1)</script>` | XSS-001, XSS-004 |
| 2 | `…?name=%253Cscript%253E…` (*double encode*) | `…?name=<script>…` | `…?name=<script>…` | XSS-001 (dan/atau XSS-004) |
| 3 | `…?id=1%27%20or%201%3D1--` | `…?id=1' or 1=1--` | `…?id=1' or 1=1--` | SQLI-002, SQLI-003 |
| 4 | `…/login.php` | `…/login.php` | `…/login.php` | — (Normal) |

[PERLU BUKTI: ganti contoh di atas dengan cuplikan baris log nyata dari eksperimen (sertakan IP, *timestamp*, dan URI lengkap bila relevan); lampirkan tangkapan layar field `decoded_payload` pada halaman Hasil Deteksi.]

### 4.3.3 Pengaruh Preprocessing terhadap Deteksi

Secara konseptual, decoding mengubah representasi encoded menjadi bentuk yang selaras dengan pola serangan pada *ruleset*. Sebagai ilustrasi, pola XSS-001 mencari struktur *tag* `script`, sementara string `%3Cscript%3E` tidak memuat karakter `<` dan `>` secara literal. Tanpa decoding, rule tersebut tidak dapat mencocokkan payload yang disamarkan melalui URL encoding, meskipun niat serangan secara semantik sama.

Normalisasi selanjutnya mengurangi variasi penulisan yang tidak relevan bagi deteksi pola (kapitalisasi dan spasi), sehingga mengurangi ketergantungan rule pada bentuk penulisan yang sangat spesifik.

[PERLU BUKTI kuantitatif untuk menjawab RM2 secara tegas: bandingkan jumlah deteksi benar atau metrik evaluasi pada dataset yang sama dengan dua kondisi—(A) *pipeline* lengkap dengan decoding/normalisasi, dan (B) *pipeline* tanpa decoding/normalisasi. Cantumkan selisih *true positive* XSS/SQLi atau selisih *recall*. Tanpa eksperimen komparatif ini, klaim “peningkatan kemampuan deteksi” hanya bersifat kualitatif berdasarkan contoh kasus.]

---

## 4.4 Hasil Deteksi dan Klasifikasi

### 4.4.1 Distribusi Label Prediksi

Setelah *pipeline* dijalankan terhadap data log uji, sistem menghasilkan label prediksi untuk setiap baris yang berhasil di-*parse*. Ringkasan distribusi label prediksi disajikan pada Tabel 4.7.

**Tabel 4.7** Distribusi label prediksi sistem

| Label prediksi | Jumlah | Persentase (%) |
|---|---:|---:|
| Normal | [PERLU BUKTI] | [PERLU BUKTI] |
| XSS | [PERLU BUKTI] | [PERLU BUKTI] |
| SQLi | [PERLU BUKTI] | [PERLU BUKTI] |
| Multiple | [PERLU BUKTI] | [PERLU BUKTI] |
| **Total** | **[PERLU BUKTI]** | **100** |

[PERLU BUKTI: tangkapan layar ringkasan dashboard (total log, total XSS, total SQLi, total Multiple, total alert).]

### 4.4.2 Contoh Hasil Deteksi per Kelas

Tabel 4.8 menampilkan sampel hasil deteksi yang merepresentasikan masing-masing kelas. Sampel dipilih untuk keperluan ilustrasi mekanisme klasifikasi, bukan sebagai pengganti evaluasi agregat pada Subbab 4.5.

**Tabel 4.8** Contoh hasil deteksi per kelas

| No | IP | Cuplikan request / payload | Rule terpicu | Label prediksi | Severity |
|---|---|---|---|---|---|
| 1 | [PERLU BUKTI] | `/login.php` atau URI normal | — | Normal | none |
| 2 | [PERLU BUKTI] | payload XSS (setelah decode) | XSS-… | XSS | [PERLU BUKTI] |
| 3 | [PERLU BUKTI] | payload SQLi (setelah decode) | SQLI-… | SQLi | [PERLU BUKTI] |
| 4 | [PERLU BUKTI] | payload memicu XSS dan SQLi | XSS-… + SQLI-… | Multiple | [PERLU BUKTI] |

[PERLU BUKTI: salin baris aktual dari halaman Hasil Deteksi atau ekspor CSV; sertakan teks rekomendasi mitigasi untuk satu contoh serangan.]

### 4.4.3 Rule yang Paling Sering Terpicu

Analisis frekuensi pemicuan rule memberikan gambaran pola serangan yang dominan pada data uji.

**Tabel 4.9** Frekuensi rule terpicu (peringkat teratas)

| Peringkat | Kode rule | Jumlah pemicuan |
|---|---|---:|
| 1 | [PERLU BUKTI] | [PERLU BUKTI] |
| 2 | [PERLU BUKTI] | [PERLU BUKTI] |
| 3 | [PERLU BUKTI] | [PERLU BUKTI] |
| 4 | [PERLU BUKTI] | [PERLU BUKTI] |
| 5 | [PERLU BUKTI] | [PERLU BUKTI] |

[PERLU BUKTI: ambil dari endpoint/dashboard *rule triggered*; bahas mengapa rule tersebut dominan—misalnya karena skenario uji DVWA banyak memakai payload bertipe tertentu.]

### 4.4.4 Temuan Kualitatif terhadap Karakteristik Serangan pada Log

Berdasarkan peninjauan sampel log dan hasil deteksi, karakteristik berikut teramati pada data uji.

1. Payload XSS dan SQLi pada access log umumnya berada pada *query string* atau path parameter, selaras dengan fokus inspeksi pada `request_uri`.
2. Bentuk encoded merupakan representasi lazim pada log; deteksi efektif bergantung pada keberhasilan *preprocessing*.
3. Sebagian payload dapat memicu lebih dari satu rule dalam kelas yang sama (misalnya XSS-001 dan XSS-004), sehingga *severity* mengikuti level tertinggi.
4. Sebagian kecil kasus dapat memicu rule lintas kelas sekaligus dan diklasifikasikan sebagai Multiple.

[PERLU BUKTI: sebutkan jumlah atau proporsi kasus Multiple pada data labeled; hindari generalisasi di luar dataset DVWA.]

---

## 4.5 Hasil Evaluasi Performa

### 4.5.1 Skema Evaluasi

Evaluasi performa dilakukan dengan membandingkan label prediksi sistem terhadap label aktual yang diberikan peneliti. Skema evaluasi mengikuti klasifikasi multi-kelas dengan empat kelas keluaran sistem: **XSS**, **SQLi**, **Normal**, dan **Multiple**.

*Confusion matrix* dibentuk berukuran 4×4 dengan konvensi sebagai berikut.

- Baris menyatakan label **aktual**.
- Kolom menyatakan label **prediksi**.
- Setiap rekaman hanya mengisi **satu sel** matrix (*strict*, tanpa *double-counting*).
- Sel diagonal menyatakan klasifikasi benar.
- Sel di luar diagonal menyatakan kesalahan klasifikasi antar-kelas.

Untuk setiap kelas \(C\), metrik dihitung dengan pendekatan **One-vs-Rest (OvR)** sebagai berikut.

- \(TP_C\): aktual \(C\) dan prediksi \(C\)
- \(FP_C\): aktual bukan \(C\) dan prediksi \(C\)
- \(FN_C\): aktual \(C\) dan prediksi bukan \(C\)
- \(TN_C\): aktual bukan \(C\) dan prediksi bukan \(C\)

Rumus metrik yang digunakan:

\[
Precision_C = \frac{TP_C}{TP_C + FP_C},\quad
Recall_C = \frac{TP_C}{TP_C + FN_C},\quad
F1_C = \frac{2 \cdot Precision_C \cdot Recall_C}{Precision_C + Recall_C}
\]

\[
Accuracy = \frac{\sum_{C} TP_C}{N},\quad
Macro\text{-}F1 = \frac{1}{4}\sum_{C} F1_C
\]

dengan \(N\) adalah jumlah rekaman berlabel aktual yang valid. Pembagian dengan penyebut nol ditangani dengan nilai 0 agar perhitungan tetap terdefinisi.

Konsekuensi skema *strict* yang perlu dicatat: apabila label aktual adalah XSS tetapi sistem memprediksi Multiple, rekaman tersebut masuk sel (XSS, Multiple). Untuk kelas XSS, kasus tersebut dihitung sebagai *false negative*, bukan *true positive*. Multiple tidak memberikan kredit parsial bagi XSS maupun SQLi.

### 4.5.2 Confusion Matrix

Hasil perhitungan *confusion matrix* pada data labeled disajikan pada Tabel 4.10.

**Tabel 4.10** *Confusion matrix* 4×4 (baris = aktual, kolom = prediksi)

| Aktual \ Prediksi | XSS | SQLi | Normal | Multiple | Jumlah aktual |
|---|---:|---:|---:|---:|---:|
| XSS | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] |
| SQLi | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] |
| Normal | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] |
| Multiple | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] | [PERLU BUKTI] |
| **Jumlah prediksi** | **…** | **…** | **…** | **…** | **N = …** |

[PERLU BUKTI: isi dari fitur Run Evaluation / ekspor evaluasi; cantumkan tanggal *run* dan `evaluation_runs.id` bila relevan untuk reprodusibilitas.]

Interpretasi sel-sel krusial:

1. **XSS/SQLi → Normal**: indikasi serangan yang tidak terdeteksi (*false negative* dari perspektif deteksi serangan).
2. **Normal → XSS/SQLi/Multiple**: permintaan normal yang terklasifikasi sebagai serangan (*false positive* / *false alarm*).
3. **XSS ↔ Multiple** atau **SQLi ↔ Multiple**: kesalahan pemilihan kelas pada skema multi-kelas *strict*, meskipun secara heuristik payload mungkin “mengandung” indikasi serangan.

### 4.5.3 Metrik per Kelas (One-vs-Rest)

**Tabel 4.11** Metrik OvR per kelas

| Kelas | TP | FP | TN | FN | Precision | Recall | F1-score | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| XSS | | | | | | | | | |
| SQLi | | | | | | | | | |
| Normal | | | | | | | | | |
| Multiple | | | | | | | | | |

Keterangan: \(FPR = FP/(FP+TN)\); \(FNR = FN/(FN+TP)\). Kolom FPR dimasukkan untuk selaras dengan metodologi Bab I yang menyebut *false positive rate*.

[PERLU BUKTI: seluruh sel Tabel 4.11.]

### 4.5.4 Metrik Overall

**Tabel 4.12** Metrik keseluruhan

| Metrik | Nilai |
|---|---:|
| Jumlah data labeled (\(N\)) | [PERLU BUKTI] |
| Accuracy | [PERLU BUKTI] |
| Macro-Precision | [PERLU BUKTI] |
| Macro-Recall | [PERLU BUKTI] |
| Macro-F1 | [PERLU BUKTI] |

### 4.5.5 Pembahasan Hasil Evaluasi

Berdasarkan Tabel 4.10 hingga Tabel 4.12, performa sistem dapat dibahas dari dua sisi: (1) kemampuan menangkap serangan, dan (2) ketepatan klasifikasi agar tidak menghasilkan alarm berlebih.

1. **Recall kelas XSS dan SQLi** merefleksikan proporsi serangan berlabel aktual yang berhasil diprediksi pada kelas yang sama. Nilai *recall* yang rendah pada salah satu kelas mengindikasikan banyaknya kasus *false negative*, yang pada konteks IDS berarti indikasi serangan berpotensi lolos dari pemantauan berbasis rule yang diuji.
2. **Precision kelas XSS dan SQLi** merefleksikan proporsi prediksi serangan yang memang berlabel aktual serangan pada kelas tersebut. *Precision* rendah mengindikasikan tingginya *false positive*, yang dapat menurunkan kepercayaan operator terhadap *alert*.
3. **F1-score** merangkum keseimbangan *precision* dan *recall* per kelas. Pada data tidak seimbang, **macro-F1** lebih informatif daripada accuracy semata karena memberikan bobot setara kepada setiap kelas, termasuk kelas Multiple yang jumlahnya berpotensi kecil.
4. **Kelas Normal** perlu ditafsirkan hati-hati: *true positive* Normal yang tinggi belum tentu memadai bila *false negative* serangan (serangan → Normal) masih signifikan.
5. **Kelas Multiple** pada skema *strict* cenderung “keras”. Kesalahan prediksi Multiple terhadap aktual XSS/SQLi menurunkan metrik kelas terkait meskipun sistem telah mendeteksi adanya pola serangan. Temuan semacam ini perlu dibedakan dari kegagalan deteksi total (prediksi Normal).

[PERLU BUKTI: setelah angka terisi, tulis 1–2 paragraf yang merujuk angka konkret, misalnya “recall XSS sebesar 0,xx dengan FN sebanyak yy, terutama pada sel XSS→Normal sebanyak zz”. Identifikasi jenis kesalahan dominan dari matrix.]

Dalam konteks sistem deteksi intrusi, pengurangan *false negative* pada kelas serangan bersifat prioritas karena berkaitan langsung dengan tujuan peringatan dini. Namun demikian, *false positive* yang berlebihan juga menurunkan utilitas operasional. Oleh karena itu, interpretasi hasil tidak cukup berhenti pada accuracy keseluruhan, melainkan perlu meninjau *precision*–*recall* per kelas serangan.

---

## 4.6 Pembahasan terhadap Rumusan Masalah

### 4.6.1 Rumusan Masalah Pertama: Optimasi Pendekatan Rule-Based pada Level Log

Rumusan masalah pertama menanyakan bagaimana mengoptimalkan pendekatan *rule-based* pada level log akses agar menghasilkan *ruleset* yang transparan, adaptif, dan berlatensi rendah.

Berdasarkan hasil implementasi, optimasi diwujudkan melalui tiga keputusan rancangan. Pertama, *ruleset* dipisahkan dari kode dalam bentuk berkas JSON (Tabel 4.4 dan Tabel 4.5) sehingga isi aturan dapat diaudit dan diubah tanpa kompilasi ulang logika inti. Kedua, deteksi dijalankan pada *pipeline* terstruktur (parsing → *preprocessing* → matching → klasifikasi → persistensi), sehingga setiap tahap dapat diverifikasi. Ketiga, pemantauan file log secara *realtime* dan notifikasi WebSocket memungkinkan penyampaian indikasi serangan kepada operator tanpa menunggu unggahan log manual.

[PERLU BUKTI latensi: ukur atau laporkan indikasi latensi operasional, misalnya interval *polling* watcher 0,5 detik pada konfigurasi dan/atau selisih waktu *timestamp* log terhadap waktu `created_at` deteksi / kemunculan alert. Tanpa data ini, klaim “latensi rendah” bersifat rancangan, bukan temuan terukur.]

### 4.6.2 Rumusan Masalah Kedua: Pengaruh Decoding dan Normalisasi

Rumusan masalah kedua menanyakan seberapa besar pengaruh *decoding* dan normalisasi terhadap deteksi pola SQLi dan XSS yang disamarkan melalui *obfuscation* dan teknik encoding.

Hasil Subbab 4.3 menunjukkan bahwa bentuk encoded pada access log tidak selaras secara literal dengan pola regex berbasis struktur serangan ter-decode. *Recursive decoding* hingga beberapa putaran membuka representasi payload, sedangkan normalisasi menstabilkan variasi penulisan. Dengan demikian, *preprocessing* merupakan prasyarat fungsional bagi efektivitas *ruleset* pada data log nyata.

[PERLU BUKTI “seberapa besar”: RM2 memakai frasa kuantitatif. Lengkapi dengan eksperimen A/B (dengan vs tanpa *preprocessing*) atau setidaknya hitung berapa sampel encoded yang hanya terdeteksi setelah decode. Tanpa itu, jawaban RM2 tetap kualitatif.]

### 4.6.3 Rumusan Masalah Ketiga: Performa Deteksi

Rumusan masalah ketiga menanyakan performa sistem ditinjau dari akurasi, *precision*, *recall*, dan *F1-score*.

Jawaban kuantitatif dirangkum pada Tabel 4.12 dan dirinci per kelas pada Tabel 4.11, dengan landasan *confusion matrix* pada Tabel 4.10. Evaluasi menggunakan *ground truth* manual pada lingkungan DVWA sehingga metrik merefleksikan kesesuaian prediksi terhadap skenario uji yang dikendalikan peneliti, bukan terhadap dataset publik eksternal.

[PERLU BUKTI: setelah metrik terisi, nyatakan secara eksplisit nilai accuracy dan macro-F1, serta kelas dengan *recall*/*precision* terbaik dan terendah.]

### 4.6.4 Implikasi terhadap Mitigasi

Judul penelitian menekankan aspek mitigasi. Dalam lingkup prototipe yang dibangun, mitigasi diwujudkan pada tataran **deteksi, peringatan, dan rekomendasi**, bukan pada penutupan otomatis koneksi atau modifikasi *firewall*. Sistem menyediakan: (1) penandaan request, (2) *alert realtime*, (3) rekomendasi penanganan (validasi masukan, *output encoding*, *parameterized query*, peninjauan IP/endpoint), serta (4) jejak evaluasi untuk penyempurnaan *ruleset*. Hasil tersebut dapat menjadi masukan bagi integrasi operasional lanjutan, misalnya penyesuaian kebijakan keamanan atau integrasi dengan WAF/IPS, yang berada di luar implementasi inti penelitian ini.

### 4.6.5 Keterbatasan Hasil

Temuan Bab IV dibatasi oleh kondisi berikut.

1. Pengujian dilakukan pada DVWA di lingkungan terkontrol, sehingga generalisasi ke trafik produksi belum terbukti.
2. Deteksi bergantung pada kelengkapan *ruleset*; pola di luar rule atau *obfuscation* di luar kemampuan *recursive decode* berpotensi tidak terdeteksi.
3. Label aktual bersifat manual; kesalahan labeling peneliti akan memengaruhi metrik.
4. Skema multi-kelas *strict* dengan kelas Multiple dapat menurunkan metrik meskipun sistem telah mendeteksi indikasi serangan lintas tipe.
5. Penelitian tidak menggunakan model *machine learning*; kemampuan adaptasi terhadap serangan baru bergantung pada penambahan rule oleh administrator/peneliti.

---

## 4.7 Ringkasan Bab

Bab ini memaparkan bahwa prototipe WebLog-IDS telah diimplementasikan sebagai *pipeline* deteksi berbasis log Nginx dengan *ruleset* XSS dan SQLi, dilengkapi *preprocessing* decoding/normalisasi, penyimpanan hasil, dashboard, *alert* WebSocket, serta modul evaluasi multi-kelas. Pengaruh *preprocessing* dijelaskan melalui transformasi payload encoded menuju bentuk yang dapat dicocokkan rule. Performa kuantitatif dinyatakan melalui *confusion matrix* 4×4 dan metrik OvR, dengan angka final yang wajib dilengkapi dari hasil *run* evaluasi pada data labeled. Pembahasan dikembalikan kepada ketiga rumusan masalah, disertai batasan interpretasi agar klaim tidak melampaui bukti yang tersedia.

---

# Catatan Kritis (untuk penulis, tidak dimasukkan ke naskah skripsi)

Bagian ini mengevaluasi **kelemahan argumen dan kelengkapan data** pada draf di atas. Perbaiki butir-butir berikut sebelum sidang.

### 1. Ketergantungan pada data yang belum diisi

Hampir seluruh klaim performa (Subbab 4.5) masih berupa placeholder. Tanpa \(N\), matrix, dan metrik, Bab IV belum memenuhi tujuan penelitian keempat dan RM3. **Prioritas tertinggi:** labeling → Run Evaluation → isi Tabel 4.2, 4.10, 4.11, 4.12.

### 2. RM2 belum terjawab secara kuantitatif

BAB I memakai frasa “**seberapa besar** pengaruh decoding/normalisasi”. Draf saat ini hanya memberi argumen dan contoh kasus (kualitatif). Penguji dapat menilai jawaban RM2 lemah bila tidak ada:

- eksperimen dengan vs tanpa preprocess, atau  
- statistik “X dari Y payload encoded hanya terdeteksi setelah decode”.

### 3. Klaim “latensi rendah” (RM1) masih sebatas rancangan

Interval *polling* 0,5 detik ada di konfigurasi, tetapi belum ada pengukuran end-to-end (waktu tulis log → waktu deteksi/alert). Tanpa itu, “latensi rendah” mudah dipatahkan sebagai klaim spekulatif.

### 4. Potensi *overclaim* pada “aturan penguat/pengecualian”

Tujuan BAB I menyebut aturan penguat/pengecualian untuk menekan FP. Implementasi saat ini berpusat pada daftar pola positif (regex). Jika tidak ada *whitelist*/*exception rule* eksplisit, sesuaikan redaksi tujuan/pembahasan agar selaras implementasi, atau tambahkan mekanisme/penjelasan iterasi pengetatan pola sebagai bentuk “pengecualian” yang dapat dibuktikan.

### 5. Validitas *ground truth* manual

Label aktual dari peneliti pada DVWA sah untuk eksperimen terkendali, tetapi rentan bias (peneliti mengetahui payload yang dikirim). Antisipasi pertanyaan sidang: prosedur labeling, kriteria Multiple vs XSS/SQLi murni, dan apakah labeling *double-checked*.

### 6. Kelas Multiple dan skema *strict*

Skema *strict* secara akademis konsisten, tetapi dapat “menghukum” deteksi yang secara keamanan berguna (payload berbahaya → Multiple). Siapkan penjelasan bahwa evaluasi mengukur **ketepatan kelas**, bukan hanya “apakah berbahaya”. Bila diminta, siapkan metrik tambahan opsional (misalnya *attack vs normal* biner) di lampiran—jangan mengganti skema utama tanpa konsistensi dengan sistem.

### 7. Ketidakseimbangan data dan macro-average

Jika Normal jauh lebih banyak, accuracy dapat tampak tinggi sementara *recall* serangan lemah. Wajib laporkan distribusi kelas dan utamakan pembahasan macro-F1 serta metrik kelas XSS/SQLi, bukan accuracy saja.

### 8. Cakupan serangan sempit vs klaim mitigasi

Sistem hanya menargetkan XSS dan SQLi pada layer log. Jangan mengklaim proteksi menyeluruh aplikasi web. Mitigasi yang terbukti hanyalah deteksi + alert + rekomendasi teks, bukan pencegahan otomatis.

### 9. Ketergantungan pada kualitas *ruleset*

Rule SQLi-003 (komentar `--`, `#`) dan sejenisnya berpotensi FP pada URI yang kebetulan memuat karakter tersebut. Rule XSS-004 (`alert(`) dapat meleset pada payload XSS tanpa `alert`. Bahas risiko FP/FN ini jujur di keterbatasan; bila ada data FP aktual, kaitkan ke rule spesifik.

### 10. Kesesuaian metodologi BAB I vs implementasi evaluasi

BAB I menyebut *false positive rate*; draf sudah menyiapkan kolom FPR. Pastikan angka FPR benar-benar dihitung/ditampilkan di sistem atau dihitung manual dari TP/FP/TN/FN agar tidak inkonsisten dengan teks metodologi.

### 11. Reproduktibilitas

Untuk sidang, siapkan: tanggal eksperimen, versi *ruleset*, nilai konfigurasi (`READ_FROM_BEGINNING`, path log), dan ekspor hasil evaluasi. Tanpa itu, angka sulit diverifikasi penguji.

### 12. Bahasa dan sitasi pada Bab IV

Bab hasil umumnya minim sitasi baru; fokus pada data Anda. Hindari frasa evaluatif kosong (“sangat baik”, “berjalan sempurna”). Setiap penilaian mutu harus menunjuk ke tabel/metrik.

---

## Checklist pengisian sebelum naskah final

| No | Tindakan | Status |
|---|---|---|
| 1 | Lengkapi spesifikasi lingkungan (Tabel 4.1) | ☐ |
| 2 | Selesaikan labeling; isi distribusi data (Tabel 4.2) | ☐ |
| 3 | Sisipkan screenshot empat halaman UI | ☐ |
| 4 | Ganti contoh payload dengan log nyata (Tabel 4.6, 4.8) | ☐ |
| 5 | Isi frekuensi rule terpicu (Tabel 4.9) | ☐ |
| 6 | Run Evaluation; isi matrix dan metrik (Tabel 4.10–4.12) | ☐ |
| 7 | Tulis interpretasi 4.5.5 dengan angka konkret | ☐ |
| 8 | (Disarankan) eksperimen A/B preprocessing untuk RM2 | ☐ |
| 9 | (Disarankan) ukur indikasi latensi untuk RM1 | ☐ |
| 10 | Selaraskan redaksi “pengecualian FP” dengan implementasi | ☐ |
| 11 | Hapus semua penanda `[PERLU BUKTI]` dari naskah final | ☐ |
| 12 | Jangan menyalin bagian “Catatan Kritis” ke skripsi | ☐ |

---

*Draf ini disusun dalam bahasa formal akademik untuk program studi Informatika jenjang S1. Angka, tangkapan layar, dan cuplikan log wajib diganti dengan hasil eksperimen aktual sebelum dimasukkan ke dokumen skripsi final.*
