# BAB IV — HASIL DAN PEMBAHASAN

> **Catatan penggunaan (hapus sebelum disalin ke skripsi):**
> - Teks dalam kurung siku `[...]` adalah instruksi/placeholder yang harus Anda ganti dengan data nyata hasil pengujian.
> - Tanda `[Gambar 4.x]` menandai posisi screenshot yang harus Anda sediakan.
> - Angka pada tabel yang diberi tanda "(contoh)" harus diganti dengan hasil pengujian Anda yang sebenarnya.
> - Format penomoran subbab dapat disesuaikan dengan pedoman skripsi kampus Anda.

---

## 4.1 Hasil Implementasi Sistem

Bab ini menyajikan hasil implementasi dan pengujian sistem deteksi intrusi berbasis analisis *access log* Nginx (WebLog-IDS) yang dikembangkan. Pengujian dilakukan secara bertahap mengikuti alur pemrosesan data pada sistem, yakni pembacaan dan *parsing* log, prapemrosesan (*preprocessing*) payload, pencocokan aturan (*rule matching*), klasifikasi dan penentuan tingkat keparahan (*severity*), penyimpanan data ke basis data, serta notifikasi *realtime* melalui protokol WebSocket. Penyajian hasil secara bertahap ini dimaksudkan agar setiap komponen sistem dapat diverifikasi kinerjanya secara terukur dan independen.

Sistem diimplementasikan menggunakan kerangka kerja FastAPI pada sisi *backend* dengan basis data MySQL, serta antarmuka dasbor web pada sisi *frontend*. Setelah proses instalasi dependensi dan konfigurasi lingkungan selesai dilakukan, sistem dijalankan dan diverifikasi ketersediaannya melalui endpoint pemeriksaan kesehatan (`/api/health`) yang mengembalikan respons `{"status": "ok"}`. Hasil tersebut menunjukkan bahwa seluruh komponen sistem berhasil terinisialisasi dengan baik, termasuk koneksi ke basis data dan pemuatan berkas aturan deteksi.

[Gambar 4.1 — Tangkapan layar dasbor WebLog-IDS yang berjalan / respons endpoint /api/health]

---

### 4.1.1 Hasil Pengujian Pembacaan dan Parsing Log

Tahap pertama pipeline deteksi adalah pembacaan berkas *access log* Nginx dan ekstraksi field-field relevan dari setiap baris log menggunakan ekspresi reguler (*regular expression*) sesuai format *combined log*. Setiap baris log yang sesuai format akan diuraikan menjadi sejumlah field, antara lain alamat IP sumber, penanda waktu (*timestamp*), metode HTTP, *request URI*, kode status respons, dan *user agent*.

Sebagai ilustrasi, berikut disajikan satu baris log mentah beserta hasil *parsing*-nya.

**Baris log mentah:**

```
45.1.1.1 - - [14/Jun/2026:12:00:00 +0800] "GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1" 200 100 "-" "Mozilla/5.0"
```

**Tabel 4.1 Hasil parsing satu baris access log**

| Field | Nilai |
|---|---|
| `ip_address` | 45.1.1.1 |
| `timestamp` | 14/Jun/2026:12:00:00 +0800 |
| `http_method` | GET |
| `request_uri` | /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E |
| `status_code` | 200 |
| `user_agent` | Mozilla/5.0 |

Berdasarkan hasil pengujian terhadap berkas sampel log sebanyak [N] baris, sebanyak [N] baris berhasil diparsing dengan benar, sementara [N] baris tidak sesuai format dan dilewati oleh sistem. Baris yang tidak sesuai format adalah baris yang tidak mengikuti pola *combined log* Nginx sehingga tidak memuat informasi yang diperlukan untuk proses deteksi.

**Tabel 4.2 Rekapitulasi hasil parsing berkas sampel log (contoh — sesuaikan)**

| Keterangan | Jumlah Baris | Persentase |
|---|---|---|
| Baris berhasil diparsing | [N] | [%] |
| Baris tidak sesuai format (dilewati) | [N] | [%] |
| **Total** | **[N]** | **100%** |

[Gambar 4.2 — Tangkapan layar keluaran modul parser saat memproses berkas sampel log]

---

### 4.1.2 Hasil Prapemrosesan (Preprocessing) Payload

Prapemrosesan payload merupakan tahap kritis dalam sistem ini karena payload serangan pada umumnya dikirim dalam kondisi ter-*encode* agar terhindar dari mekanisme deteksi sederhana. Prapemrosesan pada sistem WebLog-IDS terdiri atas dua tahap, yaitu dekode URL rekursif (*recursive URL decoding*) dan normalisasi payload. Hasil kedua tahap tersebut disajikan pada subbab berikut.

#### 4.1.2.1 Hasil Dekode URL Rekursif

Dekode URL rekursif dilakukan untuk mengembalikan payload yang dikodekan dalam format *percent-encoding* ke bentuk aslinya. Proses dekode dilakukan berulang kali (maksimal tiga ronde) hingga string tidak lagi berubah, sehingga payload yang dikodekan ganda (*double encoding*) maupun bertingkat tiga (*triple encoding*) dapat dikembalikan ke bentuk aslinya. Berdasarkan hasil pengujian, terdapat [N] dari [N] payload uji yang berhasil dikodekan lebih dari satu kali dan terdeteksi hanya setelah proses dekode rekursif dilakukan.

**Tabel 4.3 Hasil dekode URL rekursif pada berbagai variasi payload**

| No | Payload Mentah (dalam Log) | Hasil Dekode | Jumlah Ronde Dekode |
|---|---|---|---|
| 1 | `%3Cscript%3Ealert(1)%3C%2Fscript%3E` | `<script>alert(1)</script>` | 1 |
| 2 | `%253Cscript%253Ealert(1)%253C%252Fscript%253E` | `<script>alert(1)</script>` | 2 |
| 3 | `1%27%20or%201%3D1--` | `1' or 1=1--` | 1 |
| 4 | `union%20select%20password%20from%20users` | `union select password from users` | 1 |
| 5 | `/login.php` | `/login.php` (tidak berubah) | 0 |
| 6 | [payload triple encoding, uji tambahan] | [hasil] | 3 |
| 7 | [payload dengan null byte/spesial karakter, uji tambahan] | [hasil] | [n] |

Tabel 4.3 memperlihatkan bahwa payload pada baris ke-2 yang dikodekan dua kali (misalnya karakter `<` direpresentasikan sebagai `%253C`) hanya dapat dikembalikan ke bentuk `<script>` melalui dua ronde dekode. Tanpa mekanisme dekode rekursif, payload tersebut akan tetap berbentuk `%3Cscript%3E` dan berpotensi lolos dari proses pencocokan aturan. Sebaliknya, payload normal pada baris ke-5 tidak mengalami perubahan sehingga proses dekode berhenti lebih awal; hal ini menunjukkan bahwa mekanisme tersebut tidak menimbulkan biaya komputasi yang berarti pada trafik normal.

#### 4.1.2.2 Hasil Normalisasi Payload

Setelah proses dekode, payload dinormalisasi melalui tiga operasi, yaitu konversi seluruh karakter ke huruf kecil (*lowercase*), penyatuan segala jenis karakter whitespace (tab, baris baru, dan lain-lain) menjadi satu spasi, serta penghapusan spasi berlebih pada awal dan akhir string. Normalisasi diperlukan agar pencocokan aturan menjadi konsisten terhadap variasi penulisan payload oleh penyerang.

**Tabel 4.4 Hasil normalisasi payload**

| No | Payload Sebelum Normalisasi | Payload Sesudah Normalisasi |
|---|---|---|
| 1 | `<SCRIPT>alert(1)</SCRIPT>` | `<script>alert(1)</script>` |
| 2 | `1'   OR   1=1--` | `1' or 1=1--` |
| 3 | `UNION\tSELECT\npassword` | `union select password` |
| 4 | [contoh payload dengan campuran huruf besar/whitespace dari pengujian Anda] | [hasil] |

Hasil pada Tabel 4.4 menunjukkan bahwa payload yang semula ditulis dengan variasi kapitalisasi dan penyisipan whitespace tidak teratur telah diseragamkan menjadi bentuk baku. Tanpa normalisasi, aturan deteksi harus mencakup seluruh kemungkinan variasi penulisan (misalnya `Union Select`, `UNION SELECT`, `union   select`), yang tentu saja tidak efisien dan rentan terhadap celah. Dengan normalisasi, satu aturan regex tunggal (`union\s+select`) telah mencukupi untuk mendeteksi seluruh variasi tersebut.

#### 4.1.2.3 Pengaruh Prapemrosesan terhadap Akurasi Deteksi

Untuk membuktikan kontribusi tahap prapemrosesan, dilakukan pengujian komparatif dengan menjalankan pipeline deteksi dalam dua skenario: (a) tanpa prapemrosesan (payload mentah dari log langsung dicocokkan dengan aturan) dan (b) dengan prapemrosesan (dekode rekursif + normalisasi).

**Tabel 4.5 Perbandingan hasil deteksi dengan dan tanpa prapemrosesan (contoh — sesuaikan)**

| Skenario | Payload Terdeteksi | Payload Tidak Terdeteksi | Persentase Deteksi |
|---|---|---|---|
| Tanpa prapemrosesan | [N] | [N] | [%] |
| Dengan prapemrosesan | [N] | [N] | [%] |

Hasil pengujian menunjukkan bahwa payload yang dikodekan satu kali maupun bertingkat gagal terdeteksi pada skenario tanpa prapemrosesan karena bentuk ter-*encode*-nya tidak cocok dengan pola aturan yang telah didefinisikan. Sebagai contoh, aturan `XSS-001` dengan pola `<\s*script[^>]*>.*?<\s*/\s*script\s*>` hanya akan cocok dengan string `<script>` dan tidak akan cocok dengan `%3Cscript%3E` maupun `%253Cscript%253E`. Setelah prapemrosesan diterapkan, seluruh payload tersebut dikembalikan ke bentuk aslinya sehingga berhasil dikenali oleh *rule engine*. Temuan ini menegaskan bahwa dekode URL rekursif dan normalisasi payload merupakan komponen penentu keberhasilan deteksi, khususnya terhadap teknik obfuscation berbasis *encoding* yang lazim digunakan penyerang.

---

### 4.1.3 Hasil Deteksi Berbasis Aturan (Rule-Based Detection)

Tahap pencocokan aturan dilakukan oleh *rule engine* yang memuat 14 aturan deteksi yang telah didefinisikan sebelumnya, terdiri atas 4 aturan XSS dan 10 aturan SQL Injection. Setiap aturan memuat identifier, pola ekspresi reguler, jenis serangan, tingkat keparahan, dan deskripsi. Pencocokan dilakukan menggunakan fungsi `re.search` dengan opsi `re.IGNORECASE` terhadap payload hasil prapemrosesan.

**Tabel 4.6 Rekapitulasi aturan deteksi yang terpicu selama pengujian (contoh — sesuaikan)**

| ID Aturan | Nama Aturan | Jenis | Jumlah Terpicu | Contoh Payload yang Cocok |
|---|---|---|---|---|
| XSS-001 | XSS Script Tag | XSS | [n] | `<script>alert(1)</script>` |
| XSS-004 | XSS Alert Function | XSS | [n] | `alert(` |
| SQLI-001 | SQLi Union Select | SQLi | [n] | `union select password from users` |
| SQLI-002 | SQLi Boolean Based | SQLi | [n] | `1' or 1=1--` |
| SQLI-003 | SQLi Comment Pattern | SQLi | [n] | `--` |
| ... | ... | ... | ... | ... |

Selain deteksi satu jenis serangan, sistem juga mampu mengidentifikasi baris log yang memuat lebih dari satu jenis serangan sekaligus, yang diklasifikasikan sebagai **Multiple**. Contohnya adalah baris log berikut yang memuat payload XSS pada parameter `a` dan payload SQLi pada parameter `b`:

```
45.4.4.4 - - [14/Jun/2026:12:00:03 +0800] "GET /?a=%3Cscript%3Ealert(1)%3C%2Fscript%3E&b=union%20select HTTP/1.1" 200 90 "-" "sqlmap/1.7"
```

Setelah prapemrosesan, payload gabungan `/?a=<script>alert(1)</script>&b=union select` memicu aturan XSS-001 sekaligus SQLI-001, sehingga baris tersebut diberi label Multiple dengan tingkat keparahan tertinggi di antara aturan yang terpicu. Kemampuan ini penting karena serangan terhadap aplikasi web nyata kerap melibatkan kombinasi beberapa vektor serangan dalam satu permintaan.

---

### 4.1.4 Hasil Klasifikasi dan Penentuan Tingkat Keparahan

Setelah aturan terpicu, sistem mengklasifikasikan setiap baris log ke dalam salah satu dari empat label: **Normal**, **XSS**, **SQLi**, atau **Multiple**, kemudian menetapkan tingkat keparahan (*severity*) pada empat jenjang: `none`, `low`, `medium`, dan `high`, beserta rekomendasi mitigasi yang sesuai. Berikut rekapitulasi hasil klasifikasi selama pengujian.

**Tabel 4.7 Distribusi hasil klasifikasi (contoh — sesuaikan)**

| Label | Jumlah Baris Log | Persentase |
|---|---|---|
| Normal | [N] | [%] |
| XSS | [N] | [%] |
| SQLi | [N] | [%] |
| Multiple (XSS + SQLi) | [N] | [%] |
| **Total** | **[N]** | **100%** |

**Tabel 4.8 Distribusi tingkat keparahan (contoh — sesuaikan)**

| Severity | Jumlah Deteksi | Contoh Rekomendasi Mitigasi yang Dihasilkan |
|---|---|---|
| low | [N] | [isi rekomendasi dari sistem] |
| medium | [N] | [isi rekomendasi dari sistem] |
| high | [N] | [isi rekomendasi dari sistem] |

[Gambar 4.3 — Tangkapan layar halaman ringkasan dasbor (/api/dashboard/summary)]

---

### 4.1.5 Hasil Penyimpanan Data dan Notifikasi Realtime

Seluruh baris log yang telah diproses beserta hasil deteksinya disimpan ke basis data MySQL pada tabel `access_log` dan `detection_result`. Verifikasi dilakukan dengan memeriksa isi kedua tabel tersebut melalui antarmuka phpMyAdmin, yang menunjukkan bahwa seluruh [N] baris log berhasil tersimpan beserta payload ter-*encode*, payload hasil dekode, label serangan, tingkat keparahan, dan aturan yang terpicu.

[Gambar 4.4 — Tangkapan layar isi tabel access_log dan detection_result pada phpMyAdmin]

Untuk fitur notifikasi *realtime*, ketika baris log baru yang terdeteksi sebagai serangan ditambahkan ke berkas log yang dipantau, sistem menyiarkan (*broadcast*) alert ke seluruh klien dasbor melalui koneksi WebSocket tanpa perlu penyegaran halaman. Pengujian dilakukan dengan menjalankan dasbor dan *client* WebSocket secara bersamaan, kemudian menyuntikkan baris log serangan ke berkas log; alert terdeteksi muncul pada dasbor dalam waktu [n] detik setelah baris ditambahkan.

[Gambar 4.5 — Tangkapan layar alert serangan yang muncul pada dasbor secara realtime]

---

### 4.1.6 Hasil Ekspor Laporan

Sistem menyediakan fitur ekspor laporan deteksi dalam format CSV melalui endpoint `/api/reports/export-csv`. Berkas CSV yang dihasilkan memuat kolom [sebutkan kolom: waktu, IP sumber, payload, label, severity, aturan yang terpicu, dan sebagainya], yang selanjutnya digunakan sebagai bahan perhitungan metrik evaluasi pada subbab 4.2.

[Gambar 4.6 — Tangkapan layar proses dan hasil ekspor laporan CSV]

---

## 4.2 Pengujian dan Evaluasi Sistem

### 4.2.1 Skenario Pengujian

Pengujian dilakukan menggunakan data uji yang terdiri atas [N] baris *access log*, yang mencakup [N] baris trafik normal dan [N] baris trafik serangan. Trafik serangan dibangkitkan menggunakan [generator serangan bawaan sistem / aktivitas manual terhadap aplikasi DVWA], yang menghasilkan variasi payload XSS dan SQLi dengan tingkat pengodean yang berbeda-beda (tanpa pengodean, pengodean tunggal, dan pengodean ganda). Label kebenaran (*ground truth*) setiap baris ditetapkan secara manual sebagai dasar perhitungan metrik evaluasi.

**Tabel 4.9 Komposisi data uji (contoh — sesuaikan)**

| Kategori | Jumlah Baris | Keterangan |
|---|---|---|
| Trafik normal | [N] | Permintaan HTTP wajar tanpa payload serangan |
| Serangan XSS | [N] | Variasi payload XSS, ter-encode dan tidak |
| Serangan SQLi | [N] | Variasi payload SQLi, ter-encode dan tidak |
| Serangan gabungan | [N] | XSS dan SQLi dalam satu baris log |
| **Total** | **[N]** | |

### 4.2.2 Hasil Evaluasi Deteksi

Evaluasi kinerja deteksi dilakukan dengan membandingkan hasil klasifikasi sistem terhadap label kebenaran, yang direpresentasikan dalam *confusion matrix* dan metrik presisi, *recall*, F1-*score*, dan akurasi. Perhitungan metrik dilakukan menggunakan pustaka scikit-learn.

**Tabel 4.10 Confusion matrix hasil deteksi (contoh — sesuaikan)**

| | Prediksi Normal | Prediksi XSS | Prediksi SQLi | Prediksi Multiple |
|---|---|---|---|---|
| **Aktual Normal** | [TP] | [FP] | [FP] | [FP] |
| **Aktual XSS** | [FN] | [TP] | — | — |
| **Aktual SQLi** | [FN] | — | [TP] | — |
| **Aktual Multiple** | [FN] | — | — | [TP] |

**Tabel 4.11 Metrik evaluasi per kelas (contoh — sesuaikan)**

| Kelas | Presisi | Recall | F1-Score |
|---|---|---|---|
| Normal | [%] | [%] | [%] |
| XSS | [%] | [%] | [%] |
| SQLi | [%] | [%] | [%] |
| Multiple | [%] | [%] | [%] |
| **Akurasi keseluruhan** | | | [%] |

### 4.2.3 Analisis False Positive dan False Negative

Berdasarkan hasil evaluasi, terdapat [N] baris yang mengalami kesalahan deteksi, terdiri atas [N] *false positive* dan [N] *false negative*. [Jelaskan kasus konkret: payload apa yang salah diklasifikasi, mengapa — misalnya aturan `SQLI-003` (pola komentar SQL `--` atau `#`) berpotensi memicu *false positive* pada URL sah yang memuat karakter `#`; atau payload dengan pengodean melebihi tiga ronde yang gagal didekode sehingga lolos deteksi.] Analisis ini menjadi dasar penyempurnaan aturan pada masa mendatang.

### 4.2.4 Pengujian Performa Sistem

Pengujian performa dilakukan untuk mengukur kemampuan sistem memproses log secara *realtime*. Pengukuran mencakup waktu rata-rata pemrosesan satu baris log (dari *parsing* hingga penyimpanan hasil deteksi) dan waktu tunda (*latency*) munculnya alert pada dasbor sejak baris log ditambahkan.

**Tabel 4.12 Hasil pengujian performa (contoh — sesuaikan)**

| Metrik | Nilai |
|---|---|
| Waktu rata-rata pemrosesan satu baris log | [n] ms |
| Throughput pemrosesan | [n] baris/detik |
| Latensi alert realtime (log ditulis → alert tampil) | [n] ms/detik |

### 4.2.5 Pengujian Batasan Sistem

Pengujian batasan dilakukan untuk mengetahui kondisi ketika sistem tidak lagi bekerja optimal. Salah satu batasan yang diuji adalah jumlah ronde maksimal dekode URL, yang ditetapkan sebesar tiga. Ketika baris log memuat payload dengan pengodean empat kali lipat (*quadruple encoding*), dekode hanya berjalan tiga kali sehingga payload belum sepenuhnya kembali ke bentuk asli dan tidak dikenali oleh aturan deteksi. [Sertakan hasil pengujian konkret.] Batasan lain yang diidentifikasi meliputi [ketergantungan pada format log Nginx *combined*, cakupan aturan yang belum mencakup seluruh variasi serangan, dan sebagainya].

---

## 4.3 Pembahasan

Hasil pengujian pada subbab 4.1 dan 4.2 menunjukkan bahwa pendekatan deteksi intrusi berbasis aturan (*rule-based*) yang dikombinasikan dengan prapemrosesan payload yang memadai mampu menghasilkan deteksi yang akurat terhadap serangan XSS dan SQL Injection pada *access log* Nginx.

Pertama, temuan pada subbab 4.1.2.3 menegaskan bahwa dekode URL rekursif merupakan komponen penentu keberhasilan deteksi. Teknik obfuscation berbasis pengodean bertingkat, yang lazim digunakan untuk menembus mekanisme filtrasi sederhana, terbukti dapat dinetralkan oleh dekode hingga tiga ronde. Normalisasi payload turut berperan menyederhanakan definisi aturan, karena satu pola ekspresi reguler telah mencakup seluruh variasi kapitalisasi dan penataan whitespace payload.

Kedua, hasil evaluasi pada subbab 4.2.2 menunjukkan [ringkas angka utama: akurasi, presisi, recall]. Nilai *recall* yang [tinggi/cukup] pada kelas serangan menunjukkan bahwa sebagian besar payload serangan berhasil dikenali, sedangkan *false positive* yang ditemukan bersumber terutama dari aturan berpola umum seperti pola komentar SQL. [Kaitkan dengan penelitian terdahulu dari Bab 2: bandingkan akurasi/pendekatan Anda dengan penelitian yang dirujuk.]

Ketiga, dibandingkan dengan pendekatan *machine learning*, pendekatan berbasis aturan memberikan keunggulan dalam interpretabilitas — setiap deteksi dapat ditelusuri ke aturan spesifik yang terpicu — serta keterbukaan terhadap pembaruan, karena penambahan aturan cukup dilakukan dengan menyunting berkas JSON tanpa perubahan kode. Sebaliknya, pendekatan ini memiliki keterbatasan pada cakupan: aturan hanya mengenali pola yang telah didefinisikan sebelumnya sehingga serangan dengan pola yang belum terdefinisi (zero-day) tidak akan terdeteksi.

Dengan demikian, secara keseluruhan sistem WebLog-IDS yang dikembangkan telah memenuhi tujuan penelitian, yakni [sebutkan rumusan masalah/tujuan dari Bab 1: membangun sistem deteksi intrusi realtime berbasis analisis access log untuk serangan XSS dan SQLi dengan notifikasi realtime].
