3.6.	Penentuan Severity
Dalam sistem deteksi intrusi, sekadar mendeteksi adanya serangan tidak cukup. Setiap serangan yang terdeteksi perlu diklasifikasikan tingkat dampaknya agar administrator dapat memprioritaskan tindakan mitigasi yang tepat. Penelitian WebLog-IDS ini menggunakan empat tingkat severity, yaitu Low, Medium, High, dan Critical. Tingkat severity ditentukan berdasarkan CVSS v3.1 (Common Vulnerability Scoring System Version 3.1) yang diterbitkan oleh FIRST.org sebagai standar internasional untuk mengukur tingkat keparahan kerentanan perangkat lunak.
CVSS v3.1 merupakan standar pengukuran tingkat keparahan kerentanan yang dikembangkan oleh Forum of Incident Response and Security Teams (FIRST). Skor CVSS dihitung berdasarkan **Base Metrics** yang terdiri dari delapan komponen vektor, yaitu
1.	Attack Vector (AV) yaitu jalur eksploitasi: Network (N), Adjacent (A), Local (L), atau Physical (P). Pada penelitian ini, seluruh serangan berasal dari log akses Nginx yang terekspos melalui jaringan, sehingga bernilai Network (N).
2.	Attack Complexity (AC) yaitu kompleksitas eksploitasi: Low (L) atau High (H). Payload XSS dan SQLi yang umum ditemui memiliki kompleksitas rendah.
3.	Privileges Required (PR) yaitu hak akses yang dibutuhkan penyerang: None (N), Low (L), atau High (H). Sebagian besar serangan terhadap aplikasi web dapat dilakukan tanpa autentikasi.
4.	User Interaction (UI) yaitu interaksi pengguna: None (N) atau Required (R). XSS Reflected dan DOM-based memerlukan interaksi pengguna, sedangkan SQLi tidak.
5.	Scope (S) yaitu cakupan dampak: Unchanged (U) atau Changed (C). XSS yang menyerang konteks browser korban masuk kategori Changed.
6.	Confidentiality (C) yaitu dampak terhadap kerahasiaan: None (N), Low (L), atau High (H). SQLi yang mengekstraksi data sensitif bernilai High.
7.	Integrity (I) yaitu dampak terhadap integritas: None (N), Low (L), atau High (H).
8.	Availability (A) yaitu dampak terhadap ketersediaan: None (N), Low (L), atau High (H).
Base score dihitung menggunakan rumus resmi CVSS v3.1 yang terdapat pada CVSS v3.1 Specification Document Section 7.1. Skor kemudian dipetakan ke skala kualitatif severity berdasarkan Section 7.4 dari dokumen yang sama.
Tabel 3.2 Penentuan Severity Berdasarkan CVSS
CVSS Base Score	Severity	Deskripsi
0.0	None	Tidak ada dampak
0.1 – 3.9	Low	Dampak minimal, exploit sulit
4.0 – 6.9	Medium	Dampak signifikan, butuh kondisi tertentu
7.0 – 8.9	High	Dampak serius, mudah dieksploitasi
9.0 – 10.0	Critical	Dampak katastropik, exploit trivial

3.7. Menentukan Severity untuk Serangan XSS
Tabel 3.3 Severity Serangan XSS
Tipe Serangan	Payload Contoh	CVSS v3.1 Vector	Base Score	Severity	Justifikasi
XSS Reflected	<script>alert(1)
</script> via parameter URL	AV:N/AC:L/PR:N/UI:R
/S:C/C:L/I:L/A:N	6.1	Medium	Butuh user interaction (klik link), dampak terbatas pada session browser korban
XSS Stored	Payload tersimpan di DB, tampil di halaman admin	AV:N/AC:L/PR:N/UI:R
/S:C/C:H/I:H/A:N	9.0–9.1	Critical	Persistent, menyebar otomatis ke semua pengguna yang mengakses halaman terinfeksi
XSS DOM-based	<img src=x onerror=...> via fragment URL	AV:N/AC:H/PR:N/UI:R
/S:C/C:L/I:L/A:N	5.4	Medium	Dampak sama reflected, tapi exploitation bergantung pada eksekusi sisi klien
XSS Attempt (gagal/blocked)	Payload tidak ter-eksekusi (WAF/escape)	—	—	Low	Logging anomaly, payload terdeteksi tapi tidak berhasil

3.8. Menentukan Severity untuk Serangan SQL Injection

Tabel 3.4 Severity Serangan SQL Injection
Tipe Serangan	Payload Contoh	CVSS v3.1 Vector	Base Score	Severity	Justifikasi
SQLi — Auth Bypass	' OR '1'='1' – pada
 form login	AV:N/AC:L/PR:N
/UI:N/S:U/C:H/I:H/A:H	9.8	Critical	Akses penuh tanpa kredensial, manipulasi database langsung
SQLi — Union-Based	UNION SELECT username,password FROM users--	AV:N/AC:L/PR:N
/UI:N/S:U/C:H/I:N/A:N	7.5	High	Ekstraksi data sensitif, exploit langsung tanpa interaksi
SQLi — Error-Based	' AND extractvalue(1,concat(0x7e,(SELECT version())))--	AV:N/AC:L/PR:N
/UI:N/S:U/C:L/I:N/A:N	5.3	Medium	Hanya bocoran info via error message, bukan akses data langsung
SQLi — Time-Based Blind	'; IF(1=1) WAITFOR DELAY '0:0:5'--	AV:N/AC:L/PR:N
/UI:N/S:U/C:L/I:L/A:N	6.5	Medium	Inference data perlahan, dampak tertunda
SQLi — Stacked Queries (write)	; DROP TABLE users;-- / ; INSERT INTO admin...	AV:N/AC:L/PR:N
/UI:N/S:U/C:H/I:H/A:H	9.8	Critical	Modifikasi/hapus data, kelangsungan layanan terganggu
SQLi Attempt (gagal/fingerprint)	' OR 1=1 terblokir, atau karakter anomali tanpa payload utuh	—	—	Low	Reconnaisance, payload tidak ter-eksekusi
