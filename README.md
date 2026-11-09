# HydraSec — Website Vulnerability Scanner

**HydraSec** adalah platform web untuk **membantu perusahaan, kelompok UMKM, bahkan perorangan mendeteksi kerentanan (vulnerability) yang terdapat pada website mereka** — menggunakan enam tool pengujian keamanan standar industri yang terkonsolidasi dalam satu antarmuka.

<p align="center">
        <img width="49%" alt="Screenshot 2026-11-09 205140" src="https://github.com/user-attachments/assets/75825be9-7645-4e60-8d86-b051a38002a9" />
        <img width="49%" alt="Screenshot 2026-11-09 205152" src="https://github.com/user-attachments/assets/75468aeb-4d98-4947-beb7-369d5256e8df" />
</p>
<p align="center">
        <img width="49%" alt="Screenshot 2026-11-09 205201" src="https://github.com/user-attachments/assets/ccbe94f6-6631-4ced-bacd-8f6fb09b7964" />
        <img width="49%" alt="Screenshot 2026-11-09 205212" src="https://github.com/user-attachments/assets/26aa34d6-60c7-4eb9-98e0-699c4d3cd846" />
</p>
<p align="center">
        <img width="49%" alt="Screenshot 2026-11-09 205229" src="https://github.com/user-attachments/assets/08ea5789-63dd-4b08-878c-6c15b2a90201" />
        <img width="49%" alt="Screenshot 2026-11-09 205407" src="https://github.com/user-attachments/assets/f4f813bf-d7dc-4440-b128-091c45073c37" />
</p>
<p align="center">
        <img width="49%" alt="Screenshot 2026-11-09 205455" src="https://github.com/user-attachments/assets/f1319e8a-fb9d-4bbf-951c-32ca0abf18ad" />
        <img width="49%" alt="Screenshot 2026-11-09 205811" src="https://github.com/user-attachments/assets/993ae53d-1297-4338-a50b-1833511073f2" />
</p>

## Demo Aplikasi
https://youtu.be/---Ny7KHdEk

## Latar Belakang & Tujuan

Hampir semua bisnis saat ini memiliki website — etalase UMKM, profil perusahaan, hingga aplikasi web sederhana milik perorangan. Namun kebanyakan pemiliknya **tidak pernah tahu apakah website-nya memiliki celah keamanan** seperti port yang tidak sengaja terbuka, halaman admin yang bocor, SQL injection pada form kontak, atau bahkan XSS pada kolom komentar.

Masalahnya klasik:

- **Pengujian keamanan profesional mahal** — satu kali jasa penetration testing komersial bisa jutaan rupiah, tidak terjangkau untuk UMKM.
- **Tool keamanan itu sulit** — nmap, sqlmap, nuclei, ffuf, dan kawan-kawan adalah program dengan Command-Line Interface yang butuh keahlian khusus untuk dijalankan dan dibaca hasilnya.
- **Format laporan terfragmentasi** — setiap tool menghasilkan output berbeda (XML, JSON, log teks), sehingga pemilik website kesulitan memahami keseluruhan risikonya.

**HydraSec menjawabnya:** pemilik website cukup membuka browser, memasukkan alamat website-nya sendiri, dan platform ini menjalankan keenam tool secara otomatis di dalam kontainer yang aman, menampilkan prosesnya secara real-time seperti terminal asli, lalu menyatukan seluruh temuan ke dalam **satu laporan kerentanan terstandar** — lengkap dengan tingkat keparahan, lokasi, deskripsi, dan rekomendasi perbaikan.

> Semua pemrosesan terjadi di mesin sendiri (localhost). Website yang dipindai tidak dikirim ke pihak ketiga mana pun.

## Untuk Siapa

| Pengguna | Kebutuhan yang dijawab |
|---|---|
| **Pemilik UMKM** | Cek berkala apakah website toko/bisnisnya punya celah, tanpa harus paham CLI |
| **Tim IT perusahaan kecil–menengah** | Rekon dan vuln-scan rutin yang terdokumentasi: riwayat per user, statistik per tool, laporan JSON |
| **Perorangan / developer** | Audit cepat sebelum rilis: port, direktori tersembunyi, SQLi, XSS, CVE berbasis template |
| **Kelas / lab keamanan** | Demonstrasi arsitektur SOAR: orkestrasi kontainer, antrean, streaming log, normalisasi data |

> **Etika penggunaan:** platform ini dirancang untuk memindai **website milik sendiri atau yang memiliki izin resmi**. Memindai website orang lain tanpa izin adalah pelanggaran hukum. Guard SSRF bawaan menolak localhost/alamat privat secara default, dan penggunaan tetap menjadi tanggung jawab pengguna.

---

## Tool yang Terkonsolidasi

| Nama Tools | Fungsi | Output |
|---|---|---|
| **nmap** 7.95 | Port scanning | XML |
| **nuclei** 3.3.7 free-tier | Pemindaian kerentanan berbasis 9000+ template komunitas: CVE, misconfiguration, exposed panel | JSONL |
| **xray** 1.9.11 community | Deep web assessment: XSS, SQLi, SSRF, redirect, dan puluhan kelas lain | JSON |
| **XSStrike** | Deteksi & konfirmasi celah Cross-Site Scripting (XSS) dengan payload yang lolos filter | Console |
| **sqlmap** | Deteksi & konfirmasi SQL injection pada parameter URL | Log |
| **ffuf** 2.1.0 | Fuzzing directory/parameter berdasarkan wordlist | JSON |

Setiap tool dikemas sebagai **kontainer ephemeral**: hanya menyala saat dipanggil, terisolasi total, dan terhapus otomatis setelah selesai.

## Fitur Utama

1. **Antrean terdistribusi & kendali konkurensi** — API tidak pernah mengeksekusi tool langsung; tugas diantrikan di Redis (BullMQ) dan worker memproses maksimal 2 scan paralel. Server tidak akan OOM walau banyak permintaan bersamaan.
2. **Log streaming real-time** — output stdout/stderr tool di-stream via Docker API → Redis pub/sub → WebSocket (Nginx) → **xterm.js** di browser. Melihat tool berjalan persis seperti terminal asli, tanpa refresh.
3. **Unified Vulnerability Parser** — enam format output yang berbeda dinormalisasi menjadi satu skema database: judul, tingkat keparahan (critical–info), URL, parameter, CWE/CVE/CVSS, deskripsi, remediasi, evidence — bisa diekspor JSON.
4. **Sandbox isolasi berlapis** — jaringan Docker terpisah (tool tidak bisa menyentuh database/API), non-root UID acak per scan, `CAP_DROP ALL`, limit RAM/PID, timeout otomatis, pembatalan instan.
5. **Auth tanpa password (email + OTP + username unik)** — kode 6 digit dikirim via SMTP (default: MailPit lokal) dan disimpan sebagai hash. Email yang belum terdaftar tetap harus memilih **username unik** setelah OTP tervalidasi (email tidak pernah tampil sebagai identitas). Autentikasi ini murni untuk **melacak aktivitas**: total scan semua user, per user, dan per tool.
6. **Leaderboard** — peringkat pengguna berdasarkan total scan, ditampilkan dengan **username** (bukan email), lengkap dengan penanda baris "you".
7. **Dashboard & monitoring** — statistik agregat, riwayat scan berfilter, halaman kesehatan sistem (Prometheus + cAdvisor: CPU/RAM per kontainer, status antrean).

---

## Arsitektur

<img width="1357" height="672" alt="HydraSec drawio (1)" src="https://github.com/user-attachments/assets/c09d3094-2be4-46b2-a705-5f439b2b67e6" />


---

## Persyaratan

- **Docker Desktop** (Windows/macOS) atau Docker Engine + Compose v2 di Linux; backend WSL2 untuk Windows.
- Port bebas: `8080` (aplikasi), `8025` (MailPit).
- Koneksi internet saat **build image** pertama kali (mengunduh binary tool & template nuclei).

## Menjalankan

**Cara cepat (satu perintah) di mesin baru:**

```bash
bash setup.sh     # build tool + seluruh stack + jalankan (butuh Docker Desktop + internet)
```

**Atau manual, langkah per langkah:**

```bash
# 0) siapkan konfigurasi (opsional — compose punya default untuk semua variabel)
cp .env.example .env          # ubah JWT_SECRET untuk keamanan

# 1) build keenam image tool (sekali saja; perlu internet)
bash tools/build-all.sh

# 2) angkat seluruh stack (semua image bisa juga di-build dari Docker Desktop GUI)
docker compose up -d --build

# 3) buka aplikasi
#    Web app  : http://localhost:8080
#    Inbox OTP: http://localhost:8025  (MailPit)
```

> Catatan Windows: Docker Desktop yang terpasang per-user ada di
> `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin` — masukkan ke PATH bila CLI `docker` tidak dikenali.

### Alur penggunaan

1. Buka `http://localhost:8080` → masukkan email → **Send code**.
2. Ambil kode 6 digit dari inbox MailPit (`http://localhost:8025`) → **Verify code**.
3. **Email belum terdaftar?** Setelah kode tervalidasi kamu diminta memilih **username unik** (3–24 karakter; dicek ketersediaannya; tidak boleh duplikat dengan user lain) → **Finish registration**. Email terdaftar langsung masuk tanpa langkah ini. Username-lah yang tampil di leaderboard.
3. **New Scan** → pilih tool → isi alamat website Anda → **Start scan**.
4. Pantau proses di terminal xterm.js; setelah selesai, tabel **Findings** menampilkan seluruh temuan ter-normalisasi (bisa di-filter per tingkat keparahan, atau diekspor JSON).
5. **Dashboard** menampilkan total scan semua user, per user, dan per tool; **History** menyimpan riwayat; **System** memantau kesehatan kontainer.

### Mengirim OTP ke email sungguhan (opsional)

Default-nya OTP terbaca di MailPit lokal (tanpa internet, tanpa akun). Agar OTP terkirim ke email asli penerima (email apa pun yang diinput user — penerima selalu dinamis, bukan hardcode), set SMTP di `.env`:

```env
# contoh Gmail (wajib App Password: myaccount.google.com/apppasswords)
SMTP_URL=smtp://emailkamu@gmail.com:apppassword16karakter@smtp.gmail.com:587
MAIL_FROM=HydraSec <emailkamu@gmail.com>
```

lalu `docker compose up -d --force-recreate backend-api`. Perlindungan anti-penyalahgunaan sudah aktif: cooldown 60 detik per email, rate limit 10 permintaan/menit per IP, maksimal 5 percobaan verifikasi.

### Target lab privat (DVWA/localhost)

Secara default `ALLOW_PRIVATE_TARGETS=false` — localhost/loopback/alamat privat **ditolak**. Untuk memindai lab lokal sendiri (mis. DVWA di `192.168.x.x`), set `ALLOW_PRIVATE_TARGETS=true` di `.env` lalu recreate stack.

---

## Struktur proyek

```
HydraSec/
├── docker-compose.yml        # 9 service: gateway, frontend, backend, worker,
│                             # redis, postgres, mailpit, prometheus, cadvisor
├── .env.example              # konfigurasi (port, JWT, SMTP, konkurensi, guard)
├── db/init.sql               # skema: users, scans, vulnerabilities, otps
├── nginx/nginx.conf          # reverse proxy + terminasi WebSocket + /prometheus
├── prometheus/prometheus.yml # scrape backend, worker, cadvisor
├── backend/                  # API: auth OTP, scans, stats, health, metrics, WS
│   └── src/ (Express + ws + BullMQ producer + pg + nodemailer outbox)
├── worker/                   # Engine: BullMQ consumer (concurrency 2), dockerode,
│   └── src/                  # streaming log, unified parser, pembatalan, sweep
│       └── parsers/          # nmap(XML) nuclei(JSONL) xray(JSON) ffuf(JSON)
│                             # sqlmap(log) xsstrike(konsol)
├── frontend/                 # React 18 + Vite + xterm.js (login OTP, dashboard,
│   └── src/pages/            #  scan baru, terminal streaming, riwayat, system)
├── tools/                    # 1 folder Dockerfile per tool + build-all.sh
│   ├── nmap/ nuclei/ xsstrike/ xray/ sqlmap/ ffuf/
│   └── ffuf/wordlists/common.txt   # wordlist discovery (4749 entri)
└── design/taste-skill/       # acuan design system frontend
```

## Referensi API (ringkas)

| Endpoint | Keterangan |
|---|---|
| `POST /api/auth/request-otp` `{email}` | minta kode OTP (penerima dinamis sesuai input user) |
| `POST /api/auth/verify` `{email, code}` | email terdaftar → login `{token, user}`; email baru → `{pending, regToken}` (lanjut pilih username) |
| `POST /api/auth/complete` `{username}` | finalisasi pendaftaran dengan username unik (Bearer regToken) → `{token, user}` |
| `GET /api/auth/username-available?u=` | cek ketersediaan username (publik, rate-limited) |
| `GET /api/me` | profil user login |
| `GET /api/scans/tools` | katalog tool + opsi yang diizinkan |
| `POST /api/scans` `{tool, target, options?}` | validasi → enqueue → `{scan}` |
| `GET /api/scans?tool=&status=&page=` | riwayat (milik sendiri) |
| `GET /api/scans/:id` | detail + findings |
| `POST /api/scans/:id/cancel` | batalkan (queued dihapus dari antrean; running di-kill) |
| `GET /api/scans/:id/export` | unduh temuan JSON (`hydrasec.unified.v1`) |
| `GET /api/stats` | statistik global (semua user) + per user + **leaderboard per username** + per severity |
| `GET /api/health` | status layanan + antrean + target prometheus |
| `WS /ws?token=` → `{type:"subscribe", scanId}` | stream `{log}` & `{status}` live |

## Keamanan Implementasi (ringkas)

- **SSRF guard**: hanya `http/https`; hostname di-resolve lalu diperiksa terhadap rentang loopback/private/link-local/reserved (ipaddr.js + DNS); opsi per-tool berupa whitelist ketat; argumen tool dikirim sebagai **array Docker** (tanpa shell) — command injection mustahil.
- **SQL**: semua query memakai literal SQL statis + parameter binding.
- **XML**: parser nmap memakai fast-xml-parser (tanpa dukungan DTD/external entity).
- **Redis**: tidak ada data user dalam key (suffix kanal berupa UUID server-side).
- **OTP**: disimpan sebagai hash SHA-256 dengan kedaluwarsa & batas percobaan; pengiriman asinkron via outbox Redis (retry 3×).
- Headers keamanan, rate limit auth per-IP, JWT minimal-claim (hanya `sub`).

## Atribusi & Lisensi Tool

| Tool | Sumber |
|---|---|
| nmap | paket resmi Alpine Linux |
| nuclei (free) | projectdiscovery/nuclei + nuclei-templates resmi |
| xray | chaitin/xray — **integrasi ini mencantumkan atribusi: [github.com/chaitin/xray](https://github.com/chaitin/xray)**, sesuai ketentuan License.md, dan menyetujui Disclaimer.md mereka |
| XSStrike | s0md3v/XSStrike |
| sqlmap | sqlmapproject/sqlmap |
| ffuf | ffuf/ffuf |

Semua tool adalah karya komunitas yang dijalankan apa adanya di dalam kontainer terisolasi; HydraSec tidak memodifikasi kode tool tersebut.

## Pemecahan masalah

| Gejala | Penyebab & solusi |
|---|---|
| `Image hydrasec/tool-x tidak ditemukan` | jalankan `bash tools/build-all.sh` dahulu |
| OTP tidak sampai | buka `http://localhost:8025`; untuk email sungguhan set `SMTP_URL` (bagian di atas) |
| Build tool gagal mengunduh binary | butuh internet; cek proxy/bandwidth lalu build ulang tool terkait |
| Terminal tidak mengalir | pastikan seluruh service up; cek `docker compose logs backend-api worker` |
| Target ditolak | guard SSRF aktif — gunakan website milik sendiri, atau `ALLOW_PRIVATE_TARGETS=true` untuk lab lokal |
| Prometheus kosong | tunggu ±1 menit scrape pertama; cek `/prometheus/targets` |
| Template nuclei mau di-update | template ter-bake di image dan menetap di volume `hydrasec_nuclei_templates`. Update tanpa rebuild: `docker run --rm -u 10000 -e HOME=/home/scanner -v hydrasec_nuclei_templates:/home/scanner/nuclei-templates hydrasec/tool-nuclei -ut -silent` |
| `docker` tidak dikenali di Windows | tambahkan `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin` ke PATH |

**Deklarasi Penggunaan AI**

Dalam pengerjaan proyek ini, saya menggunakan bantuan AI coding assistant (ZCode, yait model GLM 5.3) secara intensif pada tahap pengembangan. Deklarasi ini saya tulis dengan jujur demi integritas akademik.

Peran AI dalam proyek ini:
- Menyusun kerangka kode awal untuk backend (Node.js/Express), worker engine (BullMQ + Dockerode), frontend (ReactJS + xterm.js), konfigurasi Docker Compose, Nginx, dan Prometheus, serta Dockerfile keenam tool pengujian.
- Membantu diagnosa dan perbaikan sejumlah bug runtime, di antaranya: penamaan paket/tag release tool, perbandingan hash kode OTP, penanganan async pada validator input, pembacaan struktur XML nmap, serta izin baca/tulis direktori di dalam kontainer non-root.
- Menerapkan praktik keamanan yang direkomendasikan: seluruh query SQL memakai parameter binding, guard SSRF dengan resolusi DNS dan penolakan alamat privat/loopback, kode OTP disimpan sebagai hash SHA-256, dan isolasi kontainer tool (non-root, capability drop, jaringan terpisah).
- Menyusun draft README berdasarkan arsitektur yang telah dirancang oleh saya.

Peran saya :
- Menentukan ide dan konsep aplikasi untuk menyelesaikan permasalahan di masyarakat dalam ranah digital
- Menentukan keseluruhan kebutuhan aplikasi, konsep arsitektur aplikasi, pemilihan keenam tools penetration testing, serta seluruh keputusan fitur aplikasi(autentikasi OTP tanpa password, username unik untuk leaderboard, antrean dengan kendali konkurensi, dsb.).
- Menjalankan seluruh verifikasi secara mandiri: build image, scanning ke target yang legal untuk pengujian tools, pengujian alur OTP menggunakan mailpit dan username unik, serta pengujian keenam tool satu per satu hingga berfungsi.
- Merekam video demo dan melakukan operasi Git/GitHub.
