# Growtopia DDoS Protection with IP Limiter

Proyek ini adalah sebuah server HTTP/HTTPS yang dilengkapi dengan sistem proteksi DDoS dan IP limiter. Server ini dirancang untuk mendeteksi dan memblokir IP yang melakukan serangan DDoS secara otomatis berdasarkan jumlah request per detik. Proyek ini cocok digunakan untuk melindungi server dari serangan DDoS dan traffic yang tidak diinginkan. Dengan konfigurasi yang fleksibel, Anda dapat menyesuaikan batasan request, durasi pemblokiran, dan opsi pemblokiran permanen melalui file `config.js`.

## Fitur Utama
1. 🛡️ **Proteksi DDoS Otomatis**: Mendeteksi dan memblokir IP yang melakukan serangan DDoS berdasarkan jumlah request per detik.
2. 📊 **IP Limiter**: Membatasi jumlah request per detik dari setiap IP untuk mencegah serangan flooding.
3. 🔒 **Pemblokiran IP Permanen**: Opsi untuk memblokir IP secara permanen menggunakan `netsh` (Windows) atau `iptables` (Linux).
4. 📝 **Logging**: Mencatat aktivitas server dan IP yang diblokir menggunakan `winston` untuk memudahkan monitoring.
5. ⚙️ **Konfigurasi Fleksibel**: Konfigurasi batasan request, durasi pemblokiran, dan opsi pemblokiran permanen dapat disesuaikan melalui file `config.js`.

## Persyaratan
- Node.js
- Hak akses administrator (untuk fitur pemblokiran IP permanen)
- File SSL (untuk menjalankan server HTTPS)

## Instalasi
1. Clone repositori ini:
    ```bash
    git clone https://github.com/FahriCT/gt.git
    ```
2. Masuk ke direktori proyek:
    ```bash
    cd gt
    ```
3. Install dependensi:
    ```bash
    npm install
    ```

## Penggunaan
1. Sesuaikan konfigurasi di `config.js` sesuai kebutuhan Anda.
2. Jalankan server:
    ```bash
    node server.js
    ```

## Catatan
- Pastikan Anda menjalankan server ini dengan hak akses **administrator** jika menggunakan fitur pemblokiran IP permanen.
- File SSL harus disiapkan terlebih dahulu untuk menjalankan server HTTPS.

## Kontribusi
Kami menerima kontribusi dari siapa saja. Silakan fork repositori ini dan buat pull request untuk perbaikan atau penambahan fitur.

## Lisensi
Proyek ini dilisensikan di bawah [MIT License](LICENSE).
