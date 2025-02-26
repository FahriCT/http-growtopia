# Growtopia DDoS Protection with IP Limiter

Proyek ini adalah sebuah server HTTP/HTTPS yang dilengkapi dengan sistem proteksi DDoS dan IP limiter. Server ini dirancang untuk mendeteksi dan memblokir IP yang melakukan serangan DDoS secara otomatis berdasarkan jumlah request per detik. Proyek ini cocok digunakan untuk melindungi server dari serangan DDoS dan traffic yang tidak diinginkan.


## Instalasi
1. Donwload File & Extract
2. Masuk ke direktori proyek
3. Install dependensi:
    ```bash
    npm install
    ```

## Penggunaan
1. Sesuaikan konfigurasi di `config.json`.
2. Jalankan server:
    ```bash
    node index.js
    ```

## Catatan
- Pastikan Anda menjalankan server ini dengan hak akses **administrator** jika menggunakan fitur pemblokiran IP.
- Projek ini masih dalam uji coba

## Kontribusi
Kami menerima kontribusi dari siapa saja. Silakan fork repositori ini dan buat pull request untuk perbaikan atau penambahan fitur.

## Lisensi
Proyek ini dilisensikan di bawah [MIT License](LICENSE.md).
