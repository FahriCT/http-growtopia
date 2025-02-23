## Growtopia DDoS Protection with IP Limiter

Projek ini adalah sebuah server HTTP/HTTPS yang dilengkapi dengan sistem proteksi DDoS dan IP limiter. Server ini dirancang untuk mendeteksi dan memblokir IP yang melakukan serangan DDoS secara otomatis. Selain itu, server ini juga memiliki fitur untuk membatasi jumlah request per detik dari setiap IP, sehingga dapat mencegah serangan brute force atau flooding.
Projek ini cocok digunakan untuk melindungi server  dari serangan DDoS dan traffic yang tidak diinginkan. Dengan konfigurasi yang fleksibel, Anda dapat menyesuaikan batasan request, durasi pemblokiran, dan memilih apakah IP yang terdeteksi melakukan DDoS akan diblokir sementara atau permanen.

# Fitur Utama
-🛡️ Proteksi DDoS Otomatis**: Mendeteksi dan memblokir IP yang melakukan serangan DDoS berdasarkan jumlah request per detik.
-📊 IP Limiter**: Membatasi jumlah request per detik dari setiap IP untuk mencegah serangan flooding.
-🔒 Pemblokiran IP Permanen**: Opsi untuk memblokir IP secara permanen menggunakan `netsh` (Windows) atau `iptables` (Linux).
-📝 Logging**: Mencatat aktivitas server dan IP yang diblokir menggunakan `winston` untuk memudahkan monitoring.
-⚙️ Konfigurasi Fleksibel**: Konfigurasi batasan request, durasi pemblokiran, dan opsi pemblokiran permanen dapat disesuaikan melalui file `config.js`.

# 🎯 Catatan
- Pastikan Anda menjalankan server ini dengan hak akses **administrator** jika menggunakan fitur pemblokiran IP permanen.
- File SSL harus disiapkan terlebih dahulu untuk menjalankan server HTTPS.


