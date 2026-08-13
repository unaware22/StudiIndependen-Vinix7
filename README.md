# Analisis Threat Modeling STRIDE pada Infrastruktur Kubernetes

Repositori ini berisi hasil analisis dan simulasi keamanan pada cluster Kubernetes (K3s) menggunakan metodologi **STRIDE** (*Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege*). Penelitian ini berfokus pada dua skenario serangan utama—**HostPath Attack** dan **CPU Resource Exhaustion**—serta langkah-langkah mitigasinya.

---

## Arsitektur Target & Aset Kritis

### 1. Spesifikasi Cluster K3s
* **Control Plane**: Ubuntu Server (`v1.35.5+k3s1`)
* **Worker Node**: Kali Linux (`v1.35.5+k3s1`)
* **Aplikasi Target**: OWASP Juice Shop

### 2. Aset yang Dilindungi
* File kredensial sistem host (`/etc/shadow`, `/etc/passwd`)
* Akses remote SSH (`~/.ssh/authorized_keys`)
* Sumber daya komputasi node (CPU & Memori)
* Layanan web OWASP Juice Shop
* Catatan aktivitas sistem (*System & Audit Logs*)

---

## Skenario 1: HostPath Attack
Ancaman: *Information Disclosure*, *Tampering*, dan *Elevation of Privilege*

Pada skenario ini, pod jahat dikonfigurasi menggunakan volume `hostPath` yang mengarah langsung ke direktori sensitif host (`/etc`, `/var`, `/home`).

### Alur Serangan (Data Flow Diagram)
![Gambar 4.1 - Data Flow Diagram Skenario HostPath Attack](https://github.com/user-attachments/assets/50b990a9-d18b-46bc-8d74-a75802e2ffa3)
Penjelasan gambar diatas: DFD menunjukkan alur penyerang membuat malicious pod yang melakukan mounting direktori host, membaca kredensial `/etc/shadow`, meng-eksfiltrasi data, menyisipkan public key ke file `authorized_keys` host, hingga mendapatkan akses persisten via SSH.

### Tahapan Akses & Eksfiltrasi Data
![Gambar 4.2 - Konfigurasi Pod Manifest](https://github.com/user-attachments/assets/6e640b7b-3ed7-48ec-88f6-7fad1e42ad8e)
Penjelasan gambar diatas: Manifes YAML pod `skenario1` berbasis `alpine:latest` dengan mount `hostPath` ke direktori host `/etc`, `/var`, dan `/home`.

![Gambar 4.3 - Akses Shell dan File Shadow](<img width="512" height="121" alt="image" src="https://github.com/user-attachments/assets/c7c4abce-33ca-4e4d-8667-e61ca228b5e5" />)
Penjelasan gambar diatas: Penyerang menggunakan perintah `kubectl exec` untuk masuk ke shell pod dan membaca isi file sensitif `/etc/shadow` host.

![Gambar 4.4 - Pembukaan Port Listener](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Penyerang membuka listener jaringan dengan `nc -lvnp 4444` pada mesin Kali Linux untuk menerima data curian.

![Gambar 4.5 - Hasil Eksfiltrasi Data Kredensial](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Data hash password dari file `/etc/shadow` berhasil dikirim dari pod ke mesin Kali Linux.

### Tahapan Injeksi Kunci SSH & Akses Persisten
![Gambar 4.6 - Generasi SSH Key Pair dan Status Jaringan](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Penyerang membuat sepasang kunci SSH baru (`exploit_key` & `exploit_key.pub`) menggunakan perintah `ssh-keygen`.

![Gambar 4.7 - Injeksi Kunci Authorized_Keys](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Penyerang menyisipkan isi `exploit_key.pub` ke direktori `~/.ssh/authorized_keys` milik user host melalui mount point `/mnt/host-home`.

![Gambar 4.8 - Keberhasilan Login Pertama](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Penyerang berhasil melakukan login remote SSH langsung ke server host tanpa password.

![Gambar 4.9 - Pembersihan Skenario dan Namespace](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Penyerang menghapus pod dan namespace `security-audit-lab` untuk menghilangkan jejak aktivitas di Kubernetes.

![Gambar 4.10 - Akses Persisten Pasca Penghapusan](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Penyerang terbukti masih bisa mengakses host via SSH meskipun pod dan namespace pendukung di Kubernetes sudah dihapus.

---

## Skenario 2: CPU Resource Exhaustion Attack
Ancaman: *Denial of Service* (DoS) dan *Repudiation*

Skenario ini mensimulasikan pod jahat yang mengonsumsi seluruh daya komputasi CPU pada node karena tidak dilindungi oleh pembatasan kuota (*resource limit*).

### Alur Serangan (Data Flow Diagram)
![Gambar 4.11 - Data Flow Diagram Skenario CPU Exhaustion](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: DFD menggambarkan alur serangan DoS. Pod jahat mengeksekusi proses pembakaran CPU yang membuat penggunaan CPU melonjak hingga 90%, mengganggu layanan aplikasi lain, serta menunjukkan celah repudiation akibat minimnya audit log.

### Tahapan Serangan DoS
![Gambar 4.12 - Pemicu Eksploitasi DoS](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: File `attacker-pod.yaml` berisi skrip infinite loop `yes > /dev/null` tanpa batasan `resources.limits.cpu`.

![Gambar 4.13 - Penerapan Pod DoS](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Eksekusi deployment pod pembakar CPU ke namespace `dos-lab`.

![Gambar 4.14 - Sebelum Pod diterapkan ke Namespace (CPU 2%)](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Perintah `kubectl top nodes` menunjukkan penggunaan CPU node secara normal berada pada tingkat 2%.

![Gambar 4.15 - Setelah Pod diterapkan ke Namespace (CPU dari 2% menjadi 90%)](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Penggunaan CPU Control Plane melonjak drastis hingga 90% setelah pod DoS berjalan.

![Gambar 4.16 - Visualisasi Dampak Layanan Website](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Aplikasi web OWASP Juice Shop mengalami penundaan akses yang signifikan (response time hingga ~139 detik).

### Investigasi Repudiation (Ancaman Akuntabilitas)
![Gambar 4.17 - Tidak ada keunikan pada ServiceAccount](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Pod DoS menggunakan `ServiceAccount: default`, sehingga pembuat pod tidak dapat dipastikan.

![Gambar 4.18 - Tidak ada Label Identitas pada Pod](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Pod DoS tidak memiliki label identitas pengenal seperti `created-by`.

![Gambar 4.19 - Kegagalan Pelacakan Log Audit](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Pemeriksaan `journalctl` tidak menampilkan jejak pembuatan pod karena fitur audit logging K3s dalam kondisi non-aktif.

---

## Implementasi Mitigasi

### 1. Pod Security Admission (PSA)
PSA digunakan untuk menegakkan standar keamanan pod pada tingkat namespace.

![Gambar 4.20 - Aktivasi Penegakan Labeling PSA](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Pemberian label `pod-security.kubernetes.io/enforce=baseline` pada namespace target.

![Gambar 4.21 - Verifikasi Label PSA pada Namespace](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Verifikasi daftar namespace yang mengonfirmasi bahwa label baseline telah terpasang.

![Gambar 4.22 - Manifes Pengujian pada Namespace Terproteksi](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: PSA berhasil menolak (*forbidden*) deployment pod yang mencoba menggunakan volume `hostPath`.

### 2. Open Policy Agent (OPA) Gatekeeper
Gatekeeper memberikan kontrol *Policy as Code* berbasis bahasa Rego untuk memblokir penggunaan `hostPath`.

![Gambar 4.23 - Verifikasi Komponen Pods Gatekeeper](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Status pod sistem Gatekeeper di namespace `gatekeeper-system` berjalan normal.

![Gambar 4.24 - Membuat File ConstraintTemplate](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Konfigurasi Rego pada `template-hostpath.yaml` yang mendeteksi penggunaan volume `hostPath`.

![Gambar 4.25 - Menerapkan aturan ke cluster](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Menerapkan `ConstraintTemplate` ke dalam cluster.

![Gambar 4.26 - Membuat File Constraint](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Konfigurasi `constraint-hostpath.yaml` yang menentukan objek mana saja yang wajib diperiksa.

![Gambar 4.27 - Penerapan File Constraint ke cluster](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Menerapkan aturan `no-hostpath-volumes` ke dalam cluster.

![Gambar 4.28 - Validasi Kebijakan Pemblokiran HostPath](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Pengujian ulang pengiriman manifes pod `hostPath`.

![Gambar 4.29 - Blocking Webhook Gatekeeper](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Webhook Gatekeeper berhasil memblokir secara langsung pod yang mencoba mengakses direktori `/etc`, `/var`, dan `/home`.

### 3. LimitRange (Mitigasi CPU Exhaustion)
LimitRange membatasi penggunaan maksimal sumber daya CPU dan memori per kontainer pada suatu namespace.

![Gambar 4.30 - Struktur Kebijakan Kontrol Sumber Daya (LimitRange)](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: File `limitrange.yaml` menetapkan batas atas CPU sebesar `500m` (0.5 core) dan memori `256Mi`.

![Gambar 4.31 - Annotations pada Pod Menunjukkan Intervensi LimitRange](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Tampilan `kubectl describe pod` yang menunjukkan intervensi otomatis dari plugin `LimitRanger` menyuntikkan batasan sumber daya pada pod.

![Gambar 4.32 - Stabilisasi Pasca Mitigasi (CPU turun menjadi 16%)](LINK_GAMBAR_DISINI)
Penjelasan gambar diatas: Penggunaan CPU Control Plane berhasil diturunkan secara drastis dari 90% menjadi 16%, menjaga ketersediaan layanan cluster.

---

## Matriks Risiko (STRIDE)

| Kategori STRIDE | Ancaman yang Ditemukan | Skenario | Tingkat Keparahan (*Severity*) |
|---|---|---|---|
| **Spoofing** | Penyerang menyamar sebagai user `ubuntu` via SSH Key | Skenario 1 | Low |
| **Tampering** | Modifikasi file host (`authorized_keys`) | Skenario 1 | High |
| **Repudiation** | Pelaku tidak teridentifikasi karena audit log mati | Skenario 2 | Medium |
| **Information Disclosure** | Membaca & mengeksfiltrasi file `/etc/shadow` | Skenario 1 | High |
| **Denial of Service** | Lonjakan CPU hingga 90% memicu kelumpuhan layanan | Skenario 2 | High |
| **Elevation of Privilege** | Remote shell SSH persisten ke host luar | Skenario 1 | Critical |

---

## Kesimpulan Mitigasi
1. **PSA Baseline**: Efektif menolak pod dengan `hostPath` sebelum dijalankan.
2. **OPA Gatekeeper**: Memberikan kontrol kebijakan kustom yang lebih terperinci untuk mencegah akses sistem file host.
3. **LimitRange**: Efektif menstabilkan penggunaan CPU dari 90% menjadi 16%, mencegah timbulnya *Resource Starvation* dan gangguan ketersediaan (*Denial of Service*).
