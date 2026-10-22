 PHP2SHELL (BUAT KANG SHELL)

Tool buat ngecek dan ngetes CVE-2026-109618 / CVE-2026-109619. Bug di PHP session.upload_progress yang bikin memori korup pas request di-abort di tengah.

Buat lab sama authorized testing. Kalo lo pake buat hal lain, itu tanggung jawab lo.

Isi

```
poc.py                  CLI
php2shell_core.py       low-level: socket, multipart, fingerprint
php2shell_exploit.py    orkestrasi: multi-path, variant, scoring
```

Requirement

Python 3.10+. Ga ada dependency luar. Semua stdlib.

Windows: warna ANSI otomatis lewat SetConsoleMode. Kalo ga keluar, pake --color.

Cek target

```bash
python poc.py check https://target.com/index.php
python poc.py check -f targets.txt -o out.jsonl --workers 16
```

Cuma GET. Baca X-Powered-By sama Server, parse versi PHP, bandingin sama fix version.

Exit code: 0 aman, 1 unreachable, 2 likely_vulnerable.

Kalo hasilnya branch_only, versi PHP-nya EOL dan ga ada patch resmi. Tetep exposed, tapi lo ga bisa nge-claim "upgrade ke versi X" karena versi X-nya ga ada.

Trigger 618

```bash
python poc.py exploit https://target.com/ --chain 618
```

Kirim multipart dua fase. Fase pertama dikirim, diem bentar, fase kedua dikirim. Tujuannya bikin PHP kehabisan memori di tengah parsing.

Default smart mode: coba beberapa path (/index.php, /, /wp-login.php, /wp-admin/admin-ajax.php) dan variant (stall, micro, inject). Yang skornya tinggi dipake.

Satu path aja:

```bash
python poc.py exploit https://target.com/ --chain 618 --no-smart --rounds 5
```

Chain 619

Ini yang beneran eksekusi command. Butuh alamat zend_call_function atau zval_ptr_dtor yang valid dari target.

```bash
python poc.py exploit https://target.com/ --chain 619 --call 0x7f... --command "id"
```

DELTA_CALL_DEFAULT di core cuma cocok buat satu build Docker (php:8.4.26-cli). Bukan buat semua target. Kalo asal pake default, hasilnya cuma crashed=True. Bukan RCE.

Cara dapet offset: jalanin target di Docker, attach gdb, p zend_call_function sama p zval_ptr_dtor, selisihin.

Liat body tanpa nembak:

```bash
python poc.py exploit https://target.com/ --chain 619 --call 0x... --dry-run -o body.bin
```

LiteSpeed

Kalo header response ada litespeed atau lsphp, variant stall sama micro di-skip. Sisain inject. Alasannya: session.upload_progress di LiteSpeed/LSPHP sering dimatiin.

Paksa jalanin semua:

```bash
python poc.py exploit https://target.com/ --chain 618 --no-litespeed-skip
```

Field litespeed sama litespeed_skipped ada di output JSON.

Scoring

Status Skor Arti
rce_hit 100 expect ketemu di body
crash_signal 70 HTTP 0/502/503 atau body kosong
session_fixation 50 Set-Cookie echo PHPSESSID
upload_accepted 30 Multipart diterima
http_ok 10 Ada response tapi ga jelas

armed ga ada di scoring. Versi ini ga punya endpoint lab buat baca $_SESSION. Kalo field armed muncul di JSON, itu warisan, nilainya selalu False.

Yang perlu lo tau

crash_signal bukan RCE. Cuma tanda memori korup. Butuh heap grooming sama offset yang pas buat jadi RCE.

session_fixation primitif, bukan RCE. Tapi valid buat report.

upload_accepted lemah. Cuma berarti endpoint nerima POST multipart. Jangan klaim vulnerable.

Fix versions

Branch Fix
8.2 8.2.35
8.3 8.3.36
8.4 8.4.27
8.5 8.5.12

8.0 sama 8.1 EOL. Ga ada patch resmi.

Mitigasi sementara: session.upload_progress.enabled = Off di php.ini.

Tested on

Docker php:8.4.26-apache (vulnerable), php:8.4.27-apache (patched), beberapa lab HTB/THM PHP 8.x.

Ga dites di production, Windows server, PHP 5.x/7.x.

Author

053o. Bug atau mau nambah variant/path, PR aja.