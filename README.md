Log Normalizer
Çoklu log formatlarını standart bir JSON/CSV formatına dönüştüren Python aracı. Apache, Nginx, Windows Event Log, Syslog, IIS ve daha fazlasını destekler.

Özellikler
Çoklu Format Desteği: Apache Access/Error, Nginx, Windows Event Log, Syslog, IIS, JSON
Otomatik Format Algılama: Log formatını otomatik tanır
Sistem Log Tarama: Bilinen log dizinlerini otomatik tarar
Windows Event Log: PowerShell ile Windows sistem olaylarını çeker
Encoding Desteği: Türkçe karakter ve farklı encoding'leri destekler
Esnek Çıktı: JSON veya CSV formatında kayıt

Gereksinimler
Python 3.8+ (tavsiye: 3.10 veya üstü)


🚀 Usage (Kullanım)

Komut formatı
Linux Kullanımı: python3 log_normalizerr.py --scan -o kali_all_logs.json
Windows : python log_normalizerr.py --scan-windows-events -o events.json 






