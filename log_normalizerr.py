#!/usr/bin/env python3
"""
Log Normalization Script
Farkli log formatlarini standart bir formata donusturur.
Windows Event Log, Apache, Nginx, JSON, Syslog, IIS ve daha fazlasini destekler!
Otomatik sistem log taramasi ile!
"""

import re
import json
import csv
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import argparse
import os
import sys
import subprocess
import xml.etree.ElementTree as ET

# Ek bağımlılıklar
try:
    from dateutil import parser as date_parser
except ImportError:
    print("❌ 'python-dateutil' paketi gerekli. Kurmak için: pip install python-dateutil")
    sys.exit(1)

try:
    import chardet
except ImportError:
    print("❌ 'chardet' paketi gerekli. Kurmak için: pip install chardet")
    sys.exit(1)


@dataclass
class NormalizedLog:
    """Normalleştirilmiş log kaydı için standart format"""
    timestamp: str
    level: str
    source: str
    message: str
    host: Optional[str] = None
    user: Optional[str] = None
    ip: Optional[str] = None
    extra_fields: Optional[Dict[str, Any]] = None


class LogNormalizer:
    """Ana log normalizer sinifi"""
    
    def __init__(self):
        self.patterns = {
            'apache_access': re.compile(
                r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]*)" (?P<status>\d+) (?P<size>\S+)'
            ),
            'apache_error': re.compile(
                r'\[(?P<timestamp>[^\]]+)\] \[(?P<level>\w+)\] \[pid (?P<pid>\d+)\] (?P<message>.*)'
            ),
            'nginx_access': re.compile(
                r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]*)" (?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
            ),
            'syslog': re.compile(
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<host>\S+) (?P<process>\S+)(\[(?P<pid>\d+)\])?: (?P<message>.*)'
            ),
            'windows_event': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>\w+) (?P<source>\S+) (?P<event_id>\d+) (?P<message>.*)'
            ),
            'app_log': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.,]\d{3}) \[(?P<level>\w+)\] (?P<logger>\S+) - (?P<message>.*)'
            ),
            'json_log': re.compile(r'^\s*\{.*\}\s*$'),
            'iis_log': re.compile(
                r'(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<s_ip>\S+) (?P<method>\S+) (?P<uri_stem>\S+) (?P<uri_query>\S+) (?P<s_port>\d+) (?P<username>\S+) (?P<c_ip>\S+) (?P<user_agent>[^"]*) (?P<status>\d+)'
            )
        }
        
        self.level_mapping = {
            'ERROR': 'ERROR', 'WARN': 'WARNING', 'WARNING': 'WARNING', 'INFO': 'INFO',
            'DEBUG': 'DEBUG', 'TRACE': 'DEBUG', 'FATAL': 'CRITICAL', 'CRITICAL': 'CRITICAL',
            'EMERGENCY': 'CRITICAL', 'ALERT': 'CRITICAL', 'CRIT': 'CRITICAL', 'ERR': 'ERROR',
            'NOTICE': 'INFO'
        }

        self.default_log_paths = self._get_default_log_paths()

    def _get_default_log_paths(self) -> List[str]:
        paths = []
        if sys.platform == "win32":
            paths = [
                os.path.expandvars(r"%ProgramData%\Apache\logs"),
                os.path.expandvars(r"C:\Apache24\logs"),
                os.path.expandvars(r"C:\nginx\logs"),
                r"C:\inetpub\logs\LogFiles",
                os.path.expandvars(r"%ProgramData%\nginx\logs"),
                os.path.expandvars(r"C:\xampp\apache\logs"),
                os.path.expandvars(r"C:\wamp64\logs"),
            ]
        else:
            paths = [
                "/var/log",
                "/var/log/apache2",
                "/var/log/nginx",
                "/var/log/httpd",
                "/opt/tomcat/logs",
            ]
        return [p for p in paths if os.path.isdir(p)]

    def find_log_files(self, base_path: str = None) -> List[str]:
        log_files = set()
        search_paths = []

        if base_path:
            if os.path.isdir(base_path):
                search_paths = [base_path]
            else:
                logging.warning(f"Belirtilen yol bir dizin değil: {base_path}")
                return []
        else:
            # Sadece güvenli ve bilinen log dizinlerini tara
            search_paths = self.default_log_paths.copy()
            # Kullanıcı ev dizinindeki yaygın log klasörleri (daha güvenli)
            user_dirs = ["logs", "log", ".logs"]
            for d in user_dirs:
                p = os.path.join(os.path.expanduser("~"), d)
                if os.path.isdir(p):
                    search_paths.append(p)

        log_patterns = ["*.log", "*.txt"]
        for path in search_paths:
            try:
                path_obj = Path(path)
                for pattern in log_patterns:
                    for file in path_obj.rglob(pattern):
                        if file.is_file() and file.stat().st_size > 50:  # En az 50 byte
                            log_files.add(str(file.resolve()))
            except (OSError, PermissionError) as e:
                logging.debug(f"Dizin okunamadı: {path} - {e}")
                continue

        return sorted(list(log_files))

    def get_windows_event_logs(self, log_names=None, max_events=50):
        """Encoding sorunları düzeltilmiş Windows Event Log okuma"""
        if sys.platform != "win32":
            print("❌ Windows Event Log desteği sadece Windows'ta çalışır.")
            return []
        
        if log_names is None:
            log_names = ['Application', 'System']
        
        all_events = []
        
        for log_name in log_names:
            try:
                print(f"🔍 {log_name} log'u kontrol ediliyor...")
                
                # UTF-8 encoding ile PowerShell komutu
                ps_cmd = f'''
                [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                $Events = Get-WinEvent -LogName "{log_name}" -MaxEvents {max_events} -ErrorAction SilentlyContinue
                if ($Events) {{
                    $Events | Select-Object @{{n='TimeCreated';e={{$_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')}}}}, Id, LevelDisplayName, ProviderName, @{{n='Message';e={{if($_.Message){{$_.Message.Substring(0,[Math]::Min($_.Message.Length,200))}}else{{"Event ID: " + $_.Id}}}}}} | ConvertTo-Json -Depth 2
                }} else {{
                    Write-Output "[]"
                }}
                '''
                
                # Encoding'i açık olarak belirt
                result = subprocess.run(
                    ['powershell', '-Command', ps_cmd], 
                    capture_output=True, 
                    text=True, 
                    timeout=30,
                    encoding='utf-8',
                    errors='ignore'
                )
                
                if result.returncode == 0 and result.stdout and result.stdout.strip():
                    try:
                        stdout_clean = result.stdout.strip()
                        if not stdout_clean or stdout_clean == "[]":
                            print(f"⚠️ {log_name} boş veya erişilemiyor")
                            continue
                            
                        events = json.loads(stdout_clean)
                        if not isinstance(events, list):
                            events = [events]
                        
                        valid_events = []
                        for event in events:
                            if not event or not isinstance(event, dict):
                                continue
                                
                            # Güvenli string alma
                            message = str(event.get('Message', f"Event ID: {event.get('Id', 'N/A')}"))
                            if len(message) > 300:
                                message = message[:297] + "..."
                            
                            # Türkçe karakterleri temizle
                            message = message.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
                            message = message.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
                            
                            timestamp = event.get('TimeCreated')
                            if not timestamp:
                                timestamp = datetime.now().isoformat()
                            
                            level = str(event.get('LevelDisplayName', 'INFO')).upper()
                            
                            log_entry = NormalizedLog(
                                timestamp=timestamp,
                                level=level,
                                source=f"windows_{log_name.lower()}",
                                message=message,
                                extra_fields={
                                    'event_id': event.get('Id'), 
                                    'provider': event.get('ProviderName')
                                }
                            )
                            valid_events.append(log_entry)
                        
                        all_events.extend(valid_events)
                        print(f"✅ {len(valid_events)} event bulundu ({log_name})")
                        
                    except json.JSONDecodeError as e:
                        print(f"⚠️ {log_name} JSON parse hatası: {e}")
                        # Fallback - basit text parse
                        if "TimeCreated" in result.stdout:
                            lines = result.stdout.split('\n')
                            for line in lines:
                                if "TimeCreated" in line:
                                    fallback_log = NormalizedLog(
                                        timestamp=datetime.now().isoformat(),
                                        level='INFO',
                                        source=f"windows_{log_name.lower()}",
                                        message=f"Event from {log_name} (encoding issue)"
                                    )
                                    all_events.append(fallback_log)
                                    break
                else:
                    error_msg = result.stderr if result.stderr else "Bilinmeyen hata"
                    print(f"⚠️ {log_name} okunamadı: {error_msg}")
                    
            except subprocess.TimeoutExpired:
                print(f"⚠️ {log_name} timeout")
            except Exception as e:
                print(f"❌ {log_name} genel hatası: {e}")
        
        return all_events

    def _parse_windows_events_xml(self, xml_content: str, source_log: str):
        if not xml_content.strip():
            return []
        logs = []
        # XML bloklarını güvenli şekilde ayır
        events_raw = xml_content.strip().split('<?xml version=')
        for raw in events_raw:
            if '<Event' not in raw:
                continue
            # İlk <Event> bloğunu al
            start = raw.find('<Event')
            end = raw.find('</Event>') + len('</Event>')
            if start == -1 or end <= len('</Event>'):
                continue
            event_xml = raw[start:end]
            try:
                event_elem = ET.fromstring(event_xml)
                system = event_elem.find('System')
                data = event_elem.find('EventData')
                event_id = system.find('EventID').text if system is not None and system.find('EventID') is not None else 'N/A'
                level_code = system.find('Level').text if system is not None and system.find('Level') is not None else '4'
                time_created = system.find('TimeCreated').get('SystemTime') if system is not None and system.find('TimeCreated') is not None else None
                provider = system.find('Provider').get('Name') if system is not None and system.find('Provider') is not None else 'Unknown'
                computer = system.find('Computer').text if system is not None and system.find('Computer') is not None else None
                message_parts = []
                if data is not None:
                    for elem in data.findall('Data'):
                        if elem is not None and elem.text:
                            message_parts.append(elem.text)
                message = " | ".join(message_parts) if message_parts else f"Event ID: {event_id}"
                level_map = {'1': 'CRITICAL', '2': 'ERROR', '3': 'WARNING', '4': 'INFO', '5': 'DEBUG'}
                log_level = level_map.get(level_code, 'INFO')
                timestamp = self.normalize_timestamp(time_created) if time_created else datetime.now().isoformat()
                logs.append(NormalizedLog(
                    timestamp=timestamp,
                    level=log_level,
                    source=f"windows_event_{source_log}",
                    message=message,
                    host=computer,
                    extra_fields={'event_id': event_id, 'provider': provider, 'windows_level_code': level_code}
                ))
            except Exception as e:
                logging.debug(f"Event parse hatası: {e}")
                continue
        return logs

    def detect_format(self, line: str) -> str:
        line = line.strip()
        if not line:
            return 'unknown'
        if self.patterns['json_log'].match(line):
            try:
                json.loads(line)
                return 'json_log'
            except json.JSONDecodeError:
                pass
        for format_name, pattern in self.patterns.items():
            if format_name == 'json_log':
                continue
            if pattern.search(line):
                return format_name
        return 'unknown'

    def normalize_timestamp(self, timestamp_str: str) -> str:
        # Önce epoch timestamp kontrolü (milisaniye dahil)
        if timestamp_str.isdigit():
            ts = int(timestamp_str)
            if ts > 1e10:  # milisaniye
                ts = ts / 1000
            return datetime.fromtimestamp(ts).isoformat()
        try:
            # dateutil ile esnek parse
            dt = date_parser.parse(timestamp_str, fuzzy=True)
            return dt.isoformat()
        except (ValueError, TypeError, OverflowError):
            return datetime.now().isoformat()

    def normalize_level(self, level: str) -> str:
        if not level:
            return 'INFO'
        level_upper = level.upper()
        return self.level_mapping.get(level_upper, level_upper)

    def parse_apache_access(self, line: str, match) -> NormalizedLog:
        groups = match.groupdict()
        timestamp = self.normalize_timestamp(groups['timestamp'])
        message = f"{groups['method']} {groups['url']} {groups['protocol']} - Status: {groups['status']}, Size: {groups['size']}"
        return NormalizedLog(
            timestamp=timestamp,
            level='INFO',
            source='apache_access',
            message=message,
            ip=groups['ip'],
            extra_fields={'method': groups['method'], 'url': groups['url'], 'status': int(groups['status']), 'size': groups['size']}
        )

    def parse_apache_error(self, line: str, match) -> NormalizedLog:
        groups = match.groupdict()
        timestamp = self.normalize_timestamp(groups['timestamp'])
        level = self.normalize_level(groups['level'])
        return NormalizedLog(
            timestamp=timestamp,
            level=level,
            source='apache_error',
            message=groups['message'],
            extra_fields={'pid': int(groups['pid'])}
        )

    def parse_nginx_access(self, line: str, match) -> NormalizedLog:
        groups = match.groupdict()
        timestamp = self.normalize_timestamp(groups['timestamp'])
        message = f"{groups['method']} {groups['url']} - Status: {groups['status']}, Size: {groups['size']}"
        return NormalizedLog(
            timestamp=timestamp,
            level='INFO',
            source='nginx_access',
            message=message,
            ip=groups['ip'],
            user=groups['user'] if groups['user'] != '-' else None,
            extra_fields={
                'method': groups['method'], 'url': groups['url'], 'status': int(groups['status']),
                'size': int(groups['size']), 'referer': groups['referer'], 'user_agent': groups['user_agent']
            }
        )

    def parse_syslog(self, line: str, match) -> NormalizedLog:
        groups = match.groupdict()
        timestamp = self.normalize_timestamp(groups['timestamp'])
        return NormalizedLog(
            timestamp=timestamp,
            level='INFO',
            source='syslog',
            message=groups['message'],
            host=groups['host'],
            extra_fields={'process': groups['process'], 'pid': int(groups['pid']) if groups['pid'] else None}
        )

    def parse_iis_log(self, line: str, match) -> NormalizedLog:
        groups = match.groupdict()
        timestamp = self.normalize_timestamp(f"{groups['date']} {groups['time']}")
        message = f"{groups['method']} {groups['uri_stem']} - Status: {groups['status']}"
        return NormalizedLog(
            timestamp=timestamp,
            level='INFO',
            source='iis_log',
            message=message,
            ip=groups['c_ip'],
            user=groups['username'] if groups['username'] != '-' else None,
            extra_fields={k: v for k, v in groups.items() if k not in ('date', 'time', 'c_ip', 'username')}
        )

    def parse_json_log(self, line: str) -> NormalizedLog:
        try:
            data = json.loads(line)
            timestamp = data.get('timestamp') or data.get('time') or data.get('@timestamp') or datetime.now().isoformat()
            level = self.normalize_level(data.get('level') or data.get('severity') or 'INFO')
            message = data.get('message') or data.get('msg') or str(data)
            source = data.get('source') or data.get('logger') or 'json_log'
            host = data.get('host') or data.get('hostname')
            user = data.get('user') or data.get('username')
            ip = data.get('ip') or data.get('client_ip') or data.get('remote_addr')
            extra_fields = {k: v for k, v in data.items() 
                          if k not in {'timestamp', 'time', '@timestamp', 'level', 'severity', 
                                     'message', 'msg', 'source', 'logger', 'host', 'hostname', 
                                     'user', 'username', 'ip', 'client_ip', 'remote_addr'}}
            return NormalizedLog(
                timestamp=self.normalize_timestamp(timestamp),
                level=level,
                source=source,
                message=message,
                host=host,
                user=user,
                ip=ip,
                extra_fields=extra_fields or None
            )
        except json.JSONDecodeError:
            return self.create_unknown_log(line)

    def create_unknown_log(self, line: str) -> NormalizedLog:
        return NormalizedLog(
            timestamp=datetime.now().isoformat(),
            level='INFO',
            source='unknown',
            message=line.strip()
        )

    def parse_line(self, line: str) -> Optional[NormalizedLog]:
        line = line.strip()
        if not line:
            return None
        format_type = self.detect_format(line)
        if format_type == 'apache_access':
            match = self.patterns['apache_access'].search(line)
            return self.parse_apache_access(line, match) if match else self.create_unknown_log(line)
        elif format_type == 'apache_error':
            match = self.patterns['apache_error'].search(line)
            return self.parse_apache_error(line, match) if match else self.create_unknown_log(line)
        elif format_type == 'nginx_access':
            match = self.patterns['nginx_access'].search(line)
            return self.parse_nginx_access(line, match) if match else self.create_unknown_log(line)
        elif format_type == 'syslog':
            match = self.patterns['syslog'].search(line)
            return self.parse_syslog(line, match) if match else self.create_unknown_log(line)
        elif format_type == 'iis_log':
            match = self.patterns['iis_log'].search(line)
            return self.parse_iis_log(line, match) if match else self.create_unknown_log(line)
        elif format_type == 'json_log':
            return self.parse_json_log(line)
        else:
            return self.create_unknown_log(line)

    def detect_encoding(self, file_path: str) -> str:
        with open(file_path, 'rb') as f:
            raw_data = f.read(10000)  # İlk 10KB
        result = chardet.detect(raw_data)
        encoding = result['encoding']
        if encoding is None or 'ascii' in encoding.lower():
            return 'utf-8'
        return encoding

    def normalize_file(self, input_file: str, output_format: str = 'json') -> List[Dict]:
        normalized_logs = []
        try:
            encoding = self.detect_encoding(input_file)
            with open(input_file, 'r', encoding=encoding, errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        normalized_log = self.parse_line(line)
                        if normalized_log:
                            if output_format == 'json':
                                log_dict = {
                                    'timestamp': normalized_log.timestamp,
                                    'level': normalized_log.level,
                                    'source': normalized_log.source,
                                    'message': normalized_log.message,
                                    'host': normalized_log.host,
                                    'user': normalized_log.user,
                                    'ip': normalized_log.ip
                                }
                                if normalized_log.extra_fields:
                                    log_dict.update(normalized_log.extra_fields)
                                normalized_logs.append(log_dict)
                            else:
                                normalized_logs.append(normalized_log)
                    except Exception as e:
                        logging.debug(f"Satır {line_num} parse edilemedi: {e}")
        except (FileNotFoundError, PermissionError, OSError) as e:
            logging.warning(f"Dosya okunamadı: {input_file} - {e}")
        return normalized_logs

    def normalize_multiple_files(self, input_files: List[str], output_format: str = 'json') -> List[Dict]:
        all_logs = []
        seen_files = set()
        for file_path in input_files:
            if file_path in seen_files:
                continue
            seen_files.add(file_path)
            print(f"📄 Dosya işleniyor: {file_path}")
            logs = self.normalize_file(file_path, output_format)
            all_logs.extend(logs)
        return all_logs

    def save_normalized_logs(self, logs: List[Dict], output_file: str, format_type: str = 'json'):
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if format_type == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                for log in logs:
                    f.write(json.dumps(log, ensure_ascii=False) + '\n')
        elif format_type == 'csv':
            if logs:
                fieldnames = set()
                for log in logs:
                    fieldnames.update(log.keys())
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                    writer.writeheader()
                    writer.writerows(logs)
        print(f"✅ {len(logs)} log kaydı {output_file} dosyasına kaydedildi")


def test_windows_events():
    """Windows Event Log test fonksiyonu"""
    try:
        cmd = ['powershell', '-Command', 'Get-WinEvent -LogName Application -MaxEvents 3 | Select TimeCreated,Message']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        print("PowerShell Çıktısı:")
        print(result.stdout)
        print("Hatalar:")
        print(result.stderr)
    except Exception as e:
        print(f"Test hatası: {e}")


def main():
    parser = argparse.ArgumentParser(description='Gelişmiş Log Normalization Aracı - Otomatik sistem log taraması ile!')
    parser.add_argument('input_file', nargs='?', help='Giriş log dosyası (opsiyonel)')
    parser.add_argument('-o', '--output', help='Çıkış dosyası', default='normalized_logs.json')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json', help='Çıkış formatı')
    parser.add_argument('-v', '--verbose', action='store_true', help='Detaylı çıktı')
    parser.add_argument('-s', '--scan', nargs='?', const='auto', help='Log dosyalarını otomatik tara.')
    parser.add_argument('--scan-windows-events', action='store_true', help='Windows Event Log\'larını (Application, System) da tara.')
    parser.add_argument('--test', action='store_true', help='Windows Event Log test et')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.WARNING)

    if args.test:
        test_windows_events()
        return

    normalizer = LogNormalizer()

    input_files = []
    windows_event_logs = []

    if args.scan_windows_events:
        if sys.platform != "win32":
            print("❌ Windows Event Log desteği sadece Windows'ta çalışır.")
        else:
            print("🔍 Windows Event Log'ları toplanıyor...")
            windows_event_logs = normalizer.get_windows_event_logs()
            print(f"✅ {len(windows_event_logs)} Windows olayı bulundu.")

    if args.scan:
        if args.scan == 'auto':
            print("🔍 Varsayılan sistem log dizinleri taranıyor...")
            input_files = normalizer.find_log_files()
        else:
            print(f"🔍 '{args.scan}' dizini taranıyor...")
            input_files = normalizer.find_log_files(args.scan)
        if not input_files:
            print("❌ Taranan dizinlerde log dosyası bulunamadı.")
    elif args.input_file:
        if not os.path.exists(args.input_file):
            print(f"❌ Dosya bulunamadı: {args.input_file}")
            return
        input_files = [args.input_file]
    elif not args.scan_windows_events:
        print("❌ Lütfen bir dosya belirtin, '--scan' veya '--scan-windows-events' kullanın.")
        parser.print_help()
        return

    file_logs = normalizer.normalize_multiple_files(input_files, args.format) if input_files else []

    all_logs = []
    for log in windows_event_logs:
        log_dict = {
            'timestamp': log.timestamp,
            'level': log.level,
            'source': log.source,
            'message': log.message,
            'host': log.host,
            'user': log.user,
            'ip': log.ip
        }
        if log.extra_fields:
            log_dict.update(log.extra_fields)
        all_logs.append(log_dict)
    all_logs.extend(file_logs)

    if all_logs:
        normalizer.save_normalized_logs(all_logs, args.output, args.format)
        print(f"📊 Toplam işlenen log sayısı: {len(all_logs)}")
    else:
        print("❌ Hiç log kaydı işlenemedi")


def test_normalizer():
    normalizer = LogNormalizer()
    test_logs = [
        '192.168.1.100 - - [25/Dec/2023:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '[Mon Dec 25 10:00:00 2023] [error] [pid 12345] File does not exist: /var/www/html/missing.html',
        '{"timestamp": "2023-12-25T10:00:00Z", "level": "INFO", "message": "User login successful", "user": "john_doe", "ip": "192.168.1.50"}',
        'Dec 25 10:00:00 webserver nginx[1234]: Connection from 192.168.1.200',
        '2023-12-25 10:00:00 192.168.1.10 GET /login - 80 john_doe 192.168.1.50 Mozilla/5.0 200',
        'Some random log entry without standard format'
    ]
    print("🧪 Dahili test logları:")
    print("=" * 50)
    for i, log_line in enumerate(test_logs, 1):
        print(f"\n📝 Test {i}: {log_line}")
        normalized = normalizer.parse_line(log_line)
        if normalized:
            print(f"✅ Format: {normalizer.detect_format(log_line)}")
            print(f"   Timestamp: {normalized.timestamp}")
            print(f"   Level: {normalized.level}")
            print(f"   Source: {normalized.source}")
            print(f"   Message: {normalized.message}")
            if normalized.ip:
                print(f"   IP: {normalized.ip}")
            if normalized.extra_fields:
                print(f"   Extra: {normalized.extra_fields}")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        test_normalizer()
    else:
        main()