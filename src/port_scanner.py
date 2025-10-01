"""
Модуль для сканування портів за допомогою nmap
"""
import nmap
from typing import List, Dict


class PortScanner:
    """Клас для сканування відкритих портів на хостах"""

    def __init__(self):
        """Ініціалізація сканера портів"""
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("[!] Помилка: nmap не знайдено в системі")
            print("[!] Встановіть nmap: sudo apt-get install nmap (Linux)")
            raise

    def scan_host(self, ip: str, ports: str = "1-1000", arguments: str = "-sV") -> Dict:
        """
        Сканування портів на конкретному хості

        Args:
            ip: IP адреса для сканування
            ports: Діапазон портів (наприклад, '1-1000' або '22,80,443')
            arguments: Додаткові аргументи nmap (-sV для визначення версій)

        Returns:
            Словник з результатами сканування
        """
        print(f"[*] Сканування портів для {ip}...")

        try:
            self.nm.scan(ip, ports, arguments=arguments)

            if ip not in self.nm.all_hosts():
                return {'ip': ip, 'ports': [], 'state': 'down'}

            host_info = {
                'ip': ip,
                'state': self.nm[ip].state(),
                'ports': []
            }

            # Збір інформації про відкриті порти
            if 'tcp' in self.nm[ip]:
                for port in self.nm[ip]['tcp'].keys():
                    port_info = self.nm[ip]['tcp'][port]
                    host_info['ports'].append({
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', '')
                    })

            return host_info

        except Exception as e:
            print(f"[!] Помилка сканування {ip}: {e}")
            return {'ip': ip, 'ports': [], 'state': 'error'}

    def scan_multiple_hosts(self, ip_list: List[str], ports: str = "1-1000") -> Dict[str, Dict]:
        """
        Сканування портів на декількох хостах

        Args:
            ip_list: Список IP адрес
            ports: Діапазон портів для сканування

        Returns:
            Словник з результатами для кожного IP
        """
        results = {}

        for ip in ip_list:
            result = self.scan_host(ip, ports)
            results[ip] = result

            # Виведення відкритих портів
            if result['ports']:
                print(f"\n[+] Відкриті порти на {ip}:")
                for port_info in result['ports']:
                    service = port_info['service']
                    version = port_info['version']
                    print(f"    {port_info['port']}/tcp - {service} {version}")
            else:
                print(f"[-] Відкритих портів не знайдено на {ip}")

        return results

    def quick_scan(self, ip_list: List[str]) -> Dict[str, Dict]:
        """
        Швидке сканування найпопулярніших портів

        Args:
            ip_list: Список IP адрес

        Returns:
            Словник з результатами
        """
        # Популярні порти для швидкого сканування
        common_ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
        return self.scan_multiple_hosts(ip_list, ports=common_ports)
