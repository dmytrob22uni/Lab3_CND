"""
Модуль для сканування локальної мережі
"""
import ipaddress
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
from typing import List, Dict, Optional
import socket


class NetworkScanner:
    """Клас для сканування мережі та виявлення активних пристроїв"""
    
    def __init__(self, network: str, timeout: int = 2):
        """
        Ініціалізація сканера
        
        Args:
            network: Мережа для сканування (наприклад, '192.168.1.0/24')
            timeout: Таймаут для запитів (секунди)
        """
        self.network = network
        self.timeout = timeout
        self.active_hosts: List[Dict[str, str]] = []
    
    def arp_scan(self) -> List[Dict[str, str]]:
        """
        ARP сканування мережі для виявлення активних пристроїв
        
        Returns:
            Список словників з IP та MAC адресами
        """
        print(f"[*] Виконується ARP сканування мережі {self.network}...")
        
        try:
            # Створення ARP запиту
            arp_request = ARP(pdst=self.network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Відправка запиту та отримання відповідей
            answered_list = srp(arp_request_broadcast, timeout=self.timeout, verbose=False)[0]
            
            devices = []
            for sent, received in answered_list:
                device_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'hostname': self._get_hostname(received.psrc)
                }
                devices.append(device_info)
                print(f"[+] Знайдено: {device_info['ip']} - {device_info['mac']} ({device_info['hostname']})")
            
            self.active_hosts = devices
            return devices
        
        except PermissionError:
            print("[!] Помилка: Потрібні права адміністратора для ARP сканування")
            print("[!] Спробуйте запустити з sudo (Linux/Mac) або від імені адміністратора (Windows)")
            return []
        except Exception as e:
            print(f"[!] Помилка ARP сканування: {e}")
            return []
    
    def icmp_scan(self, ip_list: Optional[List[str]] = None) -> List[Dict[str, str]]:
        """
        ICMP (ping) сканування для перевірки доступності хостів
        
        Args:
            ip_list: Список IP для сканування (якщо None, сканується вся мережа)
        
        Returns:
            Список словників з активними хостами
        """
        print(f"[*] Виконується ICMP сканування...")
        
        if ip_list is None:
            # Генерація списку IP адрес з мережі
            network = ipaddress.ip_network(self.network, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        
        devices = []
        for ip in ip_list:
            if self._ping_host(ip):
                device_info = {
                    'ip': ip,
                    'mac': 'Unknown',
                    'hostname': self._get_hostname(ip)
                }
                devices.append(device_info)
                print(f"[+] Хост доступний: {ip} ({device_info['hostname']})")
        
        # Об'єднання з результатами ARP сканування
        if not self.active_hosts:
            self.active_hosts = devices
        
        return devices
    
    def _ping_host(self, ip: str) -> bool:
        """
        Перевірка доступності хоста через ICMP ping
        
        Args:
            ip: IP адреса для перевірки
        
        Returns:
            True якщо хост відповідає, False якщо ні
        """
        try:
            packet = IP(dst=ip)/ICMP()
            response = sr1(packet, timeout=self.timeout, verbose=False)
            return response is not None
        except Exception:
            return False
    
    def _get_hostname(self, ip: str) -> str:
        """
        Отримання hostname за IP адресою
        
        Args:
            ip: IP адреса
        
        Returns:
            Hostname або 'Unknown'
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return 'Unknown'
    
    def get_active_hosts(self) -> List[Dict[str, str]]:
        """
        Повернення списку активних хостів
        
        Returns:
            Список словників з інформацією про хости
        """
        return self.active_hosts
