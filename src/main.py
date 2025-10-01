"""
Головна програма для сканування мережі
"""
import sys
import argparse
import json
from datetime import datetime
from network_scanner import NetworkScanner
from port_scanner import PortScanner
from network_topology import NetworkTopology


class NetworkAnalyzer:
    """Головний клас для аналізу мережі"""
    
    def __init__(self, network: str, timeout: int = 2):
        """
        Ініціалізація аналізатора
        
        Args:
            network: Мережа для сканування (наприклад, '192.168.1.0/24')
            timeout: Таймаут для запитів
        """
        self.network = network
        self.timeout = timeout
        self.scanner = NetworkScanner(network, timeout)
        self.port_scanner = None
        self.topology = NetworkTopology()
        self.results = {}
    
    def run_full_scan(self, scan_ports: bool = True, port_range: str = "1-1000"):
        """
        Повне сканування мережі
        
        Args:
            scan_ports: Чи сканувати порти
            port_range: Діапазон портів для сканування
        """
        print("="*60)
        print("СКАНУВАННЯ ЛОКАЛЬНОЇ МЕРЕЖІ")
        print("="*60)
        print(f"Мережа: {self.network}")
        print(f"Час початку: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        # Крок 1: ARP сканування
        print("\n[КРОК 1] ARP Сканування")
        print("-"*60)
        devices = self.scanner.arp_scan()
        
        if not devices:
            print("\n[!] Пристроїв не знайдено через ARP. Пробуємо ICMP...")
            devices = self.scanner.icmp_scan()
        
        if not devices:
            print("\n[!] Активних пристроїв не знайдено!")
            return
        
        print(f"\n[✓] Знайдено {len(devices)} активних пристроїв")
        self.results['devices'] = devices
        
        # Крок 2: Сканування портів (опціонально)
        port_data = None
        if scan_ports:
            print("\n[КРОК 2] Сканування портів")
            print("-"*60)
            try:
                self.port_scanner = PortScanner()
                ip_list = [device['ip'] for device in devices]
                
                # Вибір режиму сканування
                if port_range == "quick":
                    port_data = self.port_scanner.quick_scan(ip_list)
                else:
                    port_data = self.port_scanner.scan_multiple_hosts(ip_list, port_range)
                
                self.results['ports'] = port_data
                print(f"\n[✓] Сканування портів завершено")
            except Exception as e:
                print(f"\n[!] Помилка при скануванні портів: {e}")
                print("[!] Продовжуємо без даних про порти...")
        
        # Крок 3: Побудова топології
        print("\n[КРОК 3] Побудова топології мережі")
        print("-"*60)
        self.topology.build_topology(devices, port_data)
        
        # Крок 4: Візуалізація
        print("\n[КРОК 4] Візуалізація топології")
        print("-"*60)
        self.topology.visualize(show=False)
        
        # Крок 5: Підсумок
        self._print_summary()
    
    def _print_summary(self):
        """Виведення підсумкової інформації"""
        print("\n" + "="*60)
        print("ПІДСУМОК СКАНУВАННЯ")
        print("="*60)
        
        devices = self.results.get('devices', [])
        print(f"\nВсього пристроїв: {len(devices)}")
        
        print("\nСписок пристроїв:")
        print("-"*60)
        for i, device in enumerate(devices, 1):
            print(f"{i}. IP: {device['ip']:<15} MAC: {device['mac']:<17} Hostname: {device['hostname']}")
        
        # Інформація про порти
        if 'ports' in self.results:
            print("\nВідкриті порти:")
            print("-"*60)
            for ip, data in self.results['ports'].items():
                if data['ports']:
                    print(f"\n{ip}:")
                    for port in data['ports']:
                        if port['state'] == 'open':
                            print(f"  - {port['port']}/tcp: {port['service']} {port['version']}")
        
        print("\n" + "="*60)
        print(f"Час завершення: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
    
    def save_results(self, filename: str = "scan_results.json"):
        """
        Збереження результатів у JSON файл
        
        Args:
            filename: Ім'я файлу для збереження
        """
        self.results['scan_time'] = datetime.now().isoformat()
        self.results['network'] = self.network
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        
        print(f"\n[+] Результати збережено у файл: {filename}")


def main():
    """Головна функція програми"""
    parser = argparse.ArgumentParser(
        description='Сканування локальної мережі та візуалізація топології',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Приклади використання:
  python main.py 192.168.1.0/24
  python main.py 192.168.1.0/24 --no-ports
  python main.py 192.168.1.0/24 --ports quick
  python main.py 192.168.1.0/24 --ports 1-1000 --timeout 3
        """
    )
    
    parser.add_argument('network', 
                       help='Мережа для сканування (наприклад, 192.168.1.0/24)')
    parser.add_argument('--no-ports', 
                       action='store_true',
                       help='Пропустити сканування портів')
    parser.add_argument('--ports', 
                       default='1-1000',
                       help='Діапазон портів або "quick" для швидкого сканування (за замовчуванням: 1-1000)')
    parser.add_argument('--timeout', 
                       type=int, 
                       default=2,
                       help='Таймаут для запитів в секундах (за замовчуванням: 2)')
    parser.add_argument('--output', 
                       default='scan_results.json',
                       help='Файл для збереження результатів (за замовчуванням: scan_results.json)')
    
    args = parser.parse_args()
    
    # Перевірка прав доступу
    if sys.platform != 'win32':
        import os
        if os.geteuid() != 0:
            print("[!] УВАГА: Для коректної роботи ARP сканування потрібні права root/sudo")
            print("[!] Запустіть програму з sudo: sudo python main.py " + args.network)
            print("[!] Або використовуйте тільки ICMP сканування (може бути менш точним)\n")
    
    try:
        # Створення аналізатора
        analyzer = NetworkAnalyzer(args.network, args.timeout)
        
        # Запуск сканування
        scan_ports = not args.no_ports
        analyzer.run_full_scan(scan_ports=scan_ports, port_range=args.ports)
        
        # Збереження результатів
        analyzer.save_results(args.output)
        
        print("\n[✓] Сканування успішно завершено!")
        print("[+] Перегляньте network_topology.png для візуалізації мережі")
        
    except KeyboardInterrupt:
        print("\n\n[!] Сканування перервано користувачем")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Критична помилка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
