"""
Модуль для створення та візуалізації топології мережі
"""
import networkx as nx
import matplotlib.pyplot as plt
from typing import List, Dict
import socket


class NetworkTopology:
    """Клас для створення та відображення топології мережі"""
    
    def __init__(self):
        """Ініціалізація графа мережі"""
        self.graph = nx.Graph()
        self.gateway_ip = self._get_gateway_ip()
    
    def _get_gateway_ip(self) -> str:
        """
        Визначення IP адреси шлюзу (gateway)
        
        Returns:
            IP адреса шлюзу або локальної машини
        """
        try:
            # Отримання IP локальної машини
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Припускаємо, що gateway це .1 в тій же підмережі
            ip_parts = local_ip.split('.')
            gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
            return gateway
        except Exception:
            return "192.168.1.1"
    
    def build_topology(self, devices: List[Dict[str, str]], port_data: Dict[str, Dict] = None):
        """
        Побудова топології мережі на основі виявлених пристроїв
        
        Args:
            devices: Список пристроїв з IP та MAC адресами
            port_data: Дані про відкриті порти (опціонально)
        """
        # Додавання центрального вузла (gateway/router)
        self.graph.add_node(self.gateway_ip, 
                           type='gateway', 
                           label='Gateway/Router',
                           color='red')
        
        # Додавання пристроїв до графа
        for device in devices:
            ip = device['ip']
            mac = device['mac']
            hostname = device.get('hostname', 'Unknown')
            
            # Визначення типу пристрою
            device_type = self._determine_device_type(ip, port_data)
            
            # Створення мітки для вузла
            label = f"{hostname}\n{ip}\n{mac}"
            
            # Додавання вузла
            self.graph.add_node(ip, 
                               type=device_type, 
                               label=label,
                               mac=mac,
                               hostname=hostname)
            
            # З'єднання з gateway
            self.graph.add_edge(self.gateway_ip, ip)
        
        print(f"[*] Побудовано топологію з {len(self.graph.nodes())} вузлів")
    
    def _determine_device_type(self, ip: str, port_data: Dict = None) -> str:
        """
        Визначення типу пристрою на основі відкритих портів
        
        Args:
            ip: IP адреса пристрою
            port_data: Дані про порти
        
        Returns:
            Тип пристрою
        """
        if not port_data or ip not in port_data:
            return 'device'
        
        ports = port_data[ip].get('ports', [])
        open_ports = [p['port'] for p in ports if p['state'] == 'open']
        
        # Визначення типу на основі відкритих портів
        if 80 in open_ports or 443 in open_ports:
            return 'web_server'
        elif 22 in open_ports:
            return 'server'
        elif 3389 in open_ports:
            return 'windows'
        elif 445 in open_ports:
            return 'file_server'
        else:
            return 'device'
    
    def visualize(self, output_file: str = "network_topology.png", show: bool = True):
        """
        Візуалізація топології мережі
        
        Args:
            output_file: Ім'я файлу для збереження
            show: Чи показувати графік
        """
        plt.figure(figsize=(16, 12))
        
        # Позиціонування вузлів (circular layout для кращого вигляду)
        pos = nx.spring_layout(self.graph, k=2, iterations=50)
        
        # Кольори для різних типів пристроїв
        color_map = {
            'gateway': '#FF6B6B',
            'web_server': '#4ECDC4',
            'server': '#45B7D1',
            'windows': '#FFA07A',
            'file_server': '#98D8C8',
            'device': '#95E1D3'
        }
        
        # Підготовка кольорів вузлів
        node_colors = []
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get('type', 'device')
            node_colors.append(color_map.get(node_type, '#95E1D3'))
        
        # Малювання графа
        nx.draw_networkx_edges(self.graph, pos, alpha=0.3, width=2)
        nx.draw_networkx_nodes(self.graph, pos, 
                              node_color=node_colors,
                              node_size=3000,
                              alpha=0.9)
        
        # Додавання міток
        labels = nx.get_node_attributes(self.graph, 'label')
        nx.draw_networkx_labels(self.graph, pos, labels, 
                               font_size=8,
                               font_weight='bold')
        
        # Налаштування графіку
        plt.title("Топологія локальної мережі", fontsize=20, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        
        # Додавання легенди
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', 
                      markerfacecolor=color_map['gateway'], markersize=10, label='Gateway/Router'),
            plt.Line2D([0], [0], marker='o', color='w', 
                      markerfacecolor=color_map['web_server'], markersize=10, label='Web Server'),
            plt.Line2D([0], [0], marker='o', color='w', 
                      markerfacecolor=color_map['server'], markersize=10, label='Server'),
            plt.Line2D([0], [0], marker='o', color='w', 
                      markerfacecolor=color_map['device'], markersize=10, label='Device')
        ]
        plt.legend(handles=legend_elements, loc='upper left', fontsize=10)
        
        # Збереження
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"[+] Топологія збережена у файл: {output_file}")
        
        if show:
            plt.show()
    
    def export_graph_data(self) -> Dict:
        """
        Експорт даних графа
        
        Returns:
            Словник з даними про вузли та з'єднання
        """
        return {
            'nodes': list(self.graph.nodes(data=True)),
            'edges': list(self.graph.edges()),
            'num_nodes': len(self.graph.nodes()),
            'num_edges': len(self.graph.edges())
        }
