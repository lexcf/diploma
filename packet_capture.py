"""
Модуль для захвата и парсинга сетевых пакетов.
Извлекает все необходимые features из пакетов.
"""

from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.inet6 import IPv6
import time
from typing import Dict, Optional, List


class PacketCapture:
    """Класс для захвата и обработки сетевых пакетов."""
    
    def __init__(self, interface: str = "eth0"):
        """
        Инициализация захвата пакетов.
        
        Args:
            interface: Имя сетевого интерфейса
        """
        self.interface = interface
        self.packets = []
        
    def check_interface(self) -> bool:
        """Проверка доступности интерфейса."""
        available_interfaces = get_if_list()
        return self.interface in available_interfaces
    
    def extract_features(self, packet) -> Optional[Dict]:
        """
        Извлечение features из пакета.
        
        Returns:
            Словарь с features или None если пакет не подходит
        """
        features = {
            'timestamp': time.time(),
            'src_mac': None,
            'dst_mac': None,
            'vlan': None,
            'eth_type': None,
            'src_ip': None,
            'dst_ip': None,
            'icmp_type': None,
            'icmp_code': None,
            'proto': None,
            'ttl': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'length': len(packet)
        }
        
        # Ethernet layer
        if Ether in packet:
            eth = packet[Ether]
            features['src_mac'] = eth.src
            features['dst_mac'] = eth.dst
            features['eth_type'] = hex(eth.type)
            
            # VLAN
            if Dot1Q in packet:
                features['vlan'] = packet[Dot1Q].vlan
        
        # IP layer (IPv4)
        if IP in packet:
            ip = packet[IP]
            features['src_ip'] = ip.src
            features['dst_ip'] = ip.dst
            features['proto'] = ip.proto
            features['ttl'] = ip.ttl
            
            # TCP
            if TCP in packet:
                tcp = packet[TCP]
                features['src_port'] = tcp.sport
                features['dst_port'] = tcp.dport
                features['tcp_flags'] = int(tcp.flags)
            
            # UDP
            elif UDP in packet:
                udp = packet[UDP]
                features['src_port'] = udp.sport
                features['dst_port'] = udp.dport
            
            # ICMP
            elif ICMP in packet:
                icmp = packet[ICMP]
                features['icmp_type'] = icmp.type
                features['icmp_code'] = icmp.code
        
        # IPv6
        elif IPv6 in packet:
            ipv6 = packet[IPv6]
            features['src_ip'] = ipv6.src
            features['dst_ip'] = ipv6.dst
            features['proto'] = ipv6.nh
            features['ttl'] = ipv6.hlim
            
            if TCP in packet:
                tcp = packet[TCP]
                features['src_port'] = tcp.sport
                features['dst_port'] = tcp.dport
                features['tcp_flags'] = int(tcp.flags)
            elif UDP in packet:
                udp = packet[UDP]
                features['src_port'] = udp.sport
                features['dst_port'] = udp.dport
            elif ICMP in packet:
                icmp = packet[ICMP]
                features['icmp_type'] = icmp.type
                features['icmp_code'] = icmp.code
        
        # ARP
        elif ARP in packet:
            arp = packet[ARP]
            features['src_ip'] = arp.psrc
            features['dst_ip'] = arp.pdst
        
        return features
    
    def capture_packets(self, duration: int, callback=None) -> List[Dict]:
        """
        Захват пакетов в течение указанного времени.
        
        Args:
            duration: Длительность захвата в секундах
            callback: Функция обратного вызова для обработки каждого пакета
        
        Returns:
            Список словарей с features пакетов
        """
        if not self.check_interface():
            raise ValueError(f"Интерфейс {self.interface} недоступен")
        
        captured_packets = []
        start_time = time.time()
        
        def process_packet(packet):
            features = self.extract_features(packet)
            if features:
                captured_packets.append(features)
                if callback:
                    callback(features)
        
        print(f"Начало захвата пакетов на интерфейсе {self.interface}...")
        sniff(iface=self.interface, prn=process_packet, timeout=duration, store=False)
        
        elapsed = time.time() - start_time
        print(f"Захвачено {len(captured_packets)} пакетов за {elapsed:.2f} секунд")
        
        return captured_packets
    
    def capture_packets_continuous(self, callback):
        """
        Непрерывный захват пакетов для детекции аномалий.
        
        Args:
            callback: Функция обратного вызова для обработки каждого пакета
        """
        if not self.check_interface():
            raise ValueError(f"Интерфейс {self.interface} недоступен")
        
        def process_packet(packet):
            features = self.extract_features(packet)
            if features:
                callback(features)
        
        print(f"Непрерывный захват пакетов на интерфейсе {self.interface}...")
        sniff(iface=self.interface, prn=process_packet, store=False)
