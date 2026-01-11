"""
Модуль для агрегации сетевых пакетов.
Реализует два типа агрегации: по временному окну и по flow (5-tuple).
"""

from typing import Dict, List, Optional
from collections import defaultdict
import time


class TimeWindowAggregator:
    """Агрегация пакетов по временному окну."""
    
    def __init__(self, window_size: float = 5.0):
        """
        Инициализация агрегатора по временному окну.
        
        Args:
            window_size: Размер временного окна в секундах
        """
        self.window_size = window_size
        self.current_window = []
        self.window_start = None
    
    def add_packet(self, packet: Dict) -> List[Dict]:
        """
        Добавление пакета и возврат завершенных окон.
        
        Args:
            packet: Словарь с features пакета
        
        Returns:
            Список агрегированных окон (может быть несколько, если был большой разрыв)
        """
        timestamp = packet['timestamp']
        completed_windows = []
        
        if self.window_start is None:
            # Выравниваем начало окна на границу window_size (например, каждые 5 секунд)
            # Это обеспечивает фиксированные интервалы независимо от времени первого пакета
            self.window_start = (int(timestamp / self.window_size)) * self.window_size
        
        # Обрабатываем все завершенные окна до текущего момента
        while timestamp - self.window_start >= self.window_size:
            # Сохраняем текущее окно, если в нем есть пакеты
            if self.current_window:
                window_end = self.window_start + self.window_size
                aggregated = self._aggregate_window(self.current_window, self.window_start, window_end)
                completed_windows.append(aggregated)
                self.current_window = []
            
            # Переходим к следующему окну (фиксированный интервал)
            self.window_start += self.window_size
        
        # Добавляем пакет в текущее окно
        self.current_window.append(packet)
        
        return completed_windows
    
    def _aggregate_window(self, packets: List[Dict], window_start: float, window_end: float) -> Dict:
        """
        Агрегация пакетов в окне в один вектор признаков.
        
        Args:
            packets: Список пакетов в окне
            window_start: Начало временного окна
            window_end: Конец временного окна
        
        Returns:
            Агрегированный вектор признаков
        """
        if not packets:
            return {}
        
        packet_count = len(packets)
        duration = window_end - window_start
        
        # Подсчет уникальных значений
        unique_src_mac = len(set(p['src_mac'] for p in packets if p['src_mac']))
        unique_dst_mac = len(set(p['dst_mac'] for p in packets if p['dst_mac']))
        unique_src_ip = len(set(p['src_ip'] for p in packets if p['src_ip']))
        unique_dst_ip = len(set(p['dst_ip'] for p in packets if p['dst_ip']))
        unique_src_port = len(set(p['src_port'] for p in packets if p['src_port']))
        unique_dst_port = len(set(p['dst_port'] for p in packets if p['dst_port']))
        
        # Статистики по протоколам
        proto_counts = defaultdict(int)
        for p in packets:
            if p['proto'] is not None:
                proto_counts[p['proto']] += 1
        
        # Статистики по длине пакетов
        lengths = [p['length'] for p in packets]
        avg_length = sum(lengths) / len(lengths) if lengths else 0
        min_length = min(lengths) if lengths else 0
        max_length = max(lengths) if lengths else 0
        
        # Статистики по TTL
        ttls = [p['ttl'] for p in packets if p['ttl'] is not None]
        avg_ttl = sum(ttls) / len(ttls) if ttls else 0
        
        # Статистики по TCP флагам
        tcp_flags = [p['tcp_flags'] for p in packets if p['tcp_flags'] is not None]
        unique_tcp_flags = len(set(tcp_flags)) if tcp_flags else 0
        
        # Статистики по ICMP
        icmp_packets = [p for p in packets if p['icmp_type'] is not None]
        icmp_count = len(icmp_packets)
        
        # Создание вектора признаков
        features = {
            'packet_count': packet_count,
            'duration': duration,
            'packets_per_second': packet_count / duration if duration > 0 else 0,
            'unique_src_mac': unique_src_mac,
            'unique_dst_mac': unique_dst_mac,
            'unique_src_ip': unique_src_ip,
            'unique_dst_ip': unique_dst_ip,
            'unique_src_port': unique_src_port,
            'unique_dst_port': unique_dst_port,
            'avg_length': avg_length,
            'min_length': min_length,
            'max_length': max_length,
            'avg_ttl': avg_ttl,
            'unique_tcp_flags': unique_tcp_flags,
            'icmp_count': icmp_count,
            'proto_tcp': proto_counts.get(6, 0),
            'proto_udp': proto_counts.get(17, 0),
            'proto_icmp': proto_counts.get(1, 0),
            'window_start': window_start,
            'window_end': window_end
        }
        
        return features
    
    def flush(self) -> List[Dict]:
        """
        Завершение текущего окна и возврат его.
        
        Returns:
            Список с одним агрегированным окном (если есть данные)
        """
        if self.current_window and self.window_start is not None:
            window_end = self.window_start + self.window_size
            aggregated = self._aggregate_window(self.current_window, self.window_start, window_end)
            self.current_window = []
            self.window_start = None
            return [aggregated]
        return []


class FlowAggregator:
    """Агрегация пакетов по flow (5-tuple)."""
    
    def __init__(self, flow_timeout: float = 60.0):
        """
        Инициализация агрегатора по flow.
        
        Args:
            flow_timeout: Таймаут для завершения flow в секундах
        """
        self.flow_timeout = flow_timeout
        self.active_flows = {}
    
    def _get_flow_key(self, packet: Dict) -> Optional[str]:
        """
        Получение ключа flow из 5-tuple.
        
        Args:
            packet: Словарь с features пакета
        
        Returns:
            Ключ flow или None если недостаточно данных
        """
        if not all([packet.get('src_ip'), packet.get('dst_ip'), 
                   packet.get('src_port'), packet.get('dst_port'), 
                   packet.get('proto')]):
            return None
        
        # Создаем канонический ключ (меньший IP всегда первый)
        src_ip = packet['src_ip']
        dst_ip = packet['dst_ip']
        src_port = packet['src_port']
        dst_port = packet['dst_port']
        proto = packet['proto']
        
        # Нормализация: меньший IP и порт всегда первые
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        else:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
        
        return key
    
    def add_packet(self, packet: Dict) -> List[Dict]:
        """
        Добавление пакета и возврат завершенных flow.
        
        Args:
            packet: Словарь с features пакета
        
        Returns:
            Список завершенных flow
        """
        flow_key = self._get_flow_key(packet)
        if flow_key is None:
            return []
        
        timestamp = packet['timestamp']
        completed_flows = []
        
        # Проверка таймаутов существующих flow
        flows_to_close = []
        for key, flow_data in self.active_flows.items():
            if timestamp - flow_data['last_seen'] > self.flow_timeout:
                flows_to_close.append(key)
        
        for key in flows_to_close:
            flow_data = self.active_flows.pop(key)
            aggregated = self._aggregate_flow(flow_data)
            completed_flows.append(aggregated)
        
        # Добавление пакета в flow
        if flow_key in self.active_flows:
            self.active_flows[flow_key]['packets'].append(packet)
            self.active_flows[flow_key]['last_seen'] = timestamp
        else:
            self.active_flows[flow_key] = {
                'packets': [packet],
                'first_seen': timestamp,
                'last_seen': timestamp,
                'flow_key': flow_key
            }
        
        return completed_flows
    
    def _aggregate_flow(self, flow_data: Dict) -> Dict:
        """
        Агрегация пакетов flow в вектор признаков.
        
        Args:
            flow_data: Данные flow
        
        Returns:
            Агрегированный вектор признаков
        """
        packets = flow_data['packets']
        if not packets:
            return {}
        
        flow_key = flow_data['flow_key']
        first_seen = flow_data['first_seen']
        last_seen = flow_data['last_seen']
        duration = last_seen - first_seen
        
        # Базовые статистики
        packet_count = len(packets)
        bytes_total = sum(p['length'] for p in packets)
        
        # Направление потока (больше пакетов в одну сторону)
        first_packet = packets[0]
        src_ip = first_packet['src_ip']
        dst_ip = first_packet['dst_ip']
        
        # Статистики по длине пакетов
        lengths = [p['length'] for p in packets]
        avg_length = sum(lengths) / len(lengths) if lengths else 0
        min_length = min(lengths) if lengths else 0
        max_length = max(lengths) if lengths else 0
        
        # Статистики по TTL
        ttls = [p['ttl'] for p in packets if p['ttl'] is not None]
        avg_ttl = sum(ttls) / len(ttls) if ttls else 0
        
        # Статистики по TCP флагам
        tcp_flags = [p['tcp_flags'] for p in packets if p['tcp_flags'] is not None]
        unique_tcp_flags = len(set(tcp_flags)) if tcp_flags else 0
        
        # Статистики по ICMP
        icmp_packets = [p for p in packets if p['icmp_type'] is not None]
        icmp_count = len(icmp_packets)
        
        # Протокол
        proto = first_packet.get('proto', 0)
        
        # Создание вектора признаков
        features = {
            'flow_key': flow_key,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'proto': proto,
            'packet_count': packet_count,
            'bytes_total': bytes_total,
            'duration': duration,
            'packets_per_second': packet_count / duration if duration > 0 else 0,
            'bytes_per_second': bytes_total / duration if duration > 0 else 0,
            'avg_length': avg_length,
            'min_length': min_length,
            'max_length': max_length,
            'avg_ttl': avg_ttl,
            'unique_tcp_flags': unique_tcp_flags,
            'icmp_count': icmp_count,
            'first_seen': first_seen,
            'last_seen': last_seen
        }
        
        return features
    
    def flush_all(self) -> List[Dict]:
        """
        Завершение всех активных flow.
        
        Returns:
            Список завершенных flow
        """
        completed_flows = []
        for flow_data in self.active_flows.values():
            aggregated = self._aggregate_flow(flow_data)
            completed_flows.append(aggregated)
        
        self.active_flows.clear()
        return completed_flows
