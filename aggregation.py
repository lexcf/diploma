"""
Модуль для агрегации сетевых пакетов по временному окну.
"""

from typing import Dict, List
from collections import defaultdict


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
