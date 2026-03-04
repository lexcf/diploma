#!/usr/bin/env python3
"""
Основной модуль для обучения модели и детекции аномалий в сетевом трафике.
"""

import argparse
import sys
import os
from typing import Optional
from packet_capture import PacketCapture
from aggregation import TimeWindowAggregator
from anomaly_detector import AnomalyDetector
from alerting import TrafficLogger, build_zip_from_packets, send_zip_to_server
import config
import time


def train_model(interface: str, duration_minutes: int,
                window_size: float, model_path: str):
    """
    Обучение модели на сетевом трафике.
    
    Args:
        interface: Имя сетевого интерфейса
        duration_minutes: Длительность обучения в минутах
        window_size: Размер временного окна в секундах
        model_path: Путь для сохранения модели
    """
    print(f"=" * 60)
    print(f"Обучение модели детекции аномалий")
    print(f"Интерфейс: {interface}")
    print(f"Длительность: {duration_minutes} минут")
    print(f"Тип агрегации: time_window")
    print(f"Размер окна: {window_size} секунд")
    print(f"=" * 60)
    
    # Инициализация компонентов
    capture = PacketCapture(interface)
    detector = AnomalyDetector(contamination=config.model.contamination)
    aggregator = TimeWindowAggregator(window_size=window_size)
    
    aggregated_data = []
    
    def process_packet(packet):
        """Обработка каждого захваченного пакета."""
        completed = aggregator.add_packet(packet)
        aggregated_data.extend(completed)
    
    # Захват пакетов
    duration_seconds = duration_minutes * 60
    capture.capture_packets(duration_seconds, callback=process_packet)
    
    # Завершение последних агрегированных данных
    remaining = aggregator.flush()
    aggregated_data.extend(remaining)
    
    if not aggregated_data:
        print("Ошибка: Не удалось собрать данные для обучения.")
        sys.exit(1)
    
    print(f"\nСобрано {len(aggregated_data)} агрегированных образцов")
    
    # Обучение модели
    try:
        detector.train(aggregated_data)
        detector.save(model_path)
        print(f"\nОбучение завершено успешно!")
    except Exception as e:
        print(f"Ошибка при обучении: {e}")
        sys.exit(1)
def detect_anomalies(interface: str, model_path: str,
                     window_size: float, score_threshold: Optional[float] = None):
    """
    Детекция аномалий в реальном времени.
    
    Args:
        interface: Имя сетевого интерфейса
        model_path: Путь к сохраненной модели
        window_size: Размер временного окна в секундах
        score_threshold: Порог по anomaly_score (None = использовать бинарное предсказание)
                        Чем ниже порог, тем выше чувствительность
    """
    print(f"=" * 60)
    print(f"Детекция аномалий в сетевом трафике")
    print(f"Интерфейс: {interface}")
    print(f"Модель: {model_path}")
    print(f"Тип агрегации: time_window")
    print(f"Размер окна: {window_size} секунд")
    print(f"=" * 60)
    print("Нажмите Ctrl+C для остановки\n")
    
    # Загрузка модели
    detector = AnomalyDetector()
    try:
        detector.load(model_path)
        # Устанавливаем порог, если указан (переопределяет сохраненный порог)
        if score_threshold is not None:
            detector.score_threshold = score_threshold
            print(f"Используется порог по score: {score_threshold}")
    except Exception as e:
        print(f"Ошибка при загрузке модели: {e}")
        sys.exit(1)
    
    # Инициализация компонентов
    capture = PacketCapture(interface)
    aggregator = TimeWindowAggregator(window_size=window_size)
    traffic_logger = TrafficLogger(retention_minutes=config.detection.traffic_log_minutes)
    
    anomaly_count = 0
    total_count = 0
    
    def process_packet(packet):
        """Обработка каждого захваченного пакета."""
        nonlocal anomaly_count, total_count

        # Логируем все пакеты для последующего формирования архива
        traffic_logger.add_packet(packet)

        completed = aggregator.add_packet(packet)
        
        if completed:
            # Предсказание аномалий
            results = detector.predict(completed)
            
            for result in results:
                total_count += 1
                if result['is_anomaly']:
                    anomaly_count += 1
                    handle_anomaly(result, traffic_logger)

    def handle_anomaly(result: dict, logger: TrafficLogger):
        """Обработка обнаруженной аномалии: вывод и отправка лога трафика."""
        print_anomaly(result)

        if not config.detection.send_zip_on_anomaly:
            return

        window_end = result.get('window_end', time.time())
        packets_for_zip = logger.get_recent_packets(window_end)

        if not packets_for_zip:
            print("Нет пакетов для формирования архива трафика за указанный период.")
            return

        zip_path = build_zip_from_packets(packets_for_zip)
        if not zip_path:
            print("Не удалось сформировать ZIP-архив с трафиком.")
            return

        window_end_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(window_end))
        message = (
            f"Обнаружена аномалия в окне, заканчивающемся в {window_end_str}. "
            f"В архиве {len(packets_for_zip)} пакетов за последние "
            f"{config.detection.traffic_log_minutes} минут."
        )

        ok = send_zip_to_server(zip_path, config.detection.alert_server_url, message)
        if ok:
            print(f"Архив с трафиком отправлен на {config.detection.alert_server_url}: {zip_path}")
        else:
            print(
                f"Не удалось отправить архив на {config.detection.alert_server_url}. "
                f"Файл сохранён локально: {zip_path}"
            )
    
    try:
        capture.capture_packets_continuous(process_packet)
    except KeyboardInterrupt:
        print(f"\n\nОстановлено пользователем")
        print(f"Всего обработано: {total_count}")
        print(f"Аномалий обнаружено: {anomaly_count}")


def print_anomaly(result: dict):
    """
    Вывод информации об аномалии в консоль.
    
    Args:
        result: Словарь с результатом детекции
    """
    print("\n" + "!" * 60)
    print("ОБНАРУЖЕНА АНОМАЛИЯ")
    print("!" * 60)
    
    window_start = result.get('window_start', 0)
    window_end = result.get('window_end', 0)
    duration = result.get('duration', 0)

    # Форматируем время с миллисекундами для точности
    start_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(window_start))
    end_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(window_end))

    # Добавляем миллисекунды
    start_ms = int((window_start % 1) * 1000)
    end_ms = int((window_end % 1) * 1000)

    print(f"Временное окно: {start_str}.{start_ms:03d} - {end_str}.{end_ms:03d}")
    print(f"Длительность окна: {duration:.3f} секунд (ожидается: {window_end - window_start:.3f})")
    print(f"Количество пакетов: {result.get('packet_count', 0)}")
    print(f"Пакетов в секунду: {result.get('packets_per_second', 0):.2f}")
    print(f"Уникальных IP источников: {result.get('unique_src_ip', 0)}")
    print(f"Уникальных IP назначения: {result.get('unique_dst_ip', 0)}")
    print(f"Уникальных портов источников: {result.get('unique_src_port', 0)}")
    print(f"Уникальных портов назначения: {result.get('unique_dst_port', 0)}")
    print(f"Средняя длина пакета: {result.get('avg_length', 0):.2f} байт")
    print(f"Протокол TCP: {result.get('proto_tcp', 0)} пакетов")
    print(f"Протокол UDP: {result.get('proto_udp', 0)} пакетов")
    print(f"Протокол ICMP: {result.get('proto_icmp', 0)} пакетов")
    
    print(f"Оценка аномальности: {result.get('anomaly_score', 0):.4f}")
    print("!" * 60 + "\n")


def main():
    """Главная функция с парсингом аргументов командной строки."""
    parser = argparse.ArgumentParser(
        description='Детекция аномалий в сетевом трафике с использованием обучения без учителя',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--interface', '-i',
        type=str,
        default=config.training.interface,
        help=f'Имя сетевого интерфейса (по умолчанию: {config.training.interface})'
    )
    
    parser.add_argument(
        '--mode', '-m',
        type=str,
        choices=['train', 'detect'],
        required=True,
        help='Режим работы: train (обучение) или detect (детекция)'
    )
    
    parser.add_argument(
        '--model', '-M',
        type=str,
        default=config.training.model_path,
        help=f'Путь к файлу модели (по умолчанию: {config.training.model_path})'
    )
    
    parser.add_argument(
        '--duration', '-d',
        type=int,
        default=config.training.duration_minutes,
        help=(
            'Длительность обучения в минутах (только для режима train, '
            f'по умолчанию: {config.training.duration_minutes})'
        )
    )
    
    parser.add_argument(
        '--window-size', '-w',
        type=float,
        default=config.training.window_size_seconds,
        help=(
            'Размер временного окна в секундах (используется в обоих режимах, '
            f'по умолчанию: {config.training.window_size_seconds})'
        )
    )

    parser.add_argument(
        '--score-threshold', '-t',
        type=float,
        default=config.detection.score_threshold,
        help=(
            'Порог по anomaly_score для детекции (None = использовать бинарное предсказание). '
            'Чем ниже порог, тем выше чувствительность. Для Isolation Forest обычно -0.5 до 0.0'
        )
    )
    
    args = parser.parse_args()
    
    # Проверка режима
    if args.mode == 'train':
        train_model(
            interface=args.interface,
            duration_minutes=args.duration,
            window_size=args.window_size,
            model_path=args.model
        )
    elif args.mode == 'detect':
        if not os.path.exists(args.model):
            print(f"Ошибка: Файл модели {args.model} не найден.")
            print("Сначала выполните обучение с --mode train")
            sys.exit(1)
        
        detect_anomalies(
            interface=args.interface,
            model_path=args.model,
            window_size=args.window_size,
            score_threshold=args.score_threshold
        )


if __name__ == '__main__':
    main()
