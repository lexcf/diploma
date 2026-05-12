"""
Логика режима службы/демона: обучение с сохранением состояния между перезагрузками,
затем непрерывная детекция аномалий.

Жизненный цикл:
  1. Если существует state_file — продолжить прерванное обучение.
  2. Если существует model_path и нет state_file — сразу перейти к детекции.
  3. Иначе — начать обучение с нуля.
  После завершения обучения state_file удаляется и начинается детекция.
"""

import json
import os
import signal
import sys
import time
import threading
from typing import Dict, List, Optional

from packet_capture import PacketCapture
from aggregation import TimeWindowAggregator
from anomaly_detector import AnomalyDetector
from alerting import TrafficLogger, build_zip_from_packets, send_zip_to_server
from anomaly_metadata_db import AnomalyMetadataLogger
from logger import setup_logger
import config


# ─── State persistence ────────────────────────────────────────────────────────

def _load_state(path: str) -> Optional[Dict]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _save_state(path: str, elapsed: float, windows: List[Dict]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"elapsed_seconds": elapsed, "aggregated_windows": windows}, f)
    os.replace(tmp, path)


# ─── Public entry point ───────────────────────────────────────────────────────

def run_service() -> None:
    cfg = config.service
    # Переходим в директорию скрипта, чтобы относительные пути в config работали корректно
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    log = setup_logger(cfg.log_file_path)
    total_seconds = cfg.training_duration_minutes * 60

    # --- Определяем фазу запуска ---
    state = _load_state(cfg.state_file)
    model_ready = os.path.exists(cfg.model_path)

    if state is not None:
        elapsed_before: float = state.get("elapsed_seconds", 0.0)
        aggregated_data: List[Dict] = state.get("aggregated_windows", [])
        remaining = total_seconds - elapsed_before
        if remaining > 0:
            log.info(
                "Восстановление обучения: прошло %.0f с из %.0f с, осталось %.0f с",
                elapsed_before, total_seconds, remaining,
            )
        else:
            log.info("Файл состояния найден: обучение уже завершено, обучаем модель")
            remaining = 0.0
    elif model_ready:
        log.info("Модель найдена (%s), обучение пропущено", cfg.model_path)
        detector = AnomalyDetector()
        detector.load(cfg.model_path)
        _run_detection(cfg, detector, log)
        return
    else:
        elapsed_before = 0.0
        aggregated_data = []
        remaining = total_seconds
        log.info(
            "Первый запуск: обучение %d мин на интерфейсе %s",
            cfg.training_duration_minutes, cfg.interface,
        )

    # --- Фаза обучения ---
    if remaining > 0:
        capture = PacketCapture(cfg.interface)
        aggregator = TimeWindowAggregator(window_size=cfg.window_size_seconds)
        session_start = time.time()

        def on_packet(packet: Dict) -> None:
            completed = aggregator.add_packet(packet)
            if completed:
                aggregated_data.extend(completed)
                elapsed_total = elapsed_before + (time.time() - session_start)
                _save_state(cfg.state_file, elapsed_total, aggregated_data)
                last = completed[-1]
                log.info(
                    "Обучение: окон=%d, прошло=%.0f с из %.0f с | "
                    "последнее окно: пакетов=%d, pps=%.1f",
                    len(aggregated_data), elapsed_total, total_seconds,
                    last.get("packet_count", 0), last.get("packets_per_second", 0.0),
                )

        log.info("Захват трафика для обучения: %.0f с", remaining)
        capture.capture_packets(max(1, int(remaining)), callback=on_packet)

        tail = aggregator.flush()
        aggregated_data.extend(tail)
        elapsed_total = elapsed_before + (time.time() - session_start)
        _save_state(cfg.state_file, elapsed_total, aggregated_data)
        log.info("Фаза обучения завершена: %d окон за %.1f с", len(aggregated_data), elapsed_total)

    # --- Обучение модели ---
    if not aggregated_data:
        log.error("Нет данных для обучения модели. Завершение.")
        return

    detector = AnomalyDetector(contamination=config.model.contamination)
    try:
        detector.train(aggregated_data)
        detector.save(cfg.model_path)
        log.info("Модель сохранена: %s", cfg.model_path)
    except Exception as exc:
        log.error("Ошибка при обучении модели: %s", exc)
        return

    try:
        os.remove(cfg.state_file)
    except OSError:
        pass

    log.info("Переход в режим детекции")
    _run_detection(cfg, detector, log)


# ─── Detection loop ───────────────────────────────────────────────────────────

def _run_detection(cfg, detector: AnomalyDetector, log) -> None:
    capture = PacketCapture(cfg.interface)
    aggregator = TimeWindowAggregator(window_size=cfg.window_size_seconds)
    traffic_logger = TrafficLogger(retention_minutes=config.detection.traffic_log_minutes)

    metadata_logger = None
    if config.detection.log_anomalies_to_sqlite:
        try:
            metadata_logger = AnomalyMetadataLogger(config.detection.anomalies_sqlite_path)
        except Exception as exc:
            log.warning("Не удалось инициализировать SQLite-логгер: %s", exc)

    stats = {"total": 0, "since_last": 0, "last_ts": time.time()}
    stop_event = threading.Event()

    def _stats_loop() -> None:
        while not stop_event.wait(config.detection.log_stats_interval):
            now = time.time()
            elapsed = now - stats["last_ts"]
            pps = stats["since_last"] / elapsed if elapsed > 0 else 0.0
            log.info(
                "Статистика: за %.0f с перехвачено %d пакетов (%.1f пак/с), всего %d",
                elapsed, stats["since_last"], pps, stats["total"],
            )
            stats["since_last"] = 0
            stats["last_ts"] = now

    threading.Thread(target=_stats_loop, daemon=True).start()

    def on_packet(packet: Dict) -> None:
        stats["total"] += 1
        stats["since_last"] += 1
        traffic_logger.add_packet(packet)
        completed = aggregator.add_packet(packet)
        if completed:
            for result in detector.predict(completed):
                log.info(
                    "Окно: пакетов=%d, pps=%.1f, score=%.4f%s",
                    result.get("packet_count", 0),
                    result.get("packets_per_second", 0.0),
                    result.get("anomaly_score", 0.0),
                    " [АНОМАЛИЯ]" if result["is_anomaly"] else "",
                )
                if result["is_anomaly"]:
                    _handle_anomaly(result, traffic_logger, metadata_logger, cfg, detector, log)

    def _on_sigterm(signum, frame) -> None:
        stop_event.set()
        log.info("Получен SIGTERM. Детекция остановлена. Всего пакетов: %d", stats["total"])
        raise SystemExit(0)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _on_sigterm)

    try:
        capture.capture_packets_continuous(on_packet)
    except (KeyboardInterrupt, SystemExit):
        stop_event.set()
        log.info("Детекция остановлена. Всего пакетов: %d", stats["total"])


def _handle_anomaly(result, traffic_logger, metadata_logger, cfg, detector, log) -> None:
    ws = result.get("window_start", 0)
    we = result.get("window_end", 0)
    log.warning(
        "АНОМАЛИЯ: окно %s – %s | score=%.4f | пакетов=%d | pps=%.2f"
        " | src_ip=%d | dst_ip=%d | TCP=%d UDP=%d ICMP=%d",
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ws)),
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(we)),
        result.get("anomaly_score", 0),
        result.get("packet_count", 0),
        result.get("packets_per_second", 0),
        result.get("unique_src_ip", 0),
        result.get("unique_dst_ip", 0),
        result.get("proto_tcp", 0),
        result.get("proto_udp", 0),
        result.get("proto_icmp", 0),
    )

    if metadata_logger:
        try:
            metadata_logger.log_anomaly(
                result=result,
                interface=cfg.interface,
                model_path=cfg.model_path,
                score_threshold=detector.score_threshold,
            )
        except Exception as exc:
            log.warning("Не удалось записать аномалию в SQLite: %s", exc)

    if not config.detection.send_zip_on_anomaly:
        return

    packets_for_zip = traffic_logger.get_recent_packets(we)
    if not packets_for_zip:
        return

    zip_path = build_zip_from_packets(packets_for_zip)
    if not zip_path:
        return

    message = (
        f"Аномалия в окне {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(we))}. "
        f"{len(packets_for_zip)} пакетов за последние {config.detection.traffic_log_minutes} мин."
    )
    if not send_zip_to_server(zip_path, config.detection.alert_server_url, message):
        log.warning("Не удалось отправить архив на %s", config.detection.alert_server_url)
