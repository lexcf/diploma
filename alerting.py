"""
Модуль для логирования трафика и отправки архивов на сервер при обнаружении аномалий.
"""

import json
import logging
import os
import threading
import time
import zipfile
from typing import Dict, List

import requests

_log = logging.getLogger("anomaly_detector")


class TrafficLogger:
    """
    Хранит последние N минут трафика в памяти.
    """

    def __init__(self, retention_minutes: int = 5):
        self.retention_seconds = max(1, retention_minutes * 60)
        self._packets: List[Dict] = []

    def add_packet(self, packet: Dict) -> None:
        """Добавить пакет в лог и удалить устаревшие записи."""
        ts = float(packet.get("timestamp", time.time()))

        packet = dict(packet)
        packet["timestamp"] = ts
        self._packets.append(packet)

        cutoff = ts - self.retention_seconds
        idx = 0
        for idx, p in enumerate(self._packets):
            if p.get("timestamp", 0) >= cutoff:
                break
        else:
            self._packets.clear()
            return

        if idx > 0:
            self._packets = self._packets[idx:]

    def get_recent_packets(self, now_ts: float) -> List[Dict]:
        """Вернуть все пакеты за последние retention_minutes минут относительно now_ts."""
        cutoff = now_ts - self.retention_seconds
        return [p for p in self._packets if p.get("timestamp", 0) >= cutoff]


def build_zip_from_packets(packets: List[Dict], output_dir: str = ".") -> str:
    """
    Сериализует список пакетов в JSON и упаковывает в ZIP-архив.

    Returns:
        Путь к созданному ZIP-файлу или пустую строку при ошибке.
    """
    if not packets:
        return ""

    try:
        os.makedirs(output_dir, exist_ok=True)

        timestamp_str = time.strftime("%Y%m%d-%H%M%S")
        base_name = f"traffic_log_{timestamp_str}"
        json_path = os.path.join(output_dir, f"{base_name}.json")

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(packets, f, ensure_ascii=False, indent=2)

        zip_path = os.path.join(output_dir, f"{base_name}.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(json_path, arcname=os.path.basename(json_path))

        os.remove(json_path)
        return zip_path

    except Exception as exc:
        _log.error("Не удалось сформировать ZIP-архив с трафиком: %s", exc)
        return ""


def send_zip_to_server(zip_path: str, host: str, token: str) -> bool:
    """
    Отправляет ZIP-архив на сервер: POST https://<host>/api/agent/logs
    с Bearer-авторизацией и параметром archive в multipart/form-data.

    Returns:
        True при успешном ответе (2xx), иначе False.
    """
    if not zip_path or not os.path.exists(zip_path):
        _log.error("Файл архива не найден: %s", zip_path)
        return False

    if not host:
        _log.error("alert_server_host не задан в config.py")
        return False

    url = f"https://{host}/api/agent/logs"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        with open(zip_path, "rb") as f:
            files = {"archive": (os.path.basename(zip_path), f, "application/zip")}
            resp = requests.post(url, files=files, headers=headers, timeout=10)

        if 200 <= resp.status_code < 300:
            _log.info("Архив отправлен на %s: %d %s", url, resp.status_code, resp.text[:200])
            return True

        _log.error(
            "Сервер вернул ошибку %d при отправке архива на %s: %s",
            resp.status_code, url, resp.text[:200],
        )
        return False

    except requests.exceptions.ConnectionError as exc:
        _log.error("Не удалось подключиться к серверу %s: %s", url, exc)
    except requests.exceptions.Timeout:
        _log.error("Таймаут при отправке архива на %s", url)
    except Exception as exc:
        _log.error("Ошибка при отправке архива на %s: %s", url, exc)

    return False


class AnomalyCoalescer:
    """
    Группирует последовательные аномалии в одно событие.

    Вызывайте on_anomaly() для каждого аномального окна и on_normal_window()
    для каждого нормального. ZIP отправляется после QUIET_WINDOWS подряд
    идущих нормальных окон с момента последней аномалии.
    """

    QUIET_WINDOWS = 2

    def __init__(
        self,
        traffic_logger: "TrafficLogger",
        host: str,
        token: str,
    ) -> None:
        self._traffic_logger = traffic_logger
        self._host = host
        self._token = token
        self._count: int = 0
        self._quiet: int = 0
        self._last_we: float = 0.0

    def on_anomaly(self, result: Dict) -> None:
        self._count += 1
        self._quiet = 0
        self._last_we = result.get("window_end", time.time())

    def on_normal_window(self) -> None:
        if self._count == 0:
            return
        self._quiet += 1
        if self._quiet >= self.QUIET_WINDOWS:
            self._flush()

    def flush_remaining(self) -> None:
        """Принудительная отправка при завершении (Ctrl+C / SIGTERM)."""
        if self._count > 0:
            self._flush()

    def _flush(self) -> None:
        count = self._count
        last_we = self._last_we
        self._count = 0
        self._quiet = 0
        self._last_we = 0.0

        _log.info(
            "Отправка ZIP: группа из %d аномалий, конец события %s",
            count,
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_we)),
        )

        packets = self._traffic_logger.get_recent_packets(last_we)
        if not packets:
            _log.warning("Нет пакетов для архивации")
            return

        zip_path = build_zip_from_packets(packets)
        if zip_path:
            threading.Thread(
                target=send_zip_to_server,
                args=(zip_path, self._host, self._token),
                daemon=True,
            ).start()
