"""
Модуль для логирования трафика и отправки архивов на веб-сервер при обнаружении аномалий.
"""

from typing import Dict, List
import time
import os
import json
import zipfile

import requests


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

        # Гарантируем наличие метки времени
        packet = dict(packet)
        packet["timestamp"] = ts
        self._packets.append(packet)

        cutoff = ts - self.retention_seconds
        # Удаляем старые записи из начала списка
        idx = 0
        for idx, p in enumerate(self._packets):
            if p.get("timestamp", 0) >= cutoff:
                break
        else:
            # Все записи устарели
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
    Сериализует список пакетов в JSONL и упаковывает в ZIP-архив.

    Returns:
        Путь к созданному ZIP-файлу.
    """
    if not packets:
        return ""

    os.makedirs(output_dir, exist_ok=True)

    timestamp_str = time.strftime("%Y%m%d-%H%M%S")
    base_name = f"traffic_log_{timestamp_str}"
    json_path = os.path.join(output_dir, f"{base_name}.jsonl")

    with open(json_path, "w", encoding="utf-8") as f:
        for pkt in packets:
            f.write(json.dumps(pkt, ensure_ascii=False) + "\n")

    zip_path = os.path.join(output_dir, f"{base_name}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(json_path, arcname=os.path.basename(json_path))

    # Исходный json можно удалить, оставляем только архив
    os.remove(json_path)

    return zip_path


def send_zip_to_server(zip_path: str, url: str, message: str) -> bool:
    """
    Отправляет ZIP-архив на веб-сервер.

    Args:
        zip_path: Путь к ZIP-файлу.
        url: URL обработчика на веб-сервере.
        message: Текстовое сообщение, сопровождающее архив.

    Returns:
        True, если отправка завершилась успешно (код 2xx), иначе False.
    """
    if not zip_path or not os.path.exists(zip_path):
        return False

    if not url:
        return False

    try:
        with open(zip_path, "rb") as f:
            files = {"file": (os.path.basename(zip_path), f, "application/zip")}
            data = {"message": message}
            resp = requests.post(url, files=files, data=data, timeout=5)

        return 200 <= resp.status_code < 300
    except Exception as exc:  # noqa: BLE001
        print(f"Ошибка при отправке архива на {url}: {exc}")
        return False

