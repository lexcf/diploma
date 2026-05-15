"""
Глобальная конфигурация параметров детектора аномалий.

Пользователь может изменять значения ниже напрямую в этом файле
без необходимости передавать параметры через CLI.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class CommonConfig:
    """Базовые параметры, общие для всех режимов."""

    # Имя сетевого интерфейса
    interface: str = "eth0"
    # Размер временного окна агрегации в секундах
    window_size_seconds: float = 5.0
    # Путь к файлу модели
    model_path: str = "anomaly_model.pkl"
    # Путь к файлу лога
    log_file_path: str = "anomaly_detector.log"


@dataclass
class TrainingConfig:
    """Параметры режима обучения."""

    # Длительность обучения (захвата трафика) в минутах
    duration_minutes: int = 5


@dataclass
class DetectionConfig:
    """Параметры режима детекции (используются также в режиме службы)."""

    # Порог по anomaly_score (None = использовать бинарное предсказание модели)
    # Чем ниже значение, тем выше чувствительность.
    score_threshold: Optional[float] = None
    # Сколько минут трафика хранить для отправки на веб-сервер при аномалии
    traffic_log_minutes: int = 5
    # Хост сервера для отправки архивов (без схемы и пути, например: example.com)
    alert_server_host: str = ""
    # Bearer-токен для авторизации на сервере
    alert_bearer_token: str = "965134b0f26a8f663ae98c68b19847fbff3a0cd53e0a0aec39628b9cec400d1c"
    # Отправлять ли ZIP с трафиком при обнаружении аномалии
    send_zip_on_anomaly: bool = True
    # Логировать ли метаданные аномалий в локальную SQLite БД
    log_anomalies_to_sqlite: bool = True
    # Путь к локальной SQLite БД с метаданными аномалий
    anomalies_sqlite_path: str = "anomalies.db"
    # Интервал вывода статистики захваченных пакетов (секунды)
    log_stats_interval: int = 10


@dataclass
class ServiceConfig:
    """Параметры режима службы/демона."""

    # Суммарная длительность обучения в минутах (накапливается между перезапусками)
    training_duration_minutes: int = 30
    # Файл состояния обучения (сохраняется между перезагрузками)
    state_file: str = "service_training_state.json"
    # PID-файл (только Linux)
    pid_file: str = "/var/run/anomaly_detector.pid"


@dataclass
class ModelConfig:
    """Параметры модели Isolation Forest."""

    # Ожидаемая доля аномалий в обучающем наборе
    contamination: float = 0.01


# Экземпляры конфигураций, которые будут использоваться в коде
common = CommonConfig()
training = TrainingConfig()
detection = DetectionConfig()
service = ServiceConfig()
model = ModelConfig()
