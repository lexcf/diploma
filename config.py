"""
Глобальная конфигурация параметров детектора аномалий.

Пользователь может изменять значения ниже напрямую в этом файле
без необходимости передавать параметры через CLI.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class TrainingConfig:
    """Параметры режима обучения."""

    # Имя сетевого интерфейса по умолчанию
    interface: str = "eth0"
    # Длительность обучения (захвата трафика) в минутах
    duration_minutes: int = 5
    # Размер временного окна агрегации в секундах
    window_size_seconds: float = 5.0
    # Путь к файлу модели
    model_path: str = "anomaly_model.pkl"


@dataclass
class DetectionConfig:
    """Параметры режима детекции."""

    # Имя сетевого интерфейса по умолчанию
    interface: str = "eth0"
    # Размер временного окна агрегации в секундах
    window_size_seconds: float = 5.0
    # Путь к файлу модели
    model_path: str = "anomaly_model.pkl"
    # Порог по anomaly_score (None = использовать бинарное предсказание модели)
    # Чем ниже значение, тем выше чувствительность.
    score_threshold: Optional[float] = None

    # Сколько минут трафика хранить для отправки на веб-сервер при аномалии
    traffic_log_minutes: int = 5
    # URL веб-сервера, на который отправляется ZIP с логом трафика
    alert_server_url: str = "http://127.0.0.1:5000/anomaly"
    # Отправлять ли ZIP с трафиком при обнаружении аномалии
    send_zip_on_anomaly: bool = True
    # Логировать ли метаданные аномалий в локальную SQLite БД
    log_anomalies_to_sqlite: bool = True
    # Путь к локальной SQLite БД с метаданными аномалий
    anomalies_sqlite_path: str = "anomalies.db"
    # Путь к файлу лога
    log_file_path: str = "anomaly_detector.log"
    # Интервал вывода статистики захваченных пакетов (секунды)
    log_stats_interval: int = 10


@dataclass
class ModelConfig:
    """Параметры модели Isolation Forest."""

    # Ожидаемая доля аномалий в обучающем наборе
    contamination: float = 0.01


@dataclass
class ServiceConfig:
    """Параметры режима службы/демона."""

    # Сетевой интерфейс
    interface: str = "eth0"
    # Суммарная длительность обучения в минутах (накапливается между перезапусками)
    training_duration_minutes: int = 30
    # Размер временного окна агрегации в секундах
    window_size_seconds: float = 5.0
    # Путь к файлу модели
    model_path: str = "anomaly_model.pkl"
    # Файл состояния обучения (сохраняется между перезагрузками)
    state_file: str = "service_training_state.json"
    # Путь к лог-файлу
    log_file_path: str = "anomaly_detector.log"
    # PID-файл (только Linux)
    pid_file: str = "/var/run/anomaly_detector.pid"


# Экземпляры конфигураций, которые будут использоваться в коде
training = TrainingConfig()
detection = DetectionConfig()
model = ModelConfig()
service = ServiceConfig()
