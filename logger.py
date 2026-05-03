"""
Настройка логгера: вывод в терминал и в файл одновременно.
"""

import logging
import sys


def setup_logger(log_file: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("anomaly_detector")
    if logger.handlers:
        return logger

    logger.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger
