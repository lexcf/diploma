"""
Запуск детектора аномалий как службы (Windows) или демона (Linux).

  Linux (требуются права root для захвата пакетов):
      sudo python daemon.py start             # запустить демон в фоне
      sudo python daemon.py stop              # остановить демон
      sudo python daemon.py status            # проверить статус
      sudo python daemon.py generate-systemd  # вывести unit-файл для systemd

  Windows (от имени администратора):
      python daemon.py install   # зарегистрировать службу
      python daemon.py start     # запустить службу
      python daemon.py stop      # остановить службу
      python daemon.py remove    # удалить службу
      python daemon.py debug     # запустить интерактивно (для отладки)

Все параметры (интерфейс, длительность обучения, пути к файлам и т.д.)
берутся из config.py — раздел ServiceConfig.
"""

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)


# ─── Linux daemon ─────────────────────────────────────────────────────────────

def _daemonize(pid_file: str) -> None:
    """Классическое двойное ветвление (double-fork) для демонизации."""
    try:
        if os.fork() > 0:
            sys.exit(0)
    except OSError as exc:
        sys.exit(f"fork #1 не удался: {exc}")

    os.chdir("/")
    os.setsid()
    os.umask(0)

    try:
        if os.fork() > 0:
            sys.exit(0)
    except OSError as exc:
        sys.exit(f"fork #2 не удался: {exc}")

    # Перенаправляем stdin/stdout/stderr в /dev/null (логи пишутся через logging в файл)
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (sys.stdin.fileno(), sys.stdout.fileno(), sys.stderr.fileno()):
        os.dup2(devnull, fd)
    os.close(devnull)

    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))


def _read_pid(pid_file: str):
    try:
        with open(pid_file) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _linux_start(pid_file: str) -> None:
    import signal as _signal

    pid = _read_pid(pid_file)
    if pid:
        try:
            os.kill(pid, 0)
            print(f"Демон уже запущен (PID {pid})")
            return
        except OSError:
            pass  # устаревший PID-файл

    print("Запуск демона...")
    _daemonize(pid_file)

    def _on_sigterm(signum, frame) -> None:
        try:
            os.remove(pid_file)
        except OSError:
            pass
        sys.exit(0)

    _signal.signal(_signal.SIGTERM, _on_sigterm)

    from service import run_service
    run_service()


def _linux_stop(pid_file: str) -> None:
    import signal as _signal

    pid = _read_pid(pid_file)
    if not pid:
        print("Демон не запущен (PID-файл не найден)")
        return
    try:
        os.kill(pid, _signal.SIGTERM)
        print(f"Сигнал SIGTERM отправлен процессу {pid}")
    except ProcessLookupError:
        print(f"Процесс {pid} не найден (устаревший PID-файл)")
        try:
            os.remove(pid_file)
        except OSError:
            pass
    except PermissionError:
        print(f"Нет прав для остановки процесса {pid}")


def _linux_status(pid_file: str) -> None:
    pid = _read_pid(pid_file)
    if not pid:
        print("Демон не запущен (PID-файл отсутствует)")
        return
    try:
        os.kill(pid, 0)
        print(f"Демон запущен (PID {pid})")
    except OSError:
        print(f"Демон не запущен (устаревший PID-файл: {pid})")


def _generate_systemd(pid_file: str) -> None:
    import config as _cfg
    python = sys.executable
    script = os.path.abspath(__file__)
    unit = f"""\
[Unit]
Description=Anomaly Detector — детектор аномалий сетевого трафика
After=network.target

[Service]
Type=forking
PIDFile={pid_file}
ExecStart={python} {script} start
ExecStop={python} {script} stop
WorkingDirectory={SCRIPT_DIR}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    print(unit)
    print("# Установка:")
    print(f"#   sudo cp anomaly_detector.service /etc/systemd/system/")
    print(f"#   sudo systemctl daemon-reload")
    print(f"#   sudo systemctl enable --now anomaly_detector")


# ─── Windows service ──────────────────────────────────────────────────────────
# Класс должен быть на уровне модуля — pywin32 ищет его как daemon._AnomalyDetectorService

_SVC_NAME = "AnomalyDetector"
_SVC_DISPLAY = "Anomaly Detector"
_SVC_DESC = "Детектор аномалий сетевого трафика"

try:
    import win32serviceutil as _w32svc
    import win32service as _w32
    import win32event as _w32evt
    import servicemanager as _svcmgr
    import threading as _threading

    class _AnomalyDetectorService(_w32svc.ServiceFramework):
        _svc_name_ = _SVC_NAME
        _svc_display_name_ = _SVC_DISPLAY
        _svc_description_ = _SVC_DESC

        def __init__(self, args):
            _w32svc.ServiceFramework.__init__(self, args)
            self._stop_event = _w32evt.CreateEvent(None, 0, 0, None)
            self._thread = None

        def SvcStop(self):
            self.ReportServiceStatus(_w32.SERVICE_STOP_PENDING)
            _w32evt.SetEvent(self._stop_event)
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=15)

        def SvcDoRun(self):
            _svcmgr.LogMsg(
                _svcmgr.EVENTLOG_INFORMATION_TYPE,
                _svcmgr.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            os.chdir(SCRIPT_DIR)
            from service import run_service
            self._thread = _threading.Thread(target=run_service, daemon=True)
            self._thread.start()
            _w32evt.WaitForSingleObject(self._stop_event, _w32evt.INFINITE)

    _PYWIN32_OK = True

except ImportError:
    _PYWIN32_OK = False


def _set_python_path_in_registry() -> None:
    """Прописывает SCRIPT_DIR в реестр, чтобы SCM нашёл наш модуль при старте службы."""
    try:
        import win32api, win32con
        key_path = f"SYSTEM\\CurrentControlSet\\Services\\{_SVC_NAME}\\Parameters"
        key = win32api.RegCreateKey(win32con.HKEY_LOCAL_MACHINE, key_path)
        win32api.RegSetValueEx(key, "PythonPath", 0, win32con.REG_SZ, SCRIPT_DIR)
        win32api.RegCloseKey(key)
        print(f"PythonPath в реестре установлен: {SCRIPT_DIR}")
    except Exception as exc:
        print(f"Предупреждение: не удалось записать PythonPath в реестр: {exc}")


def _run_windows() -> None:
    if not _PYWIN32_OK:
        print(
            "Для регистрации Windows-службы установите пакет pywin32:\n"
            "    pip install pywin32\n"
            "    python -m pywin32_postinstall -install"
        )
        sys.exit(1)

    is_install = len(sys.argv) > 1 and sys.argv[1].lower() in ("install", "--install")
    try:
        _w32svc.HandleCommandLine(_AnomalyDetectorService)
    except SystemExit:
        if is_install:
            _set_python_path_in_registry()
        raise


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    if sys.platform == "win32":
        _run_windows()
        return

    import config
    pid_file = config.service.pid_file
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""

    commands = {
        "start": lambda: _linux_start(pid_file),
        "stop": lambda: _linux_stop(pid_file),
        "status": lambda: _linux_status(pid_file),
        "generate-systemd": lambda: _generate_systemd(pid_file),
    }

    if cmd in commands:
        commands[cmd]()
    else:
        print(__doc__)
        sys.exit(0 if not cmd else 1)


if __name__ == "__main__":
    main()
