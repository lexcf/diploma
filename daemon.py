"""
Запуск детектора аномалий как службы (Windows) или демона (Linux).

  Linux (требуются права root для захвата пакетов):
      sudo python daemon.py install           # установить и запустить systemd-сервис
      sudo python daemon.py start             # запустить демон в фоне
      sudo python daemon.py stop              # остановить демон
      sudo python daemon.py status            # проверить статус
      sudo python daemon.py remove            # остановить и удалить systemd-сервис

  Windows (от имени администратора):
      python daemon.py install   # зарегистрировать службу
      python daemon.py start     # запустить службу
      python daemon.py stop      # остановить службу
      python daemon.py remove    # удалить службу
      python daemon.py debug     # запустить интерактивно (для отладки)

Все параметры (интерфейс, длительность обучения, пути к файлам и т.д.)
берутся из config.py.
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


_SYSTEMD_UNIT = "anomaly_detector"
_SYSTEMD_UNIT_PATH = f"/etc/systemd/system/{_SYSTEMD_UNIT}.service"


def _build_unit_content(pid_file: str) -> str:
    python = sys.executable
    script = os.path.abspath(__file__)
    return f"""\
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


def _linux_install(pid_file: str) -> None:
    import subprocess
    unit_content = _build_unit_content(pid_file)
    try:
        with open(_SYSTEMD_UNIT_PATH, "w") as f:
            f.write(unit_content)
        print(f"Записан unit-файл: {_SYSTEMD_UNIT_PATH}")
    except PermissionError:
        print(f"Ошибка: нет прав на запись в {_SYSTEMD_UNIT_PATH}. Запустите с sudo.")
        sys.exit(1)

    for cmd in (
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", _SYSTEMD_UNIT],
    ):
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"Ошибка при выполнении: {' '.join(cmd)}")
            sys.exit(result.returncode)

    print(f"Служба '{_SYSTEMD_UNIT}' установлена и запущена.")
    print(f"Тип запуска: Автоматически (WantedBy=multi-user.target)")


def _linux_remove(pid_file: str) -> None:
    import subprocess
    for cmd in (
        ["systemctl", "disable", "--now", _SYSTEMD_UNIT],
    ):
        subprocess.run(cmd)  # не прерываем, даже если сервис не был активен

    try:
        os.remove(_SYSTEMD_UNIT_PATH)
        print(f"Удалён unit-файл: {_SYSTEMD_UNIT_PATH}")
    except FileNotFoundError:
        print(f"Unit-файл не найден: {_SYSTEMD_UNIT_PATH}")
    except PermissionError:
        print(f"Ошибка: нет прав на удаление {_SYSTEMD_UNIT_PATH}. Запустите с sudo.")
        sys.exit(1)

    subprocess.run(["systemctl", "daemon-reload"])
    print(f"Служба '{_SYSTEMD_UNIT}' удалена.")


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


def _run_windows() -> None:
    if not _PYWIN32_OK:
        print(
            "Для регистрации Windows-службы установите пакет pywin32:\n"
            "    pip install pywin32\n"
            "    python -m pywin32_postinstall -install"
        )
        sys.exit(1)

    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else ""

    if cmd in ("install", "--install"):
        # Регистрируем python.exe как исполняемый файл службы — это надёжнее, чем
        # PythonService.exe, которому нужно искать модуль через реестр.
        try:
            import win32service
            script_path = os.path.abspath(__file__)
            binary_path = f'"{sys.executable}" "{script_path}" _svc_run'
            sc = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_CREATE_SERVICE
            )
            try:
                hsvc = win32service.CreateService(
                    sc,
                    _SVC_NAME,
                    _SVC_DISPLAY,
                    win32service.SERVICE_ALL_ACCESS,
                    win32service.SERVICE_WIN32_OWN_PROCESS,
                    win32service.SERVICE_AUTO_START,
                    win32service.SERVICE_ERROR_NORMAL,
                    binary_path,
                    None, 0, None, None, None,
                )
                win32service.CloseServiceHandle(hsvc)
            finally:
                win32service.CloseServiceHandle(sc)
            print(f"Служба '{_SVC_DISPLAY}' установлена")
            print("Тип запуска службы: Автоматически")
        except Exception as exc:
            print(f"Ошибка при установке службы: {exc}")
            sys.exit(1)

    elif cmd == "_svc_run":
        # Точка входа, которую SCM запускает при старте службы.
        import servicemanager as _sm
        _sm.Initialize()
        _sm.PrepareToHostSingle(_AnomalyDetectorService)
        _sm.StartServiceCtrlDispatcher()

    elif cmd in ("debug", "--debug"):
        print(f"Debugging service {_SVC_NAME} - press Ctrl+C to stop.")
        os.chdir(SCRIPT_DIR)
        from service import run_service
        try:
            run_service()
        except KeyboardInterrupt:
            print("\nОстановлено.")

    else:
        # start / stop / remove — просто команды к SCM, импорт модуля не нужен
        _w32svc.HandleCommandLine(_AnomalyDetectorService)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    if sys.platform == "win32":
        _run_windows()
        return

    import config
    pid_file = config.service.pid_file
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""

    commands = {
        "install": lambda: _linux_install(pid_file),
        "start":   lambda: _linux_start(pid_file),
        "stop":    lambda: _linux_stop(pid_file),
        "status":  lambda: _linux_status(pid_file),
        "remove":  lambda: _linux_remove(pid_file),
    }

    if cmd in commands:
        commands[cmd]()
    else:
        print(__doc__)
        sys.exit(0 if not cmd else 1)


if __name__ == "__main__":
    main()
