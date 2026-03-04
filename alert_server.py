"""
Простейший веб-сервер для приёма ZIP-архивов с логом трафика.

Используется для демонстрации: при получении аномалии от детектора
сервер выводит сообщение и сохраняет архив в каталог uploads/.
"""

from datetime import datetime
import os
from typing import List, Dict

from flask import Flask, jsonify, request, render_template_string, send_from_directory


app = Flask(__name__)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Память для списка полученных алертов за время работы сервера
alerts: List[Dict] = []


@app.route("/")
def index():
    """Простой UI для просмотра полученных алертов."""
    html = """
    <!doctype html>
    <html lang="ru">
    <head>
        <meta charset="utf-8">
        <title>Алерты аномалий</title>
        <style>
            body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                   margin: 2rem; background: #0b1020; color: #f5f7ff; }
            h1 { margin-bottom: 1rem; }
            table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
            th, td { border: 1px solid #333a55; padding: 0.4rem 0.6rem; font-size: 0.9rem; }
            th { background: #1b2240; }
            tr:nth-child(even) { background: #12172b; }
            tr:nth-child(odd) { background: #151a30; }
            a { color: #7dd3fc; }
            .msg { max-width: 480px; white-space: pre-wrap; }
            .meta { font-size: 0.85rem; color: #a0aec0; margin-bottom: 0.5rem; }
            .badge { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 999px;
                     background: #1d976c; color: #e6fffa; font-size: 0.75rem; margin-left: 0.5rem; }
        </style>
    </head>
    <body>
        <h1>Алерты аномалий</h1>
        <div class="meta">
            Получено алертов: {{ alerts|length }}
            <span class="badge">обновите страницу для новых</span>
        </div>
        {% if not alerts %}
            <p>Пока алертов нет. Запустите детектор и дождитесь срабатывания.</p>
        {% else %}
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Время (UTC)</th>
                    <th>Сообщение</th>
                    <th>Файл</th>
                </tr>
            </thead>
            <tbody>
            {% for a in alerts %}
                <tr>
                    <td>{{ loop.index }}</td>
                    <td>{{ a.ts }}</td>
                    <td class="msg">{{ a.message or "—" }}</td>
                    <td>
                        <a href="{{ url_for('download_upload', filename=a.filename) }}" target="_blank">
                            {{ a.filename }}
                        </a>
                    </td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
        {% endif %}
    </body>
    </html>
    """
    return render_template_string(html, alerts=alerts)


@app.route("/uploads/<path:filename>")
def download_upload(filename: str):
    """Выдача сохранённых архивов через HTTP."""
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)


@app.route("/anomaly", methods=["POST"])
def handle_anomaly():
    """Обработчик получения архива с логом трафика."""
    message = request.form.get("message", "")
    file = request.files.get("file")

    if file is None:
        return jsonify({"status": "error", "detail": "Файл не передан"}), 400

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}_{file.filename}"
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)

    alerts.append(
        {
            "ts": ts,
            "message": message,
            "filename": filename,
        }
    )

    print("=" * 60)
    print("ПОЛУЧЕНА АНОМАЛИЯ ОТ ДЕТЕКТОРА")
    if message:
        print(f"Сообщение: {message}")
    print(f"ZIP архив сохранён: {save_path}")
    print("=" * 60)

    return jsonify({"status": "ok", "saved_as": filename})


if __name__ == "__main__":
    # Запуск простого dev-сервера
    app.run(host="0.0.0.0", port=5000, debug=False)

