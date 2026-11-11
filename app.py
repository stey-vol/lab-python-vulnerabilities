"""
Учебное веб-приложение с двумя намеренными уязвимостями (OWASP Top 10).

!!! ВНИМАНИЕ !!!
Это приложение специально сделано УЯЗВИМЫМ для лабораторной работы.
Запускать ТОЛЬКО локально. Никогда не выкладывать в интернет.

Уязвимость №1: SQL-инъекция (OWASP A03:2021 - Injection)
    В форме входа логин и пароль напрямую подставляются в SQL-запрос.

Уязвимость №2: Межсайтовый скриптинг / XSS (OWASP A03:2021 - Injection)
    Текст из гостевой книги выводится на страницу без экранирования.

Приложение написано на стандартной библиотеке Python (http.server + sqlite3),
поэтому НИЧЕГО устанавливать не нужно.
"""

import sqlite3
import os
import html
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

HOST = "127.0.0.1"
PORT = 8000
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab.db")


def init_db():
    """Создаёт базу данных и наполняет её тестовыми данными."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, author TEXT, text TEXT)")

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'SuperSecret_2024')")
        cur.execute("INSERT INTO users (username, password) VALUES ('anna', 'qwerty')")
        cur.execute("INSERT INTO comments (author, text) VALUES ('Админ', 'Добро пожаловать в гостевую книгу!')")

    con.commit()
    con.close()


PAGE = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>Учебный сайт — лабораторная по ИБ</title>
  <style>
    body {{ font-family: -apple-system, Arial, sans-serif; max-width: 640px; margin: 30px auto;
           padding: 0 16px; background: #f5f6f8; color: #222; }}
    h1 {{ font-size: 22px; }}
    .card {{ background: #fff; border: 1px solid #e2e4e8; border-radius: 10px;
            padding: 18px; margin-bottom: 20px; }}
    label {{ display: block; margin: 8px 0 4px; font-size: 14px; }}
    input, textarea {{ width: 100%; padding: 8px; border: 1px solid #ccc;
           border-radius: 6px; box-sizing: border-box; font-size: 14px; }}
    button {{ margin-top: 12px; padding: 9px 18px; border: 0; border-radius: 6px;
             background: #3b6fe0; color: #fff; font-size: 14px; cursor: pointer; }}
    .msg {{ padding: 10px; border-radius: 6px; margin-bottom: 14px; font-size: 14px; }}
    .ok {{ background: #e3f6e8; color: #1c6b34; }}
    .err {{ background: #fdecea; color: #a4271c; }}
    .comment {{ border-top: 1px solid #eee; padding: 8px 0; font-size: 14px; }}
    .comment b {{ color: #3b6fe0; }}
  </style>
</head>
<body>
  <h1>Личный кабинет</h1>
  {login_result}
  <div class="card">
    <h2>Вход в систему</h2>
    <form method="POST" action="/login">
      <label>Логин</label>
      <input name="username" placeholder="например, admin">
      <label>Пароль</label>
      <input name="password" type="password" placeholder="пароль">
      <button type="submit">Войти</button>
    </form>
  </div>

  <div class="card">
    <h2>Гостевая книга</h2>
    <form method="POST" action="/comment">
      <label>Ваше имя</label>
      <input name="author" placeholder="Имя">
      <label>Сообщение</label>
      <textarea name="text" rows="3" placeholder="Напишите что-нибудь..."></textarea>
      <button type="submit">Отправить</button>
    </form>
    <h3>Сообщения:</h3>
    {comments}
  </div>
</body>
</html>"""


def render_page(login_result="", comments_html=""):
    return PAGE.format(login_result=login_result, comments=comments_html)


def get_comments_html():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT author, text FROM comments ORDER BY id DESC")
    rows = cur.fetchall()
    con.close()

    parts = []
    for author, text in rows:
        # === УЯЗВИМОСТЬ №2: XSS ===
        # Текст подставляется в HTML БЕЗ экранирования (html.escape не вызывается).
        # Поэтому <script>...</script> из сообщения выполнится в браузере.
        parts.append('<div class="comment"><b>{}</b><br>{}</div>'.format(author, text))
    return "\n".join(parts)


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, code=200):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/"):
            self._send(render_page(comments_html=get_comments_html()))

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        form = parse_qs(raw, keep_blank_values=True)
        return {k: v[0] for k, v in form.items()}

    def do_POST(self):
        if self.path == "/login":
            self.handle_login()
        elif self.path == "/comment":
            self.handle_comment()
        else:
            self._send("Not found", 404)

    def handle_login(self):
        form = self._read_form()
        username = form.get("username", "")
        password = form.get("password", "")

        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        # === УЯЗВИМОСТЬ №1: SQL-инъекция ===
        # Данные пользователя напрямую вклеиваются в текст запроса.
        # Ввод  ' OR '1'='1  ломает логику условия и пускает без пароля.
        query = "SELECT username FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
        print("[SQL]", query)  # для наглядности видно в консоли
        try:
            cur.execute(query)
            row = cur.fetchone()
        except Exception as e:
            row = None
            print("[SQL ERROR]", e)
        con.close()

        if row:
            result = '<div class="msg ok">Вход выполнен! Добро пожаловать, <b>{}</b>.</div>'.format(row[0])
        else:
            result = '<div class="msg err">Неверный логин или пароль.</div>'
        self._send(render_page(login_result=result, comments_html=get_comments_html()))

    def handle_comment(self):
        form = self._read_form()
        author = form.get("author", "") or "Аноним"
        text = form.get("text", "")

        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        # Здесь запрос параметризован (безопасно) — комментарий просто сохраняется.
        cur.execute("INSERT INTO comments (author, text) VALUES (?, ?)", (author, text))
        con.commit()
        con.close()
        self._send(render_page(comments_html=get_comments_html()))

    def log_message(self, *args):
        pass  # отключаем шумные логи сервера


if __name__ == "__main__":
    init_db()
    print("Учебный сервер запущен: http://{}:{}".format(HOST, PORT))
    print("Остановить: Ctrl + C")
    HTTPServer((HOST, PORT), Handler).serve_forever()
