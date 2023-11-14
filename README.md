from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from srptools import SRPContext, SRPClientSession, constants

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = 'ваш_секретный_ключ'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Извлекаем данные о пользователе из базы данных
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            salt = user[2]  # Получаем соль пользователя из базы данных
            verifier = user[2]  # Получаем верификатор пользователя из базы данных

            context = SRPContext(constants.RFC5054_PARAMS)  # Создаем контекст SRP

            # Создаем клиентскую сессию SRP
            client = SRPClientSession(context, username, password, salt, verifier)

            # Выполняем процесс аутентификации
            client.process()

            if client.authenticated:
                # Если аутентификация прошла успешно, перенаправляем пользователя на страницу с секретом
                return redirect(url_for('index'))
            else:
                return "Неправильный логин или пароль."
        else:
            return "Неправильный логин или пароль."

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Получаем данные формы регистрации
        username = request.form['username']
        password = request.form['password']

        # Создаем контекст SRP
        context = SRPContext(constants.rfc5054_2048)

        # Создаем клиентскую сессию SRP для регистрации
        client = SRPClientSession(context, username, password)

        # Генерируем соль и верификатор
        salt, verifier = client.get_user_data()

        # Подключаемся к базе данных и выполняем операцию вставки
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, salt, verifier) VALUES (?, ?, ?, ?)", (username, password, salt, verifier))
        conn.commit()
        conn.close()

        # Перенаправляем пользователя на страницу входа после успешной регистрации
        return redirect(url_for('login'))

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
# -
у меня ошибка в конетексте SRP 
