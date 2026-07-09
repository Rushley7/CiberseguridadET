from flask import Flask, request, render_template_string, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# CORRECCION VULN #5 (Ausencia de proteccion CSRF):
# CSRFProtect genera un token unico por sesion y lo valida en cada
# peticion POST/PUT/DELETE. Si el token no viene o no coincide (como
# pasaria con un formulario forjado en un sitio externo), la peticion
# se rechaza automaticamente con error 400.
csrf = CSRFProtect(app)

# CORRECCION VULN #4 (Cabeceras de seguridad HTTP faltantes):
# Flask no envia por defecto ninguna cabecera de proteccion contra
# clickjacking, sniffing de tipo MIME o inyeccion de recursos externos.
# Este middleware se ejecuta automaticamente en cada respuesta HTTP.
@app.after_request
def set_security_headers(response):
    # Mitiga: Content Security Policy (CSP) Header Not Set
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com; style-src 'self' https://maxcdn.bootstrapcdn.com; object-src 'none'; frame-ancestors 'self'; base-uri 'self'"
    # Mitiga: Missing Anti-clickjacking Header
    response.headers['X-Frame-Options'] = 'DENY'
    # Mitiga: X-Content-Type-Options Header Missing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Mitiga: Permissions Policy Header Not Set
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    # Mitiga: Cross-Origin-* Headers Missing or Invalid
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    # CORRECCION VULN #7 (Fuga de version del servidor):
    # Se sobrescribe la cabecera 'Server' que por defecto expone
    # 'Werkzeug/x.x.x Python/x.x.x', informacion util para un atacante
    # que busca exploits conocidos de esa version especifica.
    response.headers['Server'] = 'WebServer'
    return response



def get_db_connection():
    conn = sqlite3.connect('example.db')
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            <title>Welcome</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome to the Example Application!</h1>
                <p class="lead">This is the home page. Please <a href="/login">login</a>.</p>
            </div>
        </body>
        </html>
    ''')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()

        # CORRECCION VULN #1 (SQL Injection): consulta parametrizada.
        query = "SELECT * FROM users WHERE username = ?"
        user = conn.execute(query, (username,)).fetchone()
        conn.close()

        # CORRECCION VULN #2 (Hash debil): check_password_hash verifica
        # el password en texto plano contra el hash con salt guardado,
        # sin necesidad de recalcular ni exponer el algoritmo manualmente.
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template_string('''
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
                    <title>Login</title>
                </head>
                <body>
                    <div class="container">
                        <h1 class="mt-5">Login</h1>
                        <div class="alert alert-danger" role="alert">Invalid credentials!</div>
                        <form method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <div class="form-group">
                                <label for="username">Username</label>
                                <input type="text" class="form-control" id="username" name="username">
                            </div>
                            <div class="form-group">
                                <label for="password">Password</label>
                                <input type="password" class="form-control" id="password" name="password">
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                    </div>
                </body>
                </html>
            ''')
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            <title>Login</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Login</h1>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" class="form-control" id="password" name="password">
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </body>
        </html>
    ''')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    comments = conn.execute(
        "SELECT comment FROM comments WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()

    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            <title>Dashboard</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome, user {{ user_id }}!</h1>
                <form action="/submit_comment" method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <div class="form-group">
                        <label for="comment">Comment</label>
                        <textarea class="form-control" id="comment" name="comment" rows="3"></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Submit Comment</button>
                </form>
                <h2 class="mt-5">Your Comments</h2>
                <ul class="list-group">
                    {% for comment in comments %}
                        <li class="list-group-item">{{ comment['comment'] }}</li>
                    {% endfor %}
                </ul>
            </div>
        </body>
        </html>
    ''', user_id=user_id, comments=comments)


@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    comment = request.form['comment']
    user_id = session['user_id']

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO comments (user_id, comment) VALUES (?, ?)", (user_id, comment))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            <title>Admin Panel</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome to the admin panel!</h1>
            </div>
        </body>
        </html>
    ''')


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
