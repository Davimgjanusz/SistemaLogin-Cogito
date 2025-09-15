from flask import Flask, render_template, request, redirect, send_from_directory, url_for, session, flash, jsonify
import sqlite3
import hashlib
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Altere para uma chave segura em produção

# Função para criar as tabelas no banco de dados
def init_db():
    # Conexão com o banco de login
    conn_login = sqlite3.connect('login.db')
    cursor_login = conn_login.cursor()
    cursor_login.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL
        )
    ''')
    conn_login.commit()
    conn_login.close()
    
    # Conexão com o banco de perfil
    conn_perfil = sqlite3.connect('perfil.db')
    cursor_perfil = conn_perfil.cursor()
    cursor_perfil.execute('''
        CREATE TABLE IF NOT EXISTS perfis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            escolaridade TEXT NOT NULL,
            nome_completo TEXT,
            data_nascimento TEXT,
            avatar TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    ''')
    conn_perfil.commit()
    conn_perfil.close()

# Função para hash de senha
def hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()

# Função para obter dados do perfil
def obter_perfil(usuario_id):
    conn = sqlite3.connect('perfil.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM perfis WHERE usuario_id = ?', (usuario_id,))
    perfil = cursor.fetchone()
    conn.close()
    
    if perfil:
        return {
            'id': perfil[0],
            'usuario_id': perfil[1],
            'username': perfil[2],
            'email': perfil[3],
            'escolaridade': perfil[4],
            'nome_completo': perfil[5] if len(perfil) > 5 else '',
            'data_nascimento': perfil[6] if len(perfil) > 6 else '',
            'avatar': perfil[7] if len(perfil) > 7 and perfil[7] else '👤'
        }
    return None

@app.route('/')
def index():
    if 'usuario_id' in session:
        perfil = obter_perfil(session['usuario_id'])
        return render_template('index.html', user=perfil)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['user']
        senha = request.form['pass']
        senha_hash = hash_senha(senha)
        
        # Verificar credenciais no banco de dados
        conn = sqlite3.connect('login.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE email = ? AND senha = ?', (email, senha_hash))
        usuario = cursor.fetchone()
        conn.close()
        
        if usuario:
            session['usuario_id'] = usuario[0]
            session['email'] = usuario[1]

            # Garante que o perfil existe
            perfil = obter_perfil(usuario[0])
            if not perfil:
                conn_perfil = sqlite3.connect('perfil.db')
                cursor_perfil = conn_perfil.cursor()
                cursor_perfil.execute(
                    'INSERT INTO perfis (usuario_id, username, email, escolaridade) VALUES (?, ?, ?, ?)',
                    (
                        usuario[0],  # ID do usuário
                        usuario[1].split('@')[0],  # usa parte do email como username
                        usuario[1],  # email
                        'Não informado'  # valor padrão caso não tenha escolaridade
                    )
                )
                conn_perfil.commit()
                conn_perfil.close()

            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))

        else:
            flash('Email ou senha incorretos!', 'danger')
    
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        confirmar_email = request.form['confirm-email']
        senha = request.form['password']
        confirmar_senha = request.form['confirm-password']
        escolaridade = request.form['escolaridade']
        
        # Verificar se os emails coincidem
        if email != confirmar_email:
            flash('Os emails não coincidem!', 'danger')
            return render_template('cadastro.html')
        
        # Verificar se as senhas coincidem
        if senha != confirmar_senha:
            flash('As senhas não coincidem!', 'danger')
            return render_template('cadastro.html')
        
        # Hash da senha
        senha_hash = hash_senha(senha)
        
        try:
            # Inserir no banco de login
            conn_login = sqlite3.connect('login.db')
            cursor_login = conn_login.cursor()
            cursor_login.execute('INSERT INTO usuarios (email, senha) VALUES (?, ?)', (email, senha_hash))
            usuario_id = cursor_login.lastrowid
            conn_login.commit()
            conn_login.close()
            
            # Inserir no banco de perfil
            conn_perfil = sqlite3.connect('perfil.db')
            cursor_perfil = conn_perfil.cursor()
            cursor_perfil.execute('INSERT INTO perfis (usuario_id, username, email, escolaridade) VALUES (?, ?, ?, ?)', 
                                 (usuario_id, username, email, escolaridade))
            conn_perfil.commit()
            conn_perfil.close()
            
            # Fazer login automaticamente após o cadastro
            session['usuario_id'] = usuario_id
            session['email'] = email
            
            flash('Cadastro realizado com sucesso!', 'success')
            return redirect(url_for('index'))
            
        except sqlite3.IntegrityError:
            flash('Este email já está cadastrado!', 'danger')
    
    return render_template('cadastro.html')

@app.route('/home')
def home():
    if 'usuario_id' not in session:
        flash('Faça login para acessar esta página.', 'warning')
        return redirect(url_for('login'))
    
    perfil = obter_perfil(session['usuario_id'])
    return render_template('index.html', user=perfil)

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('index'))

@app.route('/perfil')
def perfil():
    if 'usuario_id' not in session:
        flash('Faça login para acessar esta página.', 'warning')
        return redirect(url_for('login'))
    
    perfil = obter_perfil(session['usuario_id'])
    return render_template('perfil.html', user=perfil)

@app.route('/EditarPerfil', methods=['GET', 'POST'])
def editar_perfil():
    if 'usuario_id' not in session:
        flash('Faça login para acessar esta página.', 'warning')
        return redirect(url_for('login'))
    
    perfil = obter_perfil(session['usuario_id'])
    
    if request.method == 'POST':
        username = request.form['username']
        nome_completo = request.form['nome_completo']
        data_nascimento = request.form['data_nascimento']
        escolaridade = request.form['escolaridade']
        avatar = request.form.get('avatar', '👤')
        
        try:
            conn = sqlite3.connect('perfil.db')
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE perfis 
                SET username = ?, nome_completo = ?, data_nascimento = ?, escolaridade = ?, avatar = ?
                WHERE usuario_id = ?
            ''', (username, nome_completo, data_nascimento, escolaridade, avatar, session['usuario_id']))
            conn.commit()
            conn.close()
            
            flash('Perfil atualizado com sucesso!', 'success')
            return redirect(url_for('perfil'))
            
        except Exception as e:
            flash(f'Erro ao atualizar perfil: {str(e)}', 'danger')
    
    return render_template('EditarPerfil.html', user=perfil)

@app.route('/pagtcc')
def pagina_tcc():
    if 'usuario_id' not in session:
        flash('Faça login para acessar esta página.', 'warning')
        return redirect(url_for('login'))
    
    perfil = obter_perfil(session['usuario_id'])
    return render_template('pagtcc.html', user=perfil)

@app.route('/postagensacademicas')
def postagens_academicas():
    if 'usuario_id' not in session:
        flash('Faça login para acessar esta página.', 'warning')
        return redirect(url_for('login'))
    
    perfil = obter_perfil(session['usuario_id'])
    return render_template('postagensacademicas.html', user=perfil)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico')

# Rota para servir arquivos estáticos
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
