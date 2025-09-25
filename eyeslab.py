from flask import Flask, request, render_template_string, session, redirect, url_for, flash
from datetime import datetime
import sqlite3
import hashlib
import os
import re
import subprocess
import requests
import pickle
import base64

app = Flask(__name__)
app.secret_key = 'eyestracklab_secret_key_2024'

# ================== CONFIGURAÇÃO DO BANCO ==================
def init_db():
    conn = sqlite3.connect('eyestracklab.db')
    c = conn.cursor()
    
    # Tabela de usuários
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, level INTEGER, score INTEGER)''')
    
    # Tabela de desafios
    c.execute('''CREATE TABLE IF NOT EXISTS challenges
                 (id INTEGER PRIMARY KEY, title TEXT, description TEXT, difficulty TEXT, flag TEXT, points INTEGER)''')
    
    # Tabela de conquistas
    c.execute('''CREATE TABLE IF NOT EXISTS achievements
                 (id INTEGER PRIMARY KEY, user_id INTEGER, challenge_id INTEGER, timestamp TEXT)''')
    
    # Tabela de logs (vulnerável a SQLi)
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY, ip TEXT, user_agent TEXT, page TEXT, timestamp TEXT)''')
    
    # Inserir usuário admin padrão
    c.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
    if c.fetchone()[0] == 0:
        # Senha MD5 hash de "eyestrackadmin123"
        c.execute("INSERT INTO users (username, password, level, score) VALUES (?, ?, ?, ?)",
                  ('admin', '7c6b2c4e7c6e48b2c4e7c6e48b2c4e7c6', 10, 1000))
    
    # Inserir usuário teste com senha fraca
    c.execute("INSERT OR IGNORE INTO users (username, password, level, score) VALUES (?, ?, ?, ?)",
              ('test', 'test123', 1, 0))
    
    # Inserir desafios padrão
    challenges = [
        ('SQL Injection Login', 'Bypass de autenticação usando SQL Injection. Payload: \' OR 1=1 --', 'Fácil', 'FLAG{SQLi_EyesTrackLab}', 100),
        ('XSS Refletido', 'Execute XSS no campo de busca. Payload: <script>alert("XSS")</script>', 'Médio', 'FLAG{XSS_EyesTrackLab}', 250),
        ('Força Bruta', 'Quebre a senha do usuário "test" usando força bruta', 'Fácil', 'FLAG{Brute_Force_EyesTrackLab}', 150),
        ('Directory Traversal', 'Acesse /etc/passwd usando path traversal', 'Difícil', 'FLAG{Path_Traversal_EyesTrackLab}', 500),
        ('Quebra de Hash MD5', 'Decifre a senha MD5 do administrador', 'Médio', 'FLAG{MD5_Cracked_EyesTrackLab}', 300),
        ('SQL Injection UNION', 'Extraia dados com UNION SELECT. Payload: \' UNION SELECT username, password, NULL FROM users --', 'Difícil', 'FLAG{UNION_SQLi_EyesTrackLab}', 450),
        ('Comando de Sistema', 'RCE no endpoint /terminal. Comando: whoami', 'Crítico', 'FLAG{RCE_EyesTrackLab}', 750),
        ('SSRF', 'Acesse recursos internos via /internal. URL: file:///etc/passwd', 'Difícil', 'FLAG{SSRF_EyesTrackLab}', 500),
        ('LFI', 'Inclusão de arquivo local via /files. Path: ../../etc/passwd', 'Médio', 'FLAG{LFI_EyesTrackLab}', 350),
        ('Insecure Deserialization', 'Explore desserialização insegura em /decode', 'Crítico', 'FLAG{Deserialization_EyesTrackLab}', 800)
    ]
    
    c.execute("SELECT COUNT(*) FROM challenges")
    if c.fetchone()[0] == 0:
        for challenge in challenges:
            c.execute("INSERT INTO challenges (title, description, difficulty, flag, points) VALUES (?, ?, ?, ?, ?)",
                      challenge)
    
    conn.commit()
    conn.close()

init_db()

# ================== HTML BASE ==================
base_html = """
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>
    body {{
      background: #0c0c0c;
      color: #00ff00;
      font-family: 'Courier New', monospace;
      margin: 0;
      padding: 20px;
      background-image: linear-gradient(rgba(0,0,0,0.9), rgba(0,0,0,0.9)), 
                        url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100"><rect width="100" height="100" fill="none"/><path d="M0,0L100,100M100,0L0,100" stroke="rgba(0,80,0,0.3)" stroke-width="1"/></svg>');
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
      border: 1px solid #00ff00;
      padding: 20px;
      background: rgba(0, 20, 0, 0.8);
      box-shadow: 0 0 20px #00ff00;
    }}
    .header {{
      text-align: center;
      padding: 20px;
      border-bottom: 2px solid #00ff00;
      margin-bottom: 30px;
    }}
    h1 {{
      color: #00ff00;
      text-shadow: 0 0 10px #00ff00;
      font-family: 'Consolas', monospace;
    }}
    h2 {{
      color: #ffffff;
      border-left: 4px solid #00ff00;
      padding-left: 10px;
      font-family: 'Consolas', monospace;
    }}
    h3 {{
      color: #00ff00;
      font-family: 'Consolas', monospace;
    }}
    .subtitle {{
      color: #ff6600;
      text-align: center;
      font-family: 'Consolas', monospace;
      margin-top: -15px;
      margin-bottom: 30px;
    }}
    .nav {{
      display: flex;
      justify-content: center;
      gap: 15px;
      margin-bottom: 30px;
      flex-wrap: wrap;
      padding: 15px;
      background: rgba(0, 30, 0, 0.5);
      border: 1px solid #00ff00;
    }}
    .nav a {{
      color: #00ff00;
      text-decoration: none;
      padding: 10px 20px;
      border: 1px solid #00ff00;
      border-radius: 3px;
      transition: all 0.3s;
      font-family: 'Consolas', monospace;
    }}
    .nav a:hover {{
      background: #00ff00;
      color: #000;
    }}
    .card {{
      background: rgba(0, 15, 0, 0.9);
      padding: 20px;
      border: 1px solid #00ff00;
      margin-bottom: 20px;
      border-radius: 3px;
    }}
    .challenge {{
      margin-bottom: 15px;
      padding: 15px;
      border-left: 4px solid #00ff00;
      background: rgba(0, 25, 0, 0.5);
    }}
    .challenge.completed {{
      border-color: #00cc00;
      background: rgba(0, 50, 0, 0.3);
      opacity: 0.8;
    }}
    .challenge.completed .flag-form {{
      display: none;
    }}
    .challenge.completed::before {{
      content: "✅ CONCLUÍDO";
      display: block;
      color: #00cc00;
      font-weight: bold;
      margin-bottom: 10px;
    }}
    .easy {{
      border-color: #00ff00;
    }}
    .medium {{
      border-color: #ffff00;
    }}
    .hard {{
      border-color: #ff6600;
    }}
    .critical {{
      border-color: #ff0000;
      animation: glow 2s infinite alternate;
    }}
    @keyframes glow {{
      from {{ box-shadow: 0 0 5px #ff0000; }}
      to {{ box-shadow: 0 0 20px #ff0000; }}
    }}
    .form-input {{
      width: 100%;
      padding: 12px;
      margin: 10px 0;
      border: 1px solid #00ff00;
      background: rgba(0, 0, 0, 0.7);
      color: #00ff00;
      font-family: 'Courier New', monospace;
      font-size: 14px;
      outline: none;
    }}
    .btn {{
      padding: 12px 25px;
      background: #00ff00;
      color: #000;
      font-weight: bold;
      border: none;
      border-radius: 3px;
      cursor: pointer;
      transition: 0.3s;
      margin: 5px;
      font-family: 'Consolas', monospace;
    }}
    .btn:hover {{
      background: #007700;
      color: #00ff00;
    }}
    .btn-danger {{
      background: #ff0000;
      color: #000;
    }}
    .btn-danger:hover {{
      background: #770000;
      color: #ff0000;
    }}
    .leaderboard {{
      width: 100%;
      border-collapse: collapse;
      border: 1px solid #00ff00;
    }}
    .leaderboard th, .leaderboard td {{
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #00ff00;
      font-family: 'Courier New', monospace;
    }}
    .leaderboard th {{
      background: rgba(0, 255, 0, 0.1);
    }}
    .leaderboard tr:hover {{
      background: rgba(0, 255, 0, 0.05);
    }}
    .flag-form {{
      display: flex;
      gap: 10px;
      margin-top: 10px;
    }}
    .message {{
      padding: 15px;
      margin: 15px 0;
      border-radius: 3px;
      border: 1px solid;
      font-family: 'Courier New', monospace;
    }}
    .success {{
      background: rgba(0, 255, 0, 0.1);
      border-color: #00ff00;
      color: #00ff00;
    }}
    .error {{
      background: rgba(255, 0, 0, 0.1);
      border-color: #ff0000;
      color: #ff0000;
    }}
    .warning {{
      background: rgba(255, 255, 0, 0.1);
      border-color: #ffff00;
      color: #ffff00;
    }}
    .user-info {{
      position: absolute;
      top: 20px;
      right: 20px;
      color: #00ff00;
      background: rgba(0, 0, 0, 0.8);
      padding: 10px;
      border: 1px solid #00ff00;
      border-radius: 3px;
      font-family: 'Courier New', monospace;
      font-size: 12px;
    }}
    .footer {{
      text-align: center;
      margin-top: 50px;
      font-size: 12px;
      color: #007700;
      font-family: 'Courier New', monospace;
    }}
    .search-form {{
      margin: 20px 0;
      display: flex;
      gap: 10px;
    }}
    .log-entry {{
      font-family: 'Courier New', monospace;
      font-size: 12px;
      margin: 5px 0;
      padding: 5px;
      background: rgba(0, 255, 0, 0.05);
      border-left: 2px solid #00ff00;
    }}
    .terminal {{
      background: #000;
      color: #00ff00;
      padding: 15px;
      border: 1px solid #00ff00;
      font-family: 'Courier New', monospace;
      height: 300px;
      overflow-y: auto;
      margin: 15px 0;
    }}
    .terminal pre {{
      margin: 0;
      white-space: pre-wrap;
    }}
    .flag-reveal {{
      background: rgba(0, 255, 0, 0.1);
      border: 2px solid #00ff00;
      padding: 20px;
      margin: 20px 0;
      text-align: center;
      animation: pulse 3s infinite;
    }}
    @keyframes pulse {{
      0% {{ border-color: #00ff00; }}
      50% {{ border-color: #ffffff; }}
      100% {{ border-color: #00ff00; }}
    }}
    .tools-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 15px;
      margin-top: 20px;
    }}
    .tool-btn {{
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 20px;
      background: rgba(0, 30, 0, 0.5);
      border: 1px solid #00ff00;
      border-radius: 5px;
      text-decoration: none;
      color: #00ff00;
      transition: all 0.3s;
      text-align: center;
    }}
    .tool-btn:hover {{
      background: #00ff00;
      color: #000;
      transform: translateY(-2px);
    }}
    .tool-icon {{
      font-size: 24px;
      margin-bottom: 10px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔍 EyesTrackLab</h1>
      <div class="subtitle">
        <p>Hacktivismo Brasileiro - Linux Players</p>
        <p>Laboratório de Pentest e Segurança Cibernética</p>
      </div>
    </div>
    
    {user_info}
    
    <div class="nav">
      {nav_links}
    </div>
    
    {content}
    
    <div class="footer">
      <p>🔒 EyesTrackLab Security Research - Linux Players Community</p>
      <p>📍 Brasil - Secure Server v3.0</p>
    </div>
  </div>
</body>
</html>
"""

# ================== PÁGINAS ==================
login_page = """
<div class="card">
  <h2>🔐 ACESSO AO LABORATÓRIO</h2>
  <form method="POST">
    <input class="form-input" type="text" name="username" placeholder="USUÁRIO" required>
    <input class="form-input" type="password" name="password" placeholder="SENHA" required>
    <input class="btn" type="submit" value="ACESSAR SISTEMA">
  </form>
  <div class="challenge easy">
    <h3>💡Sql bypass</h3>
    <p></p>
    <code>'</code><br>
    <code>'</code>
  </div>
</div>

<div class="card">
  <h2>📋 NOVO CADASTRO</h2>
  <form method="POST" action="/register">
    <input class="form-input" type="text" name="username" placeholder="NOVO USUÁRIO" required>
    <input class="form-input" type="password" name="password" placeholder="NOVA SENHA" required>
    <input class="btn" type="submit" value="CRIAR CONTA">
  </form>
</div>
"""

dashboard_page = """
<div class="card">
  <h2>📊 PAINEL DE CONTROLE - {username}</h2>
  <div class="terminal">
    <pre>
USUÁRIO: {username}
NÍVEL: {level}
PONTUAÇÃO: {score} PONTOS
STATUS: ATIVO
ÚLTIMO ACESSO: {timestamp}
    </pre>
  </div>
</div>

<div class="card">
  <h2>🎯 MISSÕES ATIVAS</h2>
  {challenges_list}
</div>

<div class="card">
  <h2>🏆 MISSÕES CONCLUÍDAS</h2>
  {completed_challenges}
</div>

<div class="card">
  <h2>⚔️ FERRAMENTAS DE PENTEST</h2>
  <p>Ferramentas autorizadas para testes de penetração:</p>
  <div class="tools-grid">
    <a class="tool-btn" href="/search">
      <div class="tool-icon">🔍</div>
      <span>PESQUISA VULNERÁVEL</span>
    </a>
    <a class="tool-btn" href="/terminal">
      <div class="tool-icon">💻</div>
      <span>TERMINAL DO SISTEMA</span>
    </a>
    <a class="tool-btn" href="/internal">
      <div class="tool-icon">🌐</div>
      <span>REDE INTERNA</span>
    </a>
    <a class="tool-btn" href="/files">
      <div class="tool-icon">📁</div>
      <span>EXPLORADOR DE ARQUIVOS</span>
    </a>
    <a class="tool-btn" href="/decode">
      <div class="tool-icon">🔓</div>
      <span>DECODIFICADOR</span>
    </a>
  </div>
</div>
"""

# ================== ROTAS ==================
@app.route("/", methods=["GET", "POST"])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == "POST":
        user = request.form.get("username")
        pwd = request.form.get("password")
        
        # VULNERABILIDADE: SQL Injection no login
        conn = sqlite3.connect('eyestracklab.db')
        c = conn.cursor()
        
        query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
        c.execute(query)
        user_data = c.fetchone()
        conn.close()

        if user_data:
            session['user_id'] = user_data[0]
            session['username'] = user_data[1]
            session['level'] = user_data[3]
            session['score'] = user_data[4]
            
            # Se SQL Injection foi usado, revelar flag
            if "' OR" in user or "--" in user:
                flash("🚨 SQL Injection detectado! Flag capturada: FLAG{SQLi_EyesTrackLab}", "success")
            
            return redirect(url_for('dashboard'))
        else:
            flash("❌ ACESSO NEGADO: Credenciais inválidas", "error")
    
    return render_base("EyesTrackLab - Login", login_page)

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    
    if not username or not password:
        flash("❌ Dados de registro inválidos", "error")
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('eyestracklab.db')
    c = conn.cursor()
    
    try:
        c.execute("INSERT INTO users (username, password, level, score) VALUES (?, ?, ?, ?)",
                 (username, password, 1, 0))
        conn.commit()
        flash("✅ Usuário registrado com sucesso. Você pode fazer login agora.", "success")
    except sqlite3.IntegrityError:
        flash("❌ Nome de usuário já existe", "error")
    finally:
        conn.close()
    
    return redirect(url_for('login'))

@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('eyestracklab.db')
    c = conn.cursor()
    
    # Buscar desafios concluídos
    c.execute('''SELECT c.id, c.title, a.timestamp 
                 FROM achievements a 
                 JOIN challenges c ON a.challenge_id = c.id 
                 WHERE a.user_id = ?''', (session['user_id'],))
    completed = c.fetchall()
    
    completed_html = "<ul>"
    for challenge in completed:
        completed_html += f"<li>✅ {challenge[1]} - {challenge[2]}</li>"
    completed_html += "</ul>"
    
    if completed_html == "<ul></ul>":
        completed_html = "<p>🔄 Nenhuma missão concluída ainda</p>"
    
    # Buscar todos os desafios
    c.execute("SELECT * FROM challenges")
    challenges = c.fetchall()
    
    # Buscar IDs dos desafios concluídos pelo usuário
    c.execute('''SELECT challenge_id FROM achievements WHERE user_id = ?''', (session['user_id'],))
    completed_ids = [row[0] for row in c.fetchall()]
    
    challenges_html = ""
    for challenge in challenges:
        difficulty_class = challenge[3].lower()
        is_completed = challenge[0] in completed_ids
        completed_class = "completed" if is_completed else ""
        
        challenges_html += f"""
        <div class="challenge {difficulty_class} {completed_class}">
            <h3>🎯 {challenge[1]} - [{challenge[3]}] ({challenge[5]}pts)</h3>
            <p>{challenge[2]}</p>
            """
        
        if not is_completed:
            challenges_html += f"""
            <form class="flag-form" method="POST" action="/submit_flag">
                <input type="hidden" name="challenge_id" value="{challenge[0]}">
                <input class="form-input" type="text" name="flag" placeholder="DIGITE A FLAG" required>
                <button class="btn" type="submit">ENVIAR FLAG</button>
            </form>
            """
        
        challenges_html += "</div>"
    
    conn.close()
    
    dashboard_content = dashboard_page.format(
        username=session['username'],
        level=session['level'],
        score=session['score'],
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        completed_challenges=completed_html,
        challenges_list=challenges_html
    )
    
    return render_base("EyesTrackLab - Dashboard", dashboard_content, get_nav_links())

@app.route("/search")
def search():
    query = request.args.get('q', '')
    results = ""
    
    if query:
        # VULNERABILIDADE: XSS e SQL Injection
        results += f"<h3>🔍 RESULTADOS DA PESQUISA: {query}</h3>"
        
        conn = sqlite3.connect('eyestracklab.db')
        c = conn.cursor()
        
        try:
            sql = f"SELECT id, title, description FROM challenges WHERE title LIKE '%{query}%' OR description LIKE '%{query}%'"
            c.execute(sql)
            challenges = c.fetchall()
            
            for challenge in challenges:
                results += f"<div class='challenge'><h4>{challenge[1]}</h4><p>{challenge[2]}</p></div>"
                
        except Exception as e:
            results += f"<div class='message error'>Erro no banco de dados: {str(e)}</div>"
        
        conn.close()
        
        # Se XSS foi detectado, revelar flag
        if "<script>" in query.lower():
            results += f"""
            <div class="flag-reveal">
                <h3>🚨 XSS DETECTADO!</h3>
                <p>Flag capturada: FLAG{{XSS_EyesTrackLab}}</p>
            </div>
            """
    
    search_html = f"""
    <div class="card">
        <h2>🔍 PESQUISA VULNERÁVEL</h2>
        <form class="search-form" method="GET">
            <input class="form-input" type="text" name="q" placeholder="DIGITE SUA CONSULTA" value="{query}">
            <button class="btn" type="submit">PESQUISAR</button>
        </form>
        {results}
        <div class="challenge medium">
            <h3>💡 TREINAMENTO: XSS & SQLi</h3>
            <p>Teste os payloads:</p>
            <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
            <code>' UNION SELECT username, password FROM users --</code>
        </div>
    </div>
    """
    
    return render_base("EyesTrackLab - Pesquisa", search_html, get_nav_links())

@app.route("/terminal", methods=["GET", "POST"])
def terminal():
    output = ""
    command = ""
    
    if request.method == "POST":
        command = request.form.get("command", "")
        if command:
            try:
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
                output = f"<pre>$ {command}\n{result}</pre>"
                
                # Se RCE foi bem sucedido, revelar flag
                if command.strip():
                    output += f"""
                    <div class="flag-reveal">
                        <h3>🚨 RCE EXECUTADO COM SUCESSO!</h3>
                        <p>Flag capturada: FLAG{{RCE_EyesTrackLab}}</p>
                    </div>
                    """
                    
            except subprocess.TimeoutExpired:
                output = "<div class='message error'>Comando expirado</div>"
            except Exception as e:
                output = f"<div class='message error'>Erro: {str(e)}</div>"
    
    terminal_html = f"""
    <div class="card">
        <h2>💻 TERMINAL DO SISTEMA</h2>
        <form method="POST">
            <input class="form-input" type="text" name="command" placeholder="DIGITE O COMANDO" value="{command}" required>
            <button class="btn" type="submit">EXECUTAR</button>
        </form>
        <div class="terminal">{output}</div>
        <div class="challenge critical">
            <h3>⚠️ AVISO: VULNERABILIDADE RCE</h3>
            <p>Teste os comandos:</p>
            <code>whoami</code><br>
            <code>ls -la</code><br>
            <code>cat /etc/passwd</code>
        </div>
    </div>
    """
    
    return render_base("EyesTrackLab - Terminal", terminal_html, get_nav_links())

@app.route("/internal", methods=["GET", "POST"])
def internal():
    url = ""
    content = ""
    
    if request.method == "POST":
        url = request.form.get("url", "")
        if url:
            try:
                response = requests.get(url, timeout=5)
                content = f"<pre>{response.text[:1000]}</pre>"
                
                # Se SSRF foi bem sucedido, revelar flag
                if "file://" in url or "localhost" in url:
                    content += f"""
                    <div class="flag-reveal">
                        <h3>🚨 EXPLORAÇÃO SSRF BEM-SUCEDIDA!</h3>
                        <p>Flag capturada: FLAG{{SSRF_EyesTrackLab}}</p>
                    </div>
                    """
                    
            except Exception as e:
                content = f"<div class='message error'>Erro: {str(e)}</div>"
    
    internal_html = f"""
    <div class="card">
        <h2>🌐 ACESSO À REDE INTERNA</h2>
        <form method="POST">
            <input class="form-input" type="text" name="url" placeholder="DIGITE A URL" value="{url}" required>
            <button class="btn" type="submit">ACESSAR</button>
        </form>
        {content}
        <div class="challenge hard">
            <h3>💡 TREINAMENTO: SSRF</h3>
            <p>Teste as URLs:</p>
            <code>file:///etc/passwd</code><br>
            <code>http://localhost</code><br>
            <code>http://127.0.0.1:8080</code>
        </div>
    </div>
    """
    
    return render_base("EyesTrackLab - Rede Interna", internal_html, get_nav_links())

@app.route("/files")
def files():
    page = request.args.get('page', 'logs')
    content = ""
    
    try:
        if page == 'logs':
            conn = sqlite3.connect('eyestracklab.db')
            c = conn.cursor()
            c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 10")
            logs = c.fetchall()
            
            for log in logs:
                content += f"<div class='log-entry'>[{log[4]}] {log[1]} - {log[3]}</div>"
            conn.close()
        else:
            # Tentativa de LFI
            with open(f"/tmp/{page}", "r") as f:
                content = f"<pre>{f.read()}</pre>"
                
            # Se LFI foi bem sucedido, revelar flag
            content += f"""
            <div class="flag-reveal">
                <h3>🚨 EXPLORAÇÃO LFI BEM-SUCEDIDA!</h3>
                <p>Flag capturada: FLAG{{LFI_EyesTrackLab}}</p>
            </div>
            """
            
    except:
        content = "<div class='message error'>Erro ao acessar arquivos</div>"
    
    files_html = f"""
    <div class="card">
        <h2>📁 EXPLORADOR DE ARQUIVOS</h2>
        <div class="nav">
            <a href="/files?page=logs" class="btn">LOGS DE ACESSO</a>
            <a href="/files?page=../../etc/passwd" class="btn">ARQUIVOS DO SISTEMA</a>
        </div>
        {content}
        <div class="challenge medium">
            <h3>💡 TREINAMENTO: LFI</h3>
            <p>Teste os caminhos:</p>
            <code>../../etc/passwd</code><br>
            <code>../../../etc/hosts</code>
        </div>
    </div>
    """
    
    return render_base("EyesTrackLab - Arquivos", files_html, get_nav_links())

@app.route("/submit_flag", methods=["POST"])
def submit_flag():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    challenge_id = request.form.get("challenge_id")
    flag = request.form.get("flag")
    
    conn = sqlite3.connect('eyestracklab.db')
    c = conn.cursor()
    
    c.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,))
    challenge = c.fetchone()
    
    if challenge and flag == challenge[4]:
        c.execute('''SELECT * FROM achievements WHERE user_id=? AND challenge_id=?''', 
                 (session['user_id'], challenge_id))
        if not c.fetchone():
            c.execute('''INSERT INTO achievements (user_id, challenge_id, timestamp)
                         VALUES (?, ?, ?)''', 
                         (session['user_id'], challenge_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            
            new_score = session['score'] + challenge[5]
            new_level = new_score // 100 + 1
            
            c.execute('''UPDATE users SET score=?, level=? WHERE id=?''', 
                     (new_score, new_level, session['user_id']))
            
            conn.commit()
            
            session['score'] = new_score
            session['level'] = new_level
            
            flash(f"✅ FLAG CAPTURADA! +{challenge[5]} pontos: {challenge[4]}", "success")
        else:
            flash("⚠️ Missão já concluída", "warning")
    else:
        flash("❌ FLAG INVÁLIDA", "error")
    
    conn.close()
    return redirect(url_for('dashboard'))

@app.route("/logout")
def logout():
    session.clear()
    flash("🔒 Sessão encerrada", "info")
    return redirect(url_for('login'))

# ================== FUNÇÕES AUXILIARES ==================
def render_base(title, content, nav_links="", messages=""):
    flash_messages = ""
    if 'flash_messages' in session:
        for category, message in session.pop('flash_messages'):
            flash_messages += f"<div class='message {category}'>{message}</div>"
    
    user_info = ""
    if 'username' in session:
        user_info = f"""<div class="user-info">
            🕵️ {session['username']} | ⭐ {session['score']} | 🎯 Nível {session['level']}
            <a href="/logout" style="color: #ff0000; margin-left: 10px;">SAIR</a>
        </div>"""
    
    return base_html.format(
        title=title,
        user_info=user_info,
        nav_links=nav_links,
        content=flash_messages + content
    )

def get_nav_links():
    links = [
        ("/dashboard", "📊 PAINEL"),
        ("/search", "🔍 PESQUISA"),
        ("/terminal", "💻 TERMINAL"),
    ]
    
    nav_html = ""
    for link in links:
        nav_html += f'<a href="{link[0]}">{link[1]}</a>'
    
    return nav_html

def flash(message, category="info"):
    if 'flash_messages' not in session:
        session['flash_messages'] = []
    session['flash_messages'].append((category, message))
    session.modified = True

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
