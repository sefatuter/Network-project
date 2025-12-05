from flask import Flask, request, send_file
import os

# Bu script Flask kullanir ve Gunicorn ile tam uyumludur.
# Calistirmak icin terminale: gunicorn --bind 0.0.0.0:8080 server:app

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    """Ana sayfada senin yukledigin index.html dosyasini sunar."""
    try:
        # Kodun calistigi klasordeki index.html dosyasini bulur
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, 'index.html')
        return send_file(file_path)
    except FileNotFoundError:
        return "index.html dosyasi server.py ile ayni dizinde bulunamadi!", 404

@app.route('/login', methods=['POST'])
def login():
    """Login POST istegini karsilar ve sonucu gosterir."""
    # Form verilerini al
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Senin index.html tasariminla uyumlu Sonuc Sayfasi HTML'i
    result_html = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <title>Login Successful</title>
      <style>
        :root {{
          --bg-gradient: radial-gradient(at 0% 0%, hsla(253,16%,7%,1) 0, transparent 50%), 
                         radial-gradient(at 50% 0%, hsla(225,39%,30%,1) 0, transparent 50%), 
                         radial-gradient(at 100% 0%, hsla(339,49%,30%,1) 0, transparent 50%);
          --bg-base: #0f172a;
          --card-bg: rgba(255, 255, 255, 0.95);
          --text-main: #1e293b;
          --text-muted: #64748b;
          --primary: #4f46e5;
          --primary-hover: #4338ca;
          --radius-lg: 16px;
          --shadow-card: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }}

        * {{ box-sizing: border-box; }}

        body {{
          margin: 0;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: 'Inter', system-ui, -apple-system, sans-serif;
          background-color: var(--bg-base);
          background-image: var(--bg-gradient);
          color: var(--text-main);
          padding: 20px;
        }}

        .page {{ width: 100%; max-width: 440px; }}

        .card {{
          background: var(--card-bg);
          backdrop-filter: blur(12px);
          border-radius: var(--radius-lg);
          padding: 40px;
          box-shadow: var(--shadow-card);
          border: 1px solid rgba(255, 255, 255, 0.1);
          text-align: center;
          animation: slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }}
        
        @keyframes slideUp {{
          from {{ transform: translateY(20px); opacity: 0; }}
          to {{ transform: translateY(0); opacity: 1; }}
        }}

        h2 {{ margin: 0 0 10px 0; color: var(--text-main); font-size: 22px; }}
        p {{ color: var(--text-muted); font-size: 14px; margin-bottom: 24px; }}

        .data-box {{
          background: #f1f5f9;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          padding: 16px;
          text-align: left;
          margin-bottom: 24px;
          font-family: monospace;
          font-size: 14px;
          color: #334155;
          overflow-x: auto;
        }}
        
        .data-row {{ margin-bottom: 8px; display: flex; flex-direction: column; }}
        .data-row strong {{ color: var(--primary); margin-bottom: 4px; }}
        .data-row span {{ word-break: break-all; }}
        .data-row:last-child {{ margin-bottom: 0; }}

        .btn {{
          display: inline-block;
          text-decoration: none;
          width: 100%;
          padding: 14px;
          border-radius: 8px;
          background: var(--primary);
          color: white;
          font-weight: 600;
          font-size: 15px;
          transition: all 0.2s;
          border: none;
          cursor: pointer;
        }}
        .btn:hover {{ background: var(--primary-hover); transform: translateY(-1px); }}
        
        .icon-success {{
          width: 48px; height: 48px;
          background: #dcfce7; color: #166534;
          border-radius: 50%;
          display: flex; align-items: center; justify-content: center;
          margin: 0 auto 16px auto;
        }}
      </style>
    </head>
    <body>
      <main class="page">
        <div class="card">
          <div class="icon-success">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
          </div>
          
          <h2>Credentials Captured!</h2>
          <p>The HTTP POST request was successful.</p>
          
          <div class="data-box">
            <div class="data-row">
              <strong>Username:</strong>
              <span>{username}</span>
            </div>
            <div class="data-row">
              <strong>Password:</strong>
              <span>{password}</span>
            </div>
          </div>

          <a href="/" class="btn">Return to Login</a>
        </div>
      </main>
    </body>
    </html>
    """
    return result_html

if __name__ == "__main__":
    # Bu blok SADECE 'python3 server.py' dediginde calisir.
    # Gunicorn ile calistirdiginda bu blok calismaz, boylece 'Address already in use' hatasi almazsin.
    app.run(host='0.0.0.0', port=8080)