import http.server
import socketserver
import subprocess
from urllib.parse import urlparse, unquote_plus
import os
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

CGI_SCRIPT_PATH = "./cgi-bin/debug32.cgi"

QEMU_BINARY_PATH = os.environ.get("QEMU_PATH", "/usr/bin/qemu-arm")
ARM_LIBC_DIRECTORY_PATH = os.environ.get("ARM_LIBC_PATH", "/usr/arm-linux-gnueabihf")

class ThreadedCGIHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass

class CGIRequestHandler(http.server.SimpleHTTPRequestHandler):
    cgi_directories = ["/cgi-bin"]

    def do_GET(self):
        parsed_url = urlparse(self.path)
        request_path = parsed_url.path

        allowed_cgi_script = "/cgi-bin/debug32.cgi"

        if request_path == allowed_cgi_script:
            self.run_cgi_script()
        elif request_path == '/' or request_path == '/index.html':
            self.serve_index_html()
        else:
            super().do_GET() 

    def serve_index_html(self):
        original_path = self.path
        self.path = '/index.html'
        try:
            super().do_GET()
        finally:
            self.path = original_path

    def run_cgi_script(self):
        script_request_path = self.path
        query_start_index = script_request_path.find('?', 1)
        if query_start_index >= 0:
            query_string_raw = script_request_path[query_start_index:]
            script_request_path = script_request_path[:query_start_index]
        else:
            query_string_raw = ""
        
        translated_script_path = self.translate_path(script_request_path)
        if not os.path.isfile(translated_script_path):
            self.send_error(404, "CGI script not found")
            return
        if not os.access(translated_script_path, os.X_OK):
            self.send_error(403, "CGI script is not executable")
            return

        environment_variables = os.environ.copy()
        environment_variables['SERVER_SOFTWARE'] = self.version_string()
        environment_variables['SERVER_NAME'] = self.server.server_name
        environment_variables['GATEWAY_INTERFACE'] = 'CGI/1.1'
        environment_variables['SERVER_PROTOCOL'] = self.protocol_version
        environment_variables['SERVER_PORT'] = str(self.server.server_port)
        environment_variables['REQUEST_METHOD'] = self.command
        environment_variables['PATH_INFO'] = translated_script_path
        environment_variables['PATH_TRANSLATED'] = translated_script_path
        environment_variables['SCRIPT_NAME'] = script_request_path

        if query_string_raw:
            if query_string_raw[0] == '?':
                query_string_decoded_part = query_string_raw[1:]
            else:
                query_string_decoded_part = query_string_raw

            try:
                decoded_query_string = unquote_plus(query_string_decoded_part, encoding='latin-1')
                environment_variables['QUERY_STRING'] = decoded_query_string
                logging.debug(f"Server decoded QUERY_STRING from '{query_string_raw}' to '{decoded_query_string}'")
            except Exception as e:
                logging.error(f"Error decoding QUERY_STRING on server side: {e}. Using raw string.")
                environment_variables['QUERY_STRING'] = query_string_raw
        else:
            environment_variables['QUERY_STRING'] = ""

        environment_variables['REMOTE_ADDR'] = self.client_address[0]
        environment_variables['REMOTE_HOST'] = self.address_string()
        environment_variables['CONTENT_LENGTH'] = ''
        environment_variables['HTTP_ACCEPT'] = self.headers.get('Accept','')
        environment_variables['HTTP_USER_AGENT'] = self.headers.get('User-Agent','')
        environment_variables['HTTP_CONTENT_TYPE'] = self.headers.get('Content-Type','')

        self.execute_cgi_script(translated_script_path, environment_variables)

    def execute_cgi_script(self, script_to_execute_path, env_vars):
        command = [QEMU_BINARY_PATH, "-L", ARM_LIBC_DIRECTORY_PATH, script_to_execute_path]
        try:
            logging.debug(f"CGI script command: {command}")
            process = subprocess.Popen(command,
                                       shell=False,
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       env=env_vars)
            self.log_message("CGI script started: %s", " ".join(command))
            stdout_output, stderr_output = process.communicate(timeout=300)
            logging.debug(f"CGI script stdout:\n{stdout_output.decode()}")
            logging.debug(f"CGI script stderr:\n{stderr_output.decode()}")
            self.log_message("CGI script finished (status %s)", process.returncode)

            stdout_decoded = stdout_output.decode()
            headers_part = ""
            body_part = stdout_decoded

            if "\n\n" in stdout_decoded:
                parts = stdout_decoded.split("\n\n", 1)
                headers_part = parts[0] + "\n\n"
                body_part = parts[1]

            self.send_response(200)
            if "Content-Type:" in headers_part:
                content_type_line = [line for line in headers_part.splitlines() if "Content-Type:" in line][0]
                self.send_header(content_type_line.split(":")[0].strip(), content_type_line.split(":")[1].strip())
            else:
                self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(body_part.encode())
            self.wfile.write(stderr_output)

            if process.returncode != 0:
                self.log_error(f"CGI script exited with status {process.returncode}: {command}")

        except TimeoutError:
            self.log_error("CGI script timed out: %s", " ".join(command))
            process.kill()
            self.send_error(500, "CGI script timed out")
        except OSError as e:
            self.log_error("CGI script error: %s", e)
            self.send_error(500, "CGI script error")

if __name__ == "__main__":
    SERVER_PORT = 1004
    
    HandlerClass = CGIRequestHandler
    http_daemon = ThreadedCGIHTTPServer(("", SERVER_PORT), HandlerClass)

    if not os.path.exists("./cgi-bin"):
        os.makedirs("./cgi-bin")

    print(f"Serving CGI on port {SERVER_PORT} with multi-threading...")
    try:
        http_daemon.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        http_daemon.server_close()