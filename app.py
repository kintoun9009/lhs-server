import ipaddress
import os
import re
import socket
from urllib.parse import urljoin, urlencode, urlparse

import requests
from flask import Flask, request, Response, abort, stream_with_context

app = Flask(__name__)

# ---------------------------------------------------------------
# Configurações
# ---------------------------------------------------------------
TIMEOUT = (10, 45)             # (connect, read)
CHUNK_SIZE = 64 * 1024         # 64 KB por chunk no streaming
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

# ---------------------------------------------------------------
# Whitelist de domínios permitidos
# ---------------------------------------------------------------
# ALLOWED_DOMAINS  -> domínios de ORIGEM que o proxy pode acessar
# ALLOWED_REFERERS -> domínios permitidos como REFERER (se o referer for enviado)
_env_allowed = os.environ.get("ALLOWED_DOMAINS", "").strip()
ALLOWED_DOMAINS = {
    d.strip().lower() for d in _env_allowed.split(",") if d.strip()
}

_env_referers = os.environ.get("ALLOWED_REFERERS", "").strip()
ALLOWED_REFERERS = {
    d.strip().lower() for d in _env_referers.split(",") if d.strip()
}


# ---------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------
def is_private_host(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return True
    return False


def host_matches(hostname: str, allowed: set) -> bool:
    hostname = hostname.lower()
    for d in allowed:
        if hostname == d or hostname.endswith("." + d):
            return True
    return False


def validate_url(url: str):
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        abort(403, "Somente http/https são permitidos")
    if not p.hostname:
        abort(403, "URL inválida")
    if ALLOWED_DOMAINS and not host_matches(p.hostname, ALLOWED_DOMAINS):
        abort(403, f"Domínio de origem não permitido: {p.hostname}")
    if is_private_host(p.hostname):
        abort(403, "Destino bloqueado (rede privada)")


def validate_referer(referer: str):
    """Só valida se o referer foi informado."""
    if not referer:
        return
    p = urlparse(referer)
    if not p.hostname:
        abort(403, "Referer inválido")
    if ALLOWED_REFERERS and not host_matches(p.hostname, ALLOWED_REFERERS):
        abort(403, f"Referer não permitido: {p.hostname}")


def build_referer(raw: str) -> str:
    if not raw:
        return ""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def proxy_url(abs_url: str, referer: str) -> str:
    params = {"url": abs_url}
    if referer:
        params["referer"] = referer
    return "/proxy?" + urlencode(params)


# ---------------------------------------------------------------
# Reescreve playlists M3U8
# ---------------------------------------------------------------
URI_ATTR_RE = re.compile(r'URI="([^"]+)"')


def rewrite_playlist(body: str, base_url: str, referer: str) -> str:
    out_lines = []
    for raw_line in body.splitlines():
        line = raw_line.strip()

        if not line:
            out_lines.append(raw_line)
            continue

        if line.startswith("#"):
            def repl(m):
                abs_u = urljoin(base_url, m.group(1))
                return f'URI="{proxy_url(abs_u, referer)}"'
            out_lines.append(URI_ATTR_RE.sub(repl, raw_line))
            continue

        abs_u = urljoin(base_url, line)
        out_lines.append(proxy_url(abs_u, referer))

    return "\n".join(out_lines) + "\n"


# ---------------------------------------------------------------
# Handler de erros
# ---------------------------------------------------------------
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(502)
def handle_http_error(e):
    return Response(
        f"Erro {e.code}: {e.description}\n",
        status=e.code,
        mimetype="text/plain",
        headers={"Access-Control-Allow-Origin": "*"},
    )


# ---------------------------------------------------------------
# Endpoint principal
# ---------------------------------------------------------------
@app.route("/proxy")
def proxy():
    target = request.args.get("url", "").strip()
    raw_referer = request.args.get("referer", "").strip()

    # url é obrigatório; referer é OPCIONAL
    if not target:
        abort(403, "Parâmetro 'url' é obrigatório")

    referer = build_referer(raw_referer)

    validate_url(target)
    validate_referer(referer)  # só valida se referer foi informado

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
    }
    # Só envia Referer/Origin se o cliente informou um referer.
    # Sem referer, o proxy se comporta como acesso anônimo.
    if referer:
        headers["Referer"] = referer
        p = urlparse(referer)
        headers["Origin"] = f"{p.scheme}://{p.netloc}"

    if request.headers.get("Range"):
        headers["Range"] = request.headers["Range"]

    try:
        upstream = requests.get(
            target, headers=headers, stream=True, timeout=TIMEOUT, allow_redirects=True
        )
    except requests.RequestException as e:
        abort(502, f"Falha ao acessar origem: {e}")

    content_type = upstream.headers.get("Content-Type", "").lower()

    # -------------------------
    # Caso 1: playlist HLS
    # -------------------------
    is_hls = (
        target.lower().split("?")[0].endswith((".m3u8", ".m3u"))
        or "mpegurl" in content_type
    )
    if is_hls:
        body = upstream.text
        base = upstream.url
        new_body = rewrite_playlist(body, base, referer)
        upstream.close()
        return Response(
            new_body,
            status=200,
            content_type="application/vnd.apple.mpegurl",
            headers={"Access-Control-Allow-Origin": "*"},
        )

    # -------------------------
    # Caso 2: segmento / mídia
    # -------------------------
    status = upstream.status_code
    resp_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges",
    }
    for h in ("Content-Length", "Content-Range", "Accept-Ranges", "Content-Type"):
        if h in upstream.headers:
            resp_headers[h] = upstream.headers[h]
    if "Content-Type" not in resp_headers:
        resp_headers["Content-Type"] = "application/octet-stream"

    def generate():
        try:
            for chunk in upstream.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    yield chunk
        finally:
            upstream.close()

    return Response(
        stream_with_context(generate()),
        status=status,
        headers=resp_headers,
    )


# ---------------------------------------------------------------
# Health check (sem HTML, sem mensagem de teste)
# ---------------------------------------------------------------
@app.route("/")
def index():
    return {"status": "ok"}
