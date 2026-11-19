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
TIMEOUT = (10, 45)             # (connect, read) — 45s para caber no maxDuration=60 da Vercel
CHUNK_SIZE = 64 * 1024         # 64 KB por chunk no streaming
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

# ---------------------------------------------------------------
# Whitelist de domínios permitidos
# ---------------------------------------------------------------
# Configure via variável de ambiente na Vercel:
#   ALLOWED_DOMAINS = "origem.com,cdn.origem.com"
# Se vazio, o proxy aceita qualquer domínio (NÃO recomendado em produção).
_env_allowed = os.environ.get("ALLOWED_DOMAINS", "").strip()
ALLOWED_DOMAINS = {
    d.strip().lower()
    for d in _env_allowed.split(",")
    if d.strip()
}

# Domínios permitidos como "referer" (domínio que tem permissão na origem).
# Se vazio, aceita qualquer referer (mas ainda valida formato).
_env_referers = os.environ.get("ALLOWED_REFERERS", "").strip()
ALLOWED_REFERERS = {
    d.strip().lower()
    for d in _env_referers.split(",")
    if d.strip()
}


# ---------------------------------------------------------------
# Utilitários de segurança
# ---------------------------------------------------------------
def is_private_host(hostname: str) -> bool:
    """Retorna True se o hostname resolve para IP privado/loopback/link-local."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True  # se não resolve, bloqueia
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return True
    return False


def host_matches(hostname: str, allowed: set) -> bool:
    """Verifica se hostname é igual ou subdomínio de algum domínio da lista."""
    hostname = hostname.lower()
    for d in allowed:
        if hostname == d or hostname.endswith("." + d):
            return True
    return False


def validate_url(url: str):
    """Valida protocolo e destino (anti-SSRF + whitelist de domínios)."""
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
    """Valida se o referer pertence a um domínio permitido (se a lista existir)."""
    if not referer:
        return
    p = urlparse(referer)
    if not p.hostname:
        abort(403, "Referer inválido")
    if ALLOWED_REFERERS and not host_matches(p.hostname, ALLOWED_REFERERS):
        abort(403, f"Referer não permitido: {p.hostname}")


def build_referer(raw: str) -> str:
    """Normaliza o parâmetro referer para uma URL completa."""
    if not raw:
        return ""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def proxy_url(abs_url: str, referer: str) -> str:
    """Monta a URL apontando de volta para este proxy."""
    qs = urlencode({"url": abs_url, "referer": referer})
    return f"/proxy?{qs}"


# ---------------------------------------------------------------
# Reescreve playlists M3U8 (HLS)
# ---------------------------------------------------------------
URI_ATTR_RE = re.compile(r'URI="([^"]+)"')


def rewrite_playlist(body: str, base_url: str, referer: str) -> str:
    """Reescreve segmentos e atributos URI="..." para passarem pelo proxy."""
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
# Handler de erros (para devolver texto simples, não HTML)
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

    # --- Validação dos parâmetros obrigatórios ---
    if not target:
        abort(403, "Parâmetro 'url' é obrigatório")
    if not raw_referer:
        abort(403, "Parâmetro 'referer' é obrigatório")

    referer = build_referer(raw_referer)

    # --- Validações de segurança ---
    validate_url(target)
    validate_referer(referer)

    # --- Cabeçalhos a enviar ao servidor de origem ---
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
    }
    if referer:
        headers["Referer"] = referer
        p = urlparse(referer)
        headers["Origin"] = f"{p.scheme}://{p.netloc}"

    if request.headers.get("Range"):
        headers["Range"] = request.headers["Range"]

    # --- Requisição upstream ---
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
