import ipaddress
import socket
import re
from urllib.parse import urljoin, urlencode, urlparse, unquote

import requests
from flask import Flask, request, Response, abort, stream_with_context

app = Flask(__name__)

# ---------------------------------------------------------------
# Configurações
# ---------------------------------------------------------------
TIMEOUT = (10, 60)             # (connect, read) em segundos
CHUNK_SIZE = 64 * 1024         # 64 KB por chunk no streaming
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

# Domínios que o proxy pode acessar (vazio = qualquer um, NÃO recomendado em produção)
# Ex.: ALLOWED_DOMAINS = {"origem.com", "cdn.origem.com"}
ALLOWED_DOMAINS = set()


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


def validate_url(url: str):
    """Valida protocolo e destino (anti-SSRF)."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        abort(400, "Somente http/https são permitidos")
    if not p.hostname:
        abort(400, "URL inválida")
    if ALLOWED_DOMAINS and not any(
        p.hostname == d or p.hostname.endswith("." + d) for d in ALLOWED_DOMAINS
    ):
        abort(403, "Domínio não permitido")
    if is_private_host(p.hostname):
        abort(403, "Destino bloqueado (rede privada)")


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
    """
    Reescreve:
      - linhas de segmento (URLs "soltas")
      - atributos URI="..." (usados em #EXT-X-KEY, #EXT-X-MAP,
        #EXT-X-MEDIA, #EXT-X-I-FRAME-STREAM-INF)
    Todas passam a apontar para o proxy.
    """
    out_lines = []
    for raw_line in body.splitlines():
        line = raw_line.strip()

        # linhas vazias mantêm
        if not line:
            out_lines.append(raw_line)
            continue

        # tags HLS: só mexe nos atributos URI="..."
        if line.startswith("#"):
            def repl(m):
                abs_u = urljoin(base_url, m.group(1))
                return f'URI="{proxy_url(abs_u, referer)}"'
            out_lines.append(URI_ATTR_RE.sub(repl, raw_line))
            continue

        # linha de segmento (URL relativa ou absoluta)
        abs_u = urljoin(base_url, line)
        out_lines.append(proxy_url(abs_u, referer))

    return "\n".join(out_lines) + "\n"


# ---------------------------------------------------------------
# Endpoint principal
# ---------------------------------------------------------------
@app.route("/proxy")
def proxy():
    target = request.args.get("url", "")
    referer = build_referer(request.args.get("referer", ""))

    if not target:
        abort(400, "Parâmetro 'url' obrigatório")

    validate_url(target)

    # Cabeçalhos a enviar ao servidor de origem
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "identity",   # evita gzip no streaming
    }
    if referer:
        headers["Referer"] = referer
        # Origin costuma ser scheme://host (sem path)
        p = urlparse(referer)
        headers["Origin"] = f"{p.scheme}://{p.netloc}"

    # Repassa Range se o cliente pediu (importante para .ts/.mp4)
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
    # Caso 1: é uma playlist HLS
    # -------------------------
    is_hls = (
        target.lower().split("?")[0].endswith((".m3u8", ".m3u"))
        or "mpegurl" in content_type
    )
    if is_hls:
        body = upstream.text  # playlists são pequenas
        # URL base = a URL final (após redirects) — resolve segmentos relativos
        base = upstream.url
        new_body = rewrite_playlist(body, base, referer)

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
# (Opcional) página de teste com hls.js
# ---------------------------------------------------------------
@app.route("/")
def index():
    return """
    <!doctype html>
    <html><head><meta charset="utf-8"><title>HLS Proxy Test</title></head>
    <body style="background:#111;color:#eee;font-family:sans-serif;padding:20px">
      <h3>Teste do Proxy HLS</h3>
      <p>Abra:</p>
      <code id="u"></code>
      <br><br>
      <video id="v" controls autoplay style="width:80%;max-width:900px;background:#000"></video>

      <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
      <script>
        // ajuste aqui para testar direto no navegador
        const origem  = "https://servidor-origem.com/video/master.m3u8";
        const referer = "dominioautorizado.com";
        const src = "/proxy?url=" + encodeURIComponent(origem) +
                    "&referer=" + encodeURIComponent(referer);
        document.getElementById("u").textContent = src;

        const video = document.getElementById("v");
        if (Hls.isSupported()) {
          const hls = new Hls();
          hls.loadSource(src);
          hls.attachMedia(video);
        } else {
          video.src = src;
        }
      </script>
    </body></html>
    """
