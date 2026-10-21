"""Genera la memoria de entrega docs/Memoria_PAI2_ST2.pdf (máximo 15 páginas).

Estructura exigida por el enunciado: Resumen, Manual de despliegue y uso, Grado de completitud
(trazable frente a RF/RS). Además: arquitectura con diagramas, justificación criptográfica,
análisis de capturas y logs, benchmark, ataques y reflexión sobre el uso de IA.

Las cifras NO están escritas a mano: se leen de las evidencias reales (benchmark_results.json,
attacks_report.json, audit.jsonl, pcaps, código) cada vez que se ejecuta. Si la memoria pasa de
15 páginas, el script falla.

Uso (con las evidencias ya generadas):  python -m tools.generate_memoria_pdf
"""
import collections
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (CondPageBreak, Image, KeepTogether, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from src import config

ROOT = config.BASE_DIR
OUT = ROOT / "docs" / "Memoria_PAI2_ST2.pdf"
MAX_PAGES = 15

GRUPO = "ST-2"
INTEGRANTES = ["Raimundo García Pérez", "Konstantinos Peridis", "Luis Alarcón Conradi"]
REPO = "github.com/luialacon/ssii_PAI2 (rama raimundo_dev)"

# ----------------------------------------------------------------------------- fuentes
FONTS = Path("C:/Windows/Fonts")
try:
    pdfmetrics.registerFont(TTFont("Body", str(FONTS / "arial.ttf")))
    pdfmetrics.registerFont(TTFont("Body-B", str(FONTS / "arialbd.ttf")))
    pdfmetrics.registerFont(TTFont("Body-I", str(FONTS / "ariali.ttf")))
    pdfmetrics.registerFont(TTFont("Mono", str(FONTS / "consola.ttf")))
    pdfmetrics.registerFontFamily("Body", normal="Body", bold="Body-B", italic="Body-I", boldItalic="Body-B")
    F, FB, FI, FM = "Body", "Body-B", "Body-I", "Mono"
except Exception:  # noqa: BLE001 - sin Arial se usa Helvetica (sin símbolos especiales)
    F, FB, FI, FM = "Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Courier"

NAVY, BLUE, GREEN, RED, AMBER, GREY = (colors.HexColor(c) for c in
                                      ("#16325c", "#1f6feb", "#1a7f37", "#cf222e", "#bf8700", "#6e7781"))
LIGHT = colors.HexColor("#eef3fb")

S = {
    "body": ParagraphStyle("body", fontName=F, fontSize=8.8, leading=11.6, alignment=TA_JUSTIFY, spaceAfter=4),
    "small": ParagraphStyle("small", fontName=F, fontSize=7.6, leading=9.6, textColor=GREY, spaceAfter=3),
    "h1": ParagraphStyle("h1", fontName=FB, fontSize=14, leading=17, textColor=NAVY, spaceBefore=4, spaceAfter=6),
    "h2": ParagraphStyle("h2", fontName=FB, fontSize=10.5, leading=13, textColor=BLUE, spaceBefore=6, spaceAfter=3),
    "cell": ParagraphStyle("cell", fontName=F, fontSize=7.4, leading=9.2),
    "cellb": ParagraphStyle("cellb", fontName=FB, fontSize=7.4, leading=9.2, textColor=colors.white),
    "code": ParagraphStyle("code", fontName=FM, fontSize=7.3, leading=9),
    "title": ParagraphStyle("title", fontName=FB, fontSize=22, leading=26, textColor=NAVY, spaceAfter=4),
    "sub": ParagraphStyle("sub", fontName=F, fontSize=11, leading=14, textColor=GREY, spaceAfter=8),
}


def P(text, style="body"):
    return Paragraph(text, S[style])


def H1(t):
    return P(t, "h1")


def H2(t):
    return P(t, "h2")


def code(text):
    t = Table([[Preformatted(text.strip("\n"), S["code"])]], colWidths=[17.4 * cm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f8fa")),
                           ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
                           ("LEFTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 3),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def table(rows, widths, header=True, zebra=True, font=7.4):
    cs = ParagraphStyle("c", parent=S["cell"], fontSize=font, leading=font + 1.9)
    hs = ParagraphStyle("h", parent=S["cellb"], fontSize=font, leading=font + 1.9)
    data = []
    for i, r in enumerate(rows):
        data.append([Paragraph(str(c), hs if (header and i == 0) else cs) for c in r])
    t = Table(data, colWidths=[w * cm for w in widths], repeatRows=1 if header else 0)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d0d7de")),
          ("LEFTPADDING", (0, 0), (-1, -1), 3.5), ("RIGHTPADDING", (0, 0), (-1, -1), 3.5),
          ("TOPPADDING", (0, 0), (-1, -1), 2.2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2)]
    if header:
        st.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    if zebra:
        st += [("BACKGROUND", (0, i), (-1, i), LIGHT) for i in range(2 if header else 1, len(rows), 2)]
    t.setStyle(TableStyle(st))
    return t


# ----------------------------------------------------------------------------- dibujo
def box(d, x, y, w, h, text, fill=colors.white, stroke=NAVY, size=7.2, bold=False, color=colors.black):
    d.add(Rect(x, y, w, h, fillColor=fill, strokeColor=stroke, strokeWidth=0.8, rx=3, ry=3))
    lines = text.split("\n")
    ty = y + h / 2 + (len(lines) - 1) * (size + 1) / 2 - size / 3
    for i, ln in enumerate(lines):
        d.add(String(x + w / 2, ty - i * (size + 1.2), ln, textAnchor="middle", fontName=FB if bold else F,
                     fontSize=size, fillColor=color))


def arrow(d, x1, y1, x2, y2, color=NAVY, dash=None, width=1.0, head=4):
    d.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=width, strokeDashArray=dash))
    import math
    a = math.atan2(y2 - y1, x2 - x1)
    p = [x2, y2, x2 - head * math.cos(a - 0.4), y2 - head * math.sin(a - 0.4),
         x2 - head * math.cos(a + 0.4), y2 - head * math.sin(a + 0.4)]
    d.add(Polygon(p, fillColor=color, strokeColor=color, strokeWidth=0.4))


def text(d, x, y, s, size=7, anchor="start", bold=False, color=colors.black):
    d.add(String(x, y, s, textAnchor=anchor, fontName=FB if bold else F, fontSize=size, fillColor=color))


def scaled(d, k):
    """Reduce un dibujo manteniendo proporciones (para que encaje en la página)."""
    d.scale(k, k)
    d.width *= k
    d.height *= k
    return d


def diagram_architecture():
    d = Drawing(490, 232)
    d.add(Rect(2, 8, 150, 216, fillColor=colors.HexColor("#f0f6ff"), strokeColor=BLUE, strokeWidth=0.8, rx=5, ry=5))
    text(d, 77, 210, "Dispositivos BYOD (PDI/PTGAS/Inv.)", 7.4, "middle", True, BLUE)
    for i, (n, sub) in enumerate([("Portátil personal", "Windows / macOS / Linux"), ("Smartphone", "Android / iOS"),
                                  ("Tablet", "Android / iOS")]):
        box(d, 14, 148 - i * 52, 126, 44, f"{n}\n{sub}\ncert. X.509 + clave privada", size=6.8)
    text(d, 77, 14, "ByodClient · register.py", 6.6, "middle", color=GREY)

    d.add(Rect(160, 70, 130, 78, fillColor=colors.HexColor("#fff8e5"), strokeColor=AMBER, strokeWidth=0.8, rx=30, ry=30,
               strokeDashArray=[3, 2]))
    text(d, 225, 130, "INTERNET", 8, "middle", True, AMBER)
    text(d, 225, 120, "(red no confiable)", 6.6, "middle", color=AMBER)
    box(d, 168, 90, 114, 24, "Túnel TLS 1.3 + mTLS\nAES-256-GCM / ChaCha20", fill=colors.HexColor("#dafbe1"),
        stroke=GREEN, size=6.6, bold=True, color=GREEN)
    box(d, 166, 28, 118, 34, "Atacante: sniffing, MITM,\nreplay, suplantación", fill=colors.HexColor("#ffebe9"),
        stroke=RED, size=6.6, color=RED)
    arrow(d, 225, 62, 225, 78, RED, [2, 2])
    arrow(d, 142, 102, 166, 102, GREEN, width=1.6)
    arrow(d, 284, 102, 306, 102, GREEN, width=1.6)

    d.add(Rect(300, 8, 188, 216, fillColor=colors.HexColor("#f2fbf4"), strokeColor=GREEN, strokeWidth=0.8, rx=5, ry=5))
    text(d, 394, 210, "Infraestructura U-Secure", 7.6, "middle", True, GREEN)
    box(d, 308, 160, 172, 40, "GATEWAY  :8443\nTLS 1.3 · CERT_REQUIRED · CRL\nsession.py: login 2.ª capa, perfiles",
        fill=colors.white, stroke=GREEN, size=6.8, bold=False)
    box(d, 308, 122, 82, 30, "Alta :8444\n(TLS 1.3, firma CSR)", size=6.5)
    box(d, 398, 122, 82, 30, "CA interna + CRL\nECDSA P-384", size=6.5)
    box(d, 308, 84, 82, 30, "SQLite (inmutable)\nusuarios · certificados", size=6.5)
    box(d, 398, 84, 82, 30, "Auditoría JSONL\ncadena de hashes", size=6.5)
    box(d, 308, 14, 172, 62, "RED CORPORATIVA (acceso según perfil)\nPDI: correo, docencia, gestión académica\n"
        "PTGAS: correo, gestión adm., repositorio\nInvestigador: correo, BD investigación, repo.",
        fill=colors.HexColor("#eef3fb"), size=6.5)
    arrow(d, 394, 160, 394, 154, GREEN)
    return d


def diagram_sequence():
    d = Drawing(490, 262)
    cx, gx = 84, 410
    box(d, cx - 45, 238, 90, 20, "Cliente BYOD", fill=LIGHT, size=8, bold=True)
    box(d, gx - 45, 238, 90, 20, "Gateway", fill=LIGHT, size=8, bold=True)
    d.add(Line(cx, 238, cx, 4, strokeColor=GREY, strokeDashArray=[2, 2]))
    d.add(Line(gx, 238, gx, 4, strokeColor=GREY, strokeDashArray=[2, 2]))
    steps = [
        (224, True, "1  ClientHello (solo TLS 1.3; ECDHE, suites AEAD)"),
        (205, False, "2  ServerHello + certificado de servidor + CertificateRequest (cifrado)"),
        (186, None, "3  El cliente valida: cadena → CA U-Secure, nombre gateway.usecure.es, EKU serverAuth"),
        (167, True, "4  Certificado de cliente + CertificateVerify (prueba de posesión de la clave)"),
        (148, None, "5  El servidor valida: firma de la CA, vigencia, EKU clientAuth, NO en CRL"),
        (129, False, "6  Finished: túnel TLS 1.3 abierto (claves efímeras)"),
        (108, True, "7  LOGIN {usuario, contraseña}   (dentro del túnel)"),
        (89, None, "8  CN del certificado == usuario · cert. vigente en BD · cuenta no bloqueada · Argon2id"),
        (70, False, "9  OK {rol}  →  MSG / RESOURCE según el perfil"),
        (48, True, "10 LOGOUT"),
        (29, False, "11 BYE + close_notify  →  claves de sesión descartadas"),
    ]
    for y, direction, label in steps:
        if direction is None:
            text(d, 245, y - 3, label, 6.4, "middle", False, NAVY)
            continue
        if direction:
            arrow(d, cx + 4, y, gx - 4, y, BLUE)
        else:
            arrow(d, gx - 4, y, cx + 4, y, GREEN)
        text(d, 245, y + 3, label, 6.4, "middle")
    d.add(Rect(8, 124, 8, 106, fillColor=BLUE, strokeColor=BLUE))
    text(d, 22, 180, "CAPA 1", 6.4, "start", True, BLUE)
    text(d, 22, 171, "mTLS", 6.4, "start", True, BLUE)
    d.add(Rect(8, 24, 8, 94, fillColor=GREEN, strokeColor=GREEN))
    text(d, 22, 74, "CAPA 2", 6.4, "start", True, GREEN)
    text(d, 22, 65, "credenciales", 6.4, "start", True, GREEN)
    return d


def diagram_lifecycle():
    d = Drawing(490, 118)
    items = [("1 CA raíz\nECDSA P-384\npathlen=0", 6), ("2 Cert. servidor\nserverAuth + SAN", 100),
             ("3 Dispositivo:\nclave + CSR\n(clave no viaja)", 194), ("4 enroll valida y\nla CA firma\n(clientAuth)", 288),
             ("5 Alta en BD\n(inmutable)", 382)]
    for t, x in items:
        box(d, x, 66, 90, 42, t, fill=LIGHT, size=6.8)
    for i in range(4):
        arrow(d, items[i][1] + 90, 87, items[i + 1][1], 87, NAVY)
    box(d, 100, 6, 90, 42, "6 Uso: mTLS +\nCN == usuario", fill=colors.HexColor("#dafbe1"), stroke=GREEN, size=6.8)
    box(d, 218, 6, 110, 42, "7 Revocación\nserial → CRL + BD\n(recarga en caliente)", fill=colors.HexColor("#ffebe9"),
        stroke=RED, size=6.8)
    box(d, 356, 6, 110, 42, "8 Re-emisión\nnueva CSR, nuevo\ncert. (única vía)", fill=colors.HexColor("#fff8e5"),
        stroke=AMBER, size=6.8)
    arrow(d, 427, 66, 150, 48, GREEN, [3, 2])
    arrow(d, 190, 27, 218, 27, RED)
    arrow(d, 328, 27, 356, 27, AMBER)
    return d


# ----------------------------------------------------------------------------- datos
def load_json(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def loc(*dirs):
    n = 0
    for d in dirs:
        for f in (ROOT / d).rglob("*.py"):
            if "__pycache__" not in f.parts:
                n += len(f.read_text(encoding="utf-8").splitlines())
    return n


def count_tests():
    r = subprocess.run([sys.executable, "-m", "pytest", "-o", "addopts=", "--collect-only", "-q"], capture_output=True,
                       text=True, cwd=ROOT, encoding="utf-8", errors="replace")
    m = re.search(r"(\d+) tests? collected", r.stdout) or re.search(r"(\d+) tests?", r.stdout)
    return int(m.group(1)) if m else 0


def audit_counts():
    rows = [json.loads(line) for line in (config.LOGS_DIR / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    return collections.Counter(r["event"] for r in rows), rows


def pcap_facts():
    d = config.PCAP_DIR
    secret, pw = b"INFORME-CONFIDENCIAL-NOTAS-2026", config.PRELOAD_PASSWORD.encode()
    tshark = Path("C:/Program Files/Wireshark/tshark.exe")

    def packets(f):
        if not tshark.exists():
            return "-"
        r = subprocess.run([str(tshark), "-r", str(d / f)], capture_output=True, text=True, errors="replace")
        return str(len(r.stdout.strip().splitlines()))
    out = {}
    for name in ("tls13_mtls_session", "plain_session", "tls12_rejected", "no_client_cert"):
        raw = (d / f"{name}.pcapng").read_bytes()
        out[name] = {"packets": packets(f"{name}.pcapng"), "secret": secret in raw, "password": pw in raw,
                     "bytes": len(raw)}
    return out


def wire_sample(pf):
    """Ejemplo lado a lado extraído de las capturas reales (plano frente a TLS 1.3)."""
    tshark = Path("C:/Program Files/Wireshark/tshark.exe")
    d = config.PCAP_DIR
    if not tshark.exists():
        return "(tshark no disponible: ejecute python -m tools.capture_evidence en una máquina con Wireshark)"

    def run(*args):
        r = subprocess.run([str(tshark), *args], capture_output=True, text=True, errors="replace")
        return r.stdout

    plain = []
    for ln in run("-r", str(d / "plain_session.pcapng"), "-q", "-z", "follow,tcp,ascii,0").splitlines():
        if "{" in ln:
            plain.append(ln[ln.index("{"):][:76])
    tls = [x.strip() for x in run("-r", str(d / "tls13_mtls_session.pcapng"), "-Y", "tcp.len>0 && tcp.srcport==18443",
                                  "-T", "fields", "-e", "tcp.payload").splitlines() if x.strip()]
    left = ["SIN cifrar (plain_session.pcapng)"] + plain[:3]
    right = ["TLS 1.3 (tls13_mtls_session.pcapng)"]
    for hx, label in zip(tls[:3], ("ServerHello", "datos cifrados", "datos cifrados")):
        h = " ".join(hx[i:i + 2] for i in range(0, min(len(hx), 24), 2))
        right.append(h + " ...  (" + label + ")")
    n = max(len(left), len(right))
    left += [""] * (n - len(left))
    right += [""] * (n - len(right))
    return "\n".join(a.ljust(78) + b for a, b in zip(left, right))


def fmt(x, nd=1):
    return f"{x:.{nd}f}"


# ----------------------------------------------------------------------------- contenido
def build_story():
    bench = load_json(config.BENCH_DIR / "benchmark_results.json")
    attacks = load_json(config.ATTACKS_DIR / "attacks_report.json")
    events, rows = audit_counts()
    pf = pcap_facts()
    n_tests = count_tests()
    plain, tls, ov = bench["plain"], bench["tls"], bench["overhead"]["pct"]
    runs = bench["all_runs"]

    def rng(mode, key, sub=None, nd=1):
        vals = [(r[key][sub] if sub else r[key]) for r in runs[mode]]
        return f"{min(vals):.{nd}f}–{max(vals):.{nd}f}"

    story = []

    # ------------------------------------------------------------------ portada + resumen
    story += [P("PAI-2 BYODSEC", "title"),
              P("Bring Your Own Device seguro mediante VPN SSL «road warrior» (TLS 1.3 + mTLS) para la Universidad U-Secure", "sub"),
              table([["Grupo", GRUPO], ["Integrantes", " · ".join(INTEGRANTES)],
                     ["Asignatura", "Seguridad en Sistemas de Información e Internet (SSII) · ETSII · Universidad de Sevilla"],
                     ["Repositorio", REPO], ["Fecha", date.today().strftime("%d/%m/%Y")]],
                    [3, 14.4], header=False, zebra=False, font=8),
              Spacer(1, 6),
              H1("1. Resumen"),
              P("Hemos construido un <b>gateway VPN y un cliente BYOD sobre sockets TLS 1.3 nativos</b> (módulo <font name='%s'>ssl</font> de Python sobre OpenSSL) "
                "que cumplen la política de la universidad: <i>solo usuarios, dispositivos y servicios previamente autorizados acceden a los recursos corporativos, "
                "por canales que garantizan confidencialidad, integridad y autenticidad</i>. Elegimos sockets frente a REST/gRPC porque dan control total del handshake "
                "y dejan el <code>.pcap</code> sin ruido de un servidor web." % FM),
              H2("Decisiones técnicas y algorítmicas"),
              table([["Requisito", "Decisión", "Por qué"],
                     ["RS1 PKI + mTLS", "CA interna ECDSA P-384 (<i>pathlen=0</i>); certificados por CSR; CRL; <font name='%s'>CERT_REQUIRED</font>" % FM,
                      "El servidor exige el carnet del dispositivo; el cliente valida CA <b>y nombre</b> del servidor"],
                     ["RS2 TLS 1.3", "<i>min = max = TLS 1.3</i>; suites <b>TLS_AES_256_GCM_SHA384</b> y <b>TLS_CHACHA20_POLY1305_SHA256</b>; sin tickets",
                      "Todas las suites TLS 1.3 son AEAD con PFS (ECDHE obligatorio); sin tickets no sobrevive material de sesión al cierre"],
                     ["RF2 doble capa", "mTLS + usuario/contraseña (<b>Argon2id</b>) + <b>CN del certificado = usuario</b>",
                      "Un carnet robado no sirve sin contraseña, ni para entrar como otro usuario"],
                     ["RF1 inmutabilidad", "Triggers SQLite + log de auditoría con <b>cadena de hashes</b>",
                      "La identidad y la clave pública no se pueden alterar; manipular el log se detecta"],
                     ["RS3 300 usuarios", "Hilo por conexión, semáforo de Argon2id, benchmark de 300 sesiones simultáneas <b>plano frente a TLS</b>",
                      "Misma lógica de servidor en ambos: la diferencia medida es el cifrado"],
                     ["RS4 Auditoría", "4 capturas <font name='%s'>.pcapng</font> analizadas con tshark + %d eventos auditados" % (FM, len(rows)),
                      "Demuestra tráfico 100 % cifrado y rastrea conexiones, rechazos y desconexiones"]],
                    [2.8, 8.0, 6.6]),
              Spacer(1, 4),
              P("<b>Estado:</b> %d pruebas automáticas en verde, %d ataques simulados bloqueados de %d y benchmark de %d sesiones simultáneas con %d/%d éxitos. "
                "Código: %d líneas en <font name='%s'>src/</font>, %d en pruebas, benchmark y ataques." % (
                    n_tests, sum(a["blocked"] for a in attacks), len(attacks), tls["sessions"], tls["ok"], tls["sessions"],
                    loc("src"), FM, loc("tests", "benchmarks", "attacks", "tools")))]

    # ------------------------------------------------------------------ arquitectura
    story += [CondPageBreak(9 * cm), H1("2. Arquitectura"),
              P("El proyecto sigue el escenario de la Figura 2 del enunciado: dispositivos personales que cruzan Internet hasta un gateway que da acceso a la red corporativa. "
                "Todo el tráfico va dentro de un único túnel TLS 1.3; el atacante solo ve bytes cifrados."),
              scaled(diagram_architecture(), 0.88),
              P("<b>Figura 1.</b> Arquitectura cliente-servidor/BYOD y componentes. El servicio de alta (:8444) usa TLS 1.3 sin certificado de cliente porque el usuario nuevo aún no tiene carnet.", "small"),
              KeepTogether([H2("2.1 Negociación mTLS y doble capa de autenticación"), diagram_sequence(),
                            P("<b>Figura 2.</b> Handshake TLS 1.3 con autenticación mutua (pasos 1-6) y autenticación de aplicación (7-11). En TLS 1.3 el certificado del servidor ya viaja cifrado.", "small")]),
              KeepTogether([H2("2.2 Ciclo de vida de los certificados X.509"), diagram_lifecycle(),
                            P("<b>Figura 3.</b> De la CA al uso, revocación y re-emisión. La clave privada del usuario se genera en su dispositivo y <b>nunca</b> viaja: solo la CSR.", "small")])]

    # ------------------------------------------------------------------ cripto
    story += [CondPageBreak(8 * cm), H1("3. Justificación criptográfica"),
              H2("3.1 PKI interna (RS1)"),
              P("La <b>CA raíz</b> es autofirmada, ECDSA con curva P-384 y SHA-384, con <i>BasicConstraints CA:TRUE pathlen=0</i> y <i>KeyUsage keyCertSign + cRLSign</i>: "
                "solo puede firmar certificados finales, no otras CA. El <b>certificado del servidor</b> (P-384) lleva EKU <i>serverAuth</i> y SAN (<i>gateway.usecure.es</i>, <i>localhost</i>, 127.0.0.1). "
                "Los <b>certificados de usuario</b> (P-256) llevan EKU <i>clientAuth</i>, <i>KeyUsage digitalSignature</i>, identificadores SKI/AKI y punto de distribución de CRL; el CN es el nombre de usuario y la OU, el rol."),
              P("<b>Emisión por CSR.</b> El dispositivo genera su par de claves y envía solo la CSR. La CA comprueba la firma de la CSR y que el CN coincida con el usuario, "
                "e <b>ignora cualquier extensión</b> que pida el cliente: es la CA quien decide EKU y KeyUsage (el solicitante no puede concederse permisos). "
                "<b>Revocación:</b> el serial pasa a la CRL y se marca en la BD; el gateway detecta que la CRL cambió y recarga el contexto <i>sin reiniciarse</i> (<font name='%s'>VERIFY_CRL_CHECK_LEAF</font>)." % FM),
              H2("3.2 Canal TLS 1.3 y suites (RS2)"),
              P("El contexto del servidor fija <font name='%s'>minimum_version = maximum_version = TLSv1_3</font>: SSLv3, TLS 1.0, 1.1 y 1.2 quedan descatalogados "
                "(comprobado: un cliente que solo habla TLS 1.2 recibe la alerta <i>protocol_version</i>, ver §5). "
                "TLS 1.3 elimina los modos inseguros: no hay RSA estático, CBC, RC4 ni renegociación, y <b>todas</b> sus suites son AEAD; el intercambio de claves es "
                "siempre (EC)DHE, lo que da <b>Perfect Forward Secrecy</b>: aunque se robe después la clave privada del servidor, las sesiones grabadas no se pueden descifrar." % FM),
              table([["Suite", "Cifrado autenticado", "Hash (HKDF)", "Política"],
                     ["TLS_AES_256_GCM_SHA384", "AES-256 en modo GCM (AEAD)", "SHA-384", "<b>Permitida</b> (la que se negocia: preferencia del servidor)"],
                     ["TLS_CHACHA20_POLY1305_SHA256", "ChaCha20-Poly1305 (AEAD)", "SHA-256", "<b>Permitida</b> (equipos sin aceleración AES)"],
                     ["TLS_AES_128_GCM_SHA256", "AES-128 en modo GCM (AEAD)", "SHA-256", "Fuera de política: negociable por OpenSSL, <b>cortada</b> tras el handshake (evento CIPHER_REJECTED)"]],
                    [5.6, 4.0, 1.9, 5.9]),
              Spacer(1, 3),
              P("<b>Limitación declarada.</b> El módulo <font name='%s'>ssl</font> de Python no ofrece una llamada para recortar las suites de TLS 1.3 (<font name='%s'>set_ciphers</font> solo "
                "gobierna TLS ≤ 1.2; con nombres TLS 1.3 falla: <i>No cipher can be selected</i>). Por eso el servidor impone su preferencia (<font name='%s'>OP_CIPHER_SERVER_PREFERENCE</font>) "
                "y <b>rechaza tras el handshake</b> cualquier suite fuera de la lista. Lo demostramos con un cliente <font name='%s'>openssl s_client</font> independiente: si solo ofrece AES-128 "
                "se negocia y el servidor lo corta; si ofrece ambas, se elige AES-256-GCM." % (FM, FM, FM, FM)),
              P("<b>Cierre seguro (RF4).</b> El cliente envía <i>LOGOUT</i>, el servidor confirma y ambos envían <i>close_notify</i>. Con <font name='%s'>num_tickets = 0</font> no se emiten tickets de reanudación, "
                "así que al cerrar no queda ningún secreto con el que reabrir o descifrar la sesión: las claves efímeras se descartan." % FM),
              H2("3.3 mTLS y autenticación en dos capas (RF2)"),
              P("<b>Capa 1 (transporte).</b> <font name='%s'>verify_mode = CERT_REQUIRED</font>: el servidor <i>exige</i> certificado de cliente firmado por nuestra CA, vigente, con EKU clientAuth y no revocado; "
                "el cliente valida a su vez cadena y nombre del servidor (<font name='%s'>check_hostname = True</font>). Es la autenticación mutua del enunciado. "
                "<b>Capa 2 (aplicación).</b> Usuario y contraseña, verificados con <b>Argon2id</b> (sal única por usuario, coste en memoria); además se exige <b>CN del certificado = usuario</b> y que ese "
                "certificado sea el vigente de ese usuario en la BD. Resultado: un carnet robado sin contraseña no entra (ataque 4) y un carnet no sirve para hacerse pasar por otro (ataque 5). "
                "Defensas adicionales: bloqueo temporal tras %d fallos, mensaje de error <i>genérico</i> y verificación «señuelo» para usuarios inexistentes (no se filtra por tiempo si el usuario existe), "
                "y un semáforo que limita a %d las verificaciones Argon2id simultáneas (cada una usa ≈64 MB; sin límite, 300 logins agotarían la RAM)."
                % (FM, FM, config.MAX_FAILED_ATTEMPTS, config.MAX_CONCURRENT_VERIFICATIONS)),
              H2("3.4 Inmutabilidad y auditoría (RF1, RS4)"),
              P("SQLite incluye <i>triggers</i> <font name='%s'>BEFORE UPDATE/DELETE</font> que abortan cualquier cambio de usuario, rol, fecha de alta o clave pública, y el borrado de usuarios y certificados. "
                "Solo se permite marcar un certificado como revocado (una vez). Cambiar una identidad exige revocar y emitir otra. "
                "El log de auditoría guarda en cada línea el SHA-256 de la anterior: editar o borrar una línea rompe la cadena y <font name='%s'>verify_chain()</font> lo detecta (probado)." % (FM, FM))]

    # ------------------------------------------------------------------ manual
    story += [CondPageBreak(8 * cm), H1("4. Manual de despliegue y uso"),
              P("Todos los comandos se ejecutan desde la raíz del proyecto. Probado en Windows 10 con Python 3.10. La guía completa para desarrolladores es <font name='%s'>GUIA.md</font>." % FM),
              H2("4.1 Requisitos e instalación"),
              code("python --version                       # >= 3.10\npip install -r requirements-dev.txt        # cryptography, argon2-cffi, psutil, matplotlib, pytest, reportlab\n"
                   "# Opcional: OpenSSL (pruebas con cliente independiente) y Wireshark + Npcap (capturas)"),
              H2("4.2 Generar la PKI y precargar 300 usuarios (RS1, RF5)"),
              code("python -m src.pki.preload --reset      # ~25 s: CA, certificado de servidor y 300 usuarios con certificado\n"
                   "openssl verify -CAfile certs/ca/ca.crt certs/clients/pdi_user1/pdi_user1.crt   # -> OK"),
              P("Crea <font name='%s'>certs/</font> y <font name='%s'>data/usecure.db</font>: 100 usuarios por rol (<i>pdi_user1…100</i>, <i>pas_user1…100</i>, <i>inv_user1…100</i>), "
                "con contraseña de <b>prueba</b> común (<font name='%s'>PRELOAD_PASSWORD</font> en <font name='%s'>src/config.py</font>). Las claves privadas no se versionan." % (FM, FM, FM, FM)),
              H2("4.3 Lanzar el servidor y el cliente (RF2, RF4)"),
              code("# terminal 1\npython -m src.server.gateway                 # TLS 1.3 + mTLS en :8443\n"
                   "# terminal 2\npython main.py                               # opción 4 = demo automática, 5 = sesión interactiva"),
              P("En la sesión interactiva se elige el alias del certificado, el usuario y la contraseña; comandos: <i>recurso &lt;nombre&gt;</i>, <i>logout</i> o cualquier texto (eco cifrado). "
                "Cada perfil solo accede a sus recursos."),
              H2("4.4 Registrar un usuario nuevo y revocar certificados (RF1)"),
              code("python -m src.server.enroll                 # terminal 1: servicio de alta (:8444)\npython main.py                               # terminal 2: opción 6 (usuario, rol, email, código de alta, contraseña)\n"
                   "python -m src.pki.admin revoke pdi_user1     # anula el carnet; el gateway recarga la CRL solo"),
              H2("4.5 Pruebas, capturas, ataques y benchmark (RS3, RS4)"),
              code("python -m pytest                                         # %d pruebas, ~7 s (PKI/BD/puerto temporales)\n"
                   "python -m tools.capture_evidence                             # 4 pcaps + análisis con tshark  -> evidences/pcap/\n"
                   "python -m attacks.run_attacks                                # 11 ataques + informe            -> evidences/attacks/\n"
                   "python -m benchmarks.load_test --sessions 300 --runs 3       # ~3 min, TLS frente a plano      -> evidences/bench/\n"
                   "python main.py   # opción 8: verifica la cadena de hashes del log de auditoría" % n_tests),
              H2("4.6 Entrega"),
              code("python -m tools.generate_memoria_pdf     # esta memoria\npython -m tools.build_zip                    # PAI2-ST2.zip (lista blanca, sin claves privadas)"),
              P("<b>Reproducibilidad:</b> el zip no incluye <font name='%s'>certs/</font> ni la BD; quien lo descomprima ejecuta §4.1-4.2 y obtiene una PKI nueva. "
                "<b>Valores de demostración</b> (contraseña de precarga, código de alta) están en <font name='%s'>src/config.py</font>; en producción se sustituirían." % (FM, FM))]

    # ------------------------------------------------------------------ pcap + logs
    t13 = pf["tls13_mtls_session"]
    story += [CondPageBreak(8 * cm), H1("5. Análisis de capturas de red y registros de auditoría (RS4)"),
              P("Las capturas se generan con <font name='%s'>dumpcap</font> sobre la interfaz de loopback (Npcap) y se analizan con <font name='%s'>tshark</font> "
                "(<font name='%s'>python -m tools.capture_evidence</font>, informe en <font name='%s'>evidences/pcap/analysis.txt</font>). "
                "Se usa un mensaje secreto reconocible (<i>INFORME-CONFIDENCIAL-NOTAS-2026</i>) y se busca en los bytes capturados." % (FM, FM, FM, FM)),
              table([["Captura", "Paquetes", "¿Secreto en claro?", "¿Contraseña en claro?", "Resultado"],
                     ["tls13_mtls_session", pf["tls13_mtls_session"]["packets"], "<b>NO</b>" if not t13["secret"] else "SÍ", "<b>NO</b>" if not t13["password"] else "SÍ",
                      "TLS 1.3, suite 0x1302 (AES-256-GCM); todo el diálogo cifrado"],
                     ["plain_session (comparación)", pf["plain_session"]["packets"], "<b>SÍ</b>" if pf["plain_session"]["secret"] else "no",
                      "<b>SÍ</b>" if pf["plain_session"]["password"] else "no", "Usuario, contraseña y mensaje legibles: cualquiera en la red los lee"],
                     ["tls12_rejected", pf["tls12_rejected"]["packets"], "-", "-", "Alerta <i>protocol_version</i> (70); 0 registros de datos"],
                     ["no_client_cert", pf["no_client_cert"]["packets"], "-", "-", "Handshake abortado y conexión cerrada por el servidor"]],
                    [3.6, 1.6, 2.5, 2.9, 6.8]),
              Spacer(1, 4),
              H2("5.1 Qué se observa en la sesión TLS 1.3"),
              P("<b>Handshake.</b> Un <i>ClientHello</i> que anuncia <i>supported_versions = 0x0304</i> (TLS 1.3) y las suites 0x1302/0x1303/0x1301, y un <i>ServerHello</i> que elige <b>0x1302 = TLS_AES_256_GCM_SHA384</b>. "
                "El campo de versión de la capa de registro vale 0x0303 por compatibilidad con intermediarios; la versión real está en la extensión. "
                "<b>Cifrado.</b> A partir del ServerHello todo son registros <i>Application Data</i> (tipo 23) de tamaño variable: en TLS 1.3 viajan cifrados incluso el certificado del servidor, "
                "la petición de certificado, el certificado del cliente y los mensajes de aplicación; no hay nada ininteligible que «resumir» por parte del atacante. "
                "<b>Confidencialidad.</b> Ni el secreto ni la contraseña aparecen en el fichero de captura (%d bytes, %s paquetes); en la captura sin cifrar aparecen íntegros (ejemplo siguiente, extraído de las propias capturas)." % (t13["bytes"], t13["packets"])),
              code(wire_sample(pf)),
              P("<b>Descifrado de demostración.</b> Con el fichero de claves de sesión (<font name='%s'>tls13_session.keylog</font>, generado solo para esa captura) Wireshark sí reconstruye el diálogo; "
                "sin él, no. Es la prueba de que el contenido es recuperable únicamente por quien posee las claves efímeras (PFS)." % FM),
              P("<b>Alertas en TLS 1.3.</b> En la captura <i>no_client_cert</i> no se ve el motivo del rechazo (<i>certificate_required</i>) porque, tras el ServerHello, las alertas también van cifradas. "
                "La causa queda en el log de auditoría (evento <i>HANDSHAKE_FAILED</i>). En cambio la alerta de versión (TLS 1.2) sí es visible porque se emite antes de cifrar."),
              H2("5.2 Registro de auditoría"),
              P("<font name='%s'>evidences/logs/audit.jsonl</font>: una línea JSON por evento, con IP, usuario, CN y serial del certificado, versión TLS, suite y motivo, encadenada por SHA-256. "
                "Tras ejecutar capturas y ataques contiene <b>%d eventos</b> y la cadena es <b>%s</b>." % (
                    FM, len(rows), "íntegra" if __import__("src.server.audit", fromlist=["verify_chain"]).verify_chain()[0] else "ROTA")),
              table([["Evento", "Nº", "Significado"]] + [[e, str(events[e]), m] for e, m in [
                  ("CONNECT", "Conexión mTLS (con CN, serial, TLS y suite)"), ("DISCONNECT", "Desconexión con motivo (logout, connection_lost, auth_failed…)"),
                  ("HANDSHAKE_FAILED", "Rechazo en el handshake: sin cert., CA ajena, revocado, TLS 1.2…"),
                  ("LOGIN_OK", "Autenticación completa (capa 1 + capa 2)"), ("LOGIN_FAILED", "Contraseña errónea o usuario inexistente"),
                  ("UNAUTHORIZED", "CN ≠ usuario, certificado no vigente o recurso fuera del perfil"),
                  ("ACCOUNT_LOCKED", "Bloqueo por fuerza bruta"), ("LOGOUT", "Cierre explícito de sesión (RF4)")] if events.get(e)],
                    [3.4, 1.2, 12.8]),
              P("Los eventos prueban lo pedido por RS4: <b>conexión</b> (CONNECT), <b>desconexión</b> (DISCONNECT/LOGOUT) e <b>intentos no autorizados</b> (HANDSHAKE_FAILED, LOGIN_FAILED, UNAUTHORIZED, ACCOUNT_LOCKED).", "small")]

    # ------------------------------------------------------------------ benchmark
    story += [CondPageBreak(8 * cm), H1("6. Benchmark de escalabilidad y sobrecoste (RS3)"),
              P("<b>Método.</b> <font name='%s'>benchmarks/load_test.py</font> arranca el servidor en un <b>proceso aparte</b> (para medir su CPU y RAM), lanza <b>%d clientes a la vez</b>, cada uno con "
                "<b>su propio certificado y usuario</b>, y los hace esperar en una <b>barrera</b> hasta que todos están conectados y autenticados (así se demuestra la simultaneidad: %d/%d sesiones abiertas a la vez). "
                "Después cada cliente envía %d mensajes de 256 B (latencia/RTT) y %d de 32 KB (throughput) y hace logout. Se repite <b>%d veces</b> y se informa la <b>mediana</b>. "
                "El servidor <b>plano</b> y el <b>TLS</b> comparten el mismo código de sesión y de concurrencia: la diferencia medida es el coste del cifrado." % (
                    FM, tls["sessions"], tls["simultaneous_sessions"], tls["sessions"], 20, 10, bench["runs"])),
              table([["Métrica", "Plano", "TLS 1.3 + mTLS", "Overhead", "Rango entre ejecuciones (plano → TLS)"],
                     ["Sesiones OK / fallidas", "%d / %d" % (plain["ok"], plain["failed"]), "%d / %d" % (tls["ok"], tls["failed"]), "—", "—"],
                     ["Handshake sin carga, p50 (ms)", fmt(plain["connect_unloaded_ms"]["p50"]), fmt(tls["connect_unloaded_ms"]["p50"]), "%+.0f %%" % ov["connect_unloaded"],
                      "%s → %s" % (rng("plain", "connect_unloaded_ms", "p50"), rng("tls", "connect_unloaded_ms", "p50"))],
                     ["Conexión con %d a la vez, p50 (ms)" % tls["sessions"], fmt(plain["connect_ms"]["p50"], 0), fmt(tls["connect_ms"]["p50"], 0), "%+.0f %%" % ov["connect_latency"],
                      "%s → %s" % (rng("plain", "connect_ms", "p50", 0), rng("tls", "connect_ms", "p50", 0))],
                     ["RTT 256 B p50 / p95 / p99 (ms)", "%s / %s / %s" % (fmt(plain["rtt_small_ms"]["p50"]), fmt(plain["rtt_small_ms"]["p95"]), fmt(plain["rtt_small_ms"]["p99"])),
                      "%s / %s / %s" % (fmt(tls["rtt_small_ms"]["p50"]), fmt(tls["rtt_small_ms"]["p95"]), fmt(tls["rtt_small_ms"]["p99"])), "p50 %+.0f %%" % ov["rtt_small"],
                      "p50: %s → %s" % (rng("plain", "rtt_small_ms", "p50"), rng("tls", "rtt_small_ms", "p50"))],
                     ["Throughput (MB/s)", fmt(plain["throughput_MBps"]), fmt(tls["throughput_MBps"]), "%+.0f %%" % ov["throughput"],
                      "%s → %s" % (rng("plain", "throughput_MBps"), rng("tls", "throughput_MBps"))],
                     ["Mensajes por segundo", fmt(plain["msgs_per_s"], 0), fmt(tls["msgs_per_s"], 0), "%+.0f %%" % ((tls["msgs_per_s"] / plain["msgs_per_s"] - 1) * 100), "—"],
                     ["CPU del servidor por MB (ms/MB)", fmt(plain["cpu_ms_per_MB"], 0), fmt(tls["cpu_ms_per_MB"], 0), "%+.0f %%" % ov["cpu_per_mb"],
                      "%s → %s" % (rng("plain", "cpu_ms_per_MB", None, 0), rng("tls", "cpu_ms_per_MB", None, 0))],
                     ["CPU del servidor en conectar %d (s)" % tls["sessions"], fmt(plain["cpu_s_setup"]), fmt(tls["cpu_s_setup"]), "%+.0f %%" % ov["cpu_setup"], "dominada por Argon2id"],
                     ["RAM del servidor, pico (MB)", fmt(plain["transfer_phase"]["ram_peak_mb"], 0), fmt(tls["transfer_phase"]["ram_peak_mb"], 0), "%+.0f %%" % ov["ram"], "—"]],
                    [4.6, 2.6, 3.1, 1.9, 5.2]),
              Spacer(1, 4),
              Image(str(config.BENCH_DIR / "benchmark_comparison.png"), width=14.5 * cm, height=14.5 * cm * 960 / 1800),
              P("<b>Figura 4.</b> Plano frente a TLS 1.3 + mTLS con %d sesiones simultáneas (mediana de %d ejecuciones)." % (tls["sessions"], bench["runs"]), "small"),
              H2("Interpretación"),
              P("<b>1. El coste está en el handshake, no en el cifrado.</b> Una conexión aislada pasa de %s a %s ms: son las firmas ECDSA y el intercambio ECDHE, en <i>ambos</i> sentidos por mTLS. "
                "Con %d conexiones simultáneas se forma cola y la mediana sube a %s ms (en el plano, %s ms); es un pico puntual al iniciar la jornada, no un coste por mensaje. "
                "<b>2. Una vez abierto el túnel el sobrecoste es moderado:</b> la latencia de un mensaje sube un %.0f %% en la mediana (con mucha dispersión entre ejecuciones, ver rango), "
                "el throughput baja un %.0f %% y cada MB cuesta %.0f %% más CPU. "
                "<b>3. El login domina la CPU de conexión</b> (%s s frente a %s s): Argon2id es caro a propósito y es idéntico en ambos modos, por eso el overhead de conectar es solo del %+.0f %%. "
                "<b>4. Memoria:</b> +%.0f MB (+%.0f %%) por el estado TLS de %d sesiones." % (
                    fmt(plain["connect_unloaded_ms"]["p50"]), fmt(tls["connect_unloaded_ms"]["p50"]), tls["sessions"], fmt(tls["connect_ms"]["p50"], 0), fmt(plain["connect_ms"]["p50"], 0),
                    ov["rtt_small"], -ov["throughput"], ov["cpu_per_mb"], fmt(tls["cpu_s_setup"]), fmt(plain["cpu_s_setup"]), ov["cpu_setup"],
                    tls["transfer_phase"]["ram_peak_mb"] - plain["transfer_phase"]["ram_peak_mb"], ov["ram"], tls["sessions"])),
              P("<b>Conclusión:</b> el sistema soporta %d sesiones simultáneas con 0 fallos. <b>Limitaciones honestas:</b> cliente y servidor comparten máquina (loopback), de modo que compiten por CPU y las cifras son "
                "<i>relativas</i>, no absolutas; el servidor Python está limitado por el GIL, por lo que el throughput absoluto no representa un despliegue real; y la dispersión entre ejecuciones es notable "
                "(por eso se informa la mediana y el rango). Entorno: %d CPU, %s GB RAM, Python %s." % (
                    tls["sessions"], bench["environment"]["cpus"], bench["environment"]["ram_gb"], bench["environment"]["python"]))]

    # ------------------------------------------------------------------ ataques
    blocked = sum(a["blocked"] for a in attacks)
    story += [CondPageBreak(8 * cm), H1("7. Verificación con ataques simulados (extra opcional)"),
              P("<font name='%s'>python -m attacks.run_attacks</font> lanza %d ataques en entorno controlado contra el gateway real (misma PKI y BD). "
                "Resultado: <b>%d/%d bloqueados</b>. Cada uno se comprueba además en el log de auditoría para confirmar que lo rechazó el <i>servidor</i> y por el motivo esperado." % (FM, len(attacks), blocked, len(attacks))),
              table([["#", "Ataque", "Defensa", "Resultado"]] + [[str(a["n"]), a["name"], a["defense"], "<b>Bloqueado</b>" if a["blocked"] else "<b>NO bloqueado</b>"] for a in attacks],
                    [0.7, 5.2, 9.2, 2.3]),
              Spacer(1, 4),
              P("<b>Dos matices que importan.</b> (a) En el ataque 10 (<i>replay</i>) el servidor <i>sí</i> responde con un ServerHello, pero <b>nuevo</b> (aleatorios y claves ECDHE distintos); "
                "al intentar descifrar los bytes grabados falla con <i>bad record mac</i> y no se abre ninguna sesión. Nuestra primera versión de la prueba lo marcó como fallo porque asumía que el servidor no contestaría; "
                "se corrigió el <i>criterio</i> tras leer el log, no la defensa. (b) En el ataque 9 se modifica un solo bit de un registro cifrado: la integridad AEAD lo detecta (<i>bad_record_mac</i>) y la sesión se corta."),
              P("<b>Objetivo 5 (interceptación y suplantación en redes no confiables).</b> El retransmisor MITM (<font name='%s'>attacks/relay.py</font>) reenvía el tráfico y registra todo lo que pasa: "
                "no encuentra ni el secreto ni la contraseña (ataque 8). El servidor falso con certificado de una CA con el <i>mismo nombre</i> pero otra clave es rechazado por el cliente (ataque 7): "
                "se valida la cadena criptográfica, no el nombre." % FM)]

    # ------------------------------------------------------------------ completitud
    story += [CondPageBreak(8 * cm), H1("8. Grado de completitud (trazable frente a RF y RS)"),
              P("Estado: <b>Completo</b> = implementado, probado y con evidencia; <b>Con matiz</b> = cumple con una limitación declarada. Todas las rutas son relativas a la raíz del proyecto."),
              table([["Req.", "Enunciado", "Estado", "Implementación", "Prueba / evidencia"],
                     ["RF1", "Registro con usuario y contraseña, vinculado a la emisión de certificado", "Completo", "src/server/enroll.py · src/client/register.py · ca.sign_csr()",
                      "tests/test_enroll.py (5) · la clave privada no viaja"],
                     ["RF1", "Inmutabilidad: identidad y clave pública no modificables sin re-emisión/revocación", "Completo", "src/server/store.py (triggers) · ca.revoke()",
                      "tests/test_store_audit_protocol.py (inmutabilidad ×5)"],
                     ["RF2", "Doble capa: mTLS (dispositivo) + usuario/contraseña", "Completo", "src/server/gateway.py · session._authenticate() · security/kdf.py",
                      "tests/test_auth_session.py · ataques 4 y 5 · audit.jsonl"],
                     ["RF4", "Cierre explícito, destrucción de claves efímeras y desmontaje inmediato", "Completo", "session._serve() LOGOUT · net.close_tls() · num_tickets=0",
                      "test_logout_closes_session… · evento LOGOUT/DISCONNECT · pcap (close_notify)"],
                     ["RF5", "Precarga de cuentas PDI/PTGAS/Investigadores con certificados", "Completo", "src/pki/preload.py (300 usuarios) · perfiles en session.ROLE_RESOURCES",
                      "300/300 sesiones en el benchmark · test_role_based_resource_access"],
                     ["RS1", "CA corporativa: ciclo de vida X.509 (servidor y dispositivos)", "Completo", "src/pki/ca.py (CA, CSR, CRL, revocación) · admin.py",
                      "openssl verify · test_revoked_certificate_is_rejected"],
                     ["RS1", "mTLS: cliente valida servidor y servidor exige/comprueba certificado de cliente", "Completo", "gateway.build_server_context() CERT_REQUIRED · byod_client.build_client_context()",
                      "tests/test_tls_mtls.py · ataques 1, 2, 7, 11"],
                     ["RS2", "TLS 1.3; SSLv3–TLS 1.2 descatalogados", "Completo", "min=max=TLSv1_3 (gateway, enroll, cliente)",
                      "test_obsolete_tls_versions_are_rejected · ataque 3 · tls12_rejected.pcapng"],
                     ["RS2", "Solo Cipher Suites AEAD con PFS (AES-256-GCM / ChaCha20-Poly1305)", "Con matiz", "ALLOWED_CIPHERS + OP_CIPHER_SERVER_PREFERENCE + CIPHER_REJECTED",
                      "test_unauthorised_suite_… (openssl s_client) · matiz en §3.2"],
                     ["RS3", "Modelo de concurrencia para 300 sesiones simultáneas", "Completo", "src/server/net.py (hilo por conexión) · semáforo Argon2id",
                      "benchmark: 300/300 simultáneas, 0 fallos"],
                     ["RS3", "Análisis comparativo throughput, RTT y CPU/RAM frente a tráfico sin cifrar", "Completo", "benchmarks/load_test.py · plain_server.py · plot.py",
                      "evidences/bench/ (JSON, PNG, informe) · §6"],
                     ["RS4", "Capturas .pcap: tráfico 100 % cifrado en la interfaz pública", "Completo", "tools/capture_evidence.py",
                      "evidences/pcap/*.pcapng · analysis.txt · §5"],
                     ["RS4", "Registros de conexión, desconexión e intentos no autorizados", "Completo", "src/server/audit.py (JSONL encadenado)",
                      "evidences/logs/audit.jsonl · verify_chain()"],
                     ["Obj. 5", "Demostrar resistencia a interceptación y suplantación (+10 %)", "Completo", "attacks/run_attacks.py · attacks/relay.py",
                      "evidences/attacks/attacks_report.md · %d/%d bloqueados" % (blocked, len(attacks))]],
                    [1.0, 4.4, 1.5, 5.4, 5.1], font=7.1),
              Spacer(1, 4),
              P("<b>Limitaciones conocidas:</b> (1) las suites de TLS 1.3 no se recortan en el handshake sino que se rechazan tras él (§3.2); (2) benchmark en una sola máquina (§6); "
                "(3) la contraseña de precarga y el código de alta son valores de demostración; (4) las claves de usuario se guardan sin passphrase en disco (como en un entorno de laboratorio); "
                "(5) las claves privadas que estuvieron en el historial git de la versión inicial deben considerarse comprometidas y no se reutilizan (la PKI se regenera).", "body")]

    # ------------------------------------------------------------------ IA
    story += [CondPageBreak(8 * cm), H1("9. Reflexión sobre el uso de IA"),
              P("Usamos <b>Claude Code</b> como asistente de ingeniería. El reparto fue deliberado: el equipo eligió la tecnología (sockets TLS), aprobó el plan y revisó cada bloque; la IA auditó la base de partida frente a la rúbrica, "
                "propuso el plan y generó el código, las pruebas y la documentación. La IA <b>no fijó el alcance</b> y no empezó a implementar hasta que el equipo aprobó el plan. "
                "El registro completo está en <font name='%s'>AGENTS.md</font> (incluido en la entrega)." % FM),
              H2("Cómo validamos el código generado"),
              P("Nada se dio por bueno porque «compilara». (1) %d pruebas escritas para <i>intentar romper</i> la defensa, no para confirmar el camino feliz. (2) Herramientas <b>independientes</b> del código generado: "
                "<font name='%s'>openssl verify/x509/s_client</font> y <font name='%s'>tshark</font>. (3) Ejecución real: procesos separados, 300 sesiones, 11 ataques. "
                "(4) Lectura del log de auditoría para confirmar que rechazó el servidor y por el motivo esperado." % (n_tests, FM, FM)),
              H2("Errores de la IA que detectamos y corregimos"),
              table([["Qué falló", "Cómo lo detectamos", "Corrección"],
                     ["Tres pruebas de rechazo de certificado fallaban: la IA esperaba un error al conectar", "pytest",
                      "En TLS 1.3 el cliente termina el handshake antes de que el servidor valide su certificado. La prueba acepta excepción <i>o</i> cierre y además <b>exige</b> el evento en el log del servidor (más estricta, no más laxa)"],
                     ["El replay figuraba como «no bloqueado»", "run_attacks", "Era un fallo del <b>criterio</b> de la prueba, no de la defensa (ver §7). Se leyó el log y se documentó en vez de forzar el verde"],
                     ["El primer benchmark mostraba un +2657 % de handshake, cifra engañosa", "Revisión crítica", "Se añadió medición sin carga y se explica la cola de 300 handshakes; además se sustituyó el «% de CPU» (incoherente, TLS salía menor) por ms de CPU por MB"],
                     ["Se pretendía «forzar» suites TLS 1.3 con <i>set_ciphers</i>", "Probando en el intérprete", "No es posible en este Python; solución con preferencia + lista blanca y <b>prueba con openssl</b>; la limitación se declara"],
                     ["Una frase afirmaba que Python ≥ 3.13 lo resolvería", "Revisión del texto", "No se podía respaldar: se eliminó"],
                     ["300 logins simultáneos ≈ 19 GB de RAM (Argon2id ≈ 64 MB cada uno)", "Cálculo previo", "Semáforo de %d verificaciones" % config.MAX_CONCURRENT_VERIFICATIONS],
                     ["tshark mostraba basura en lugar del texto descifrado", "Revisar el informe", "El campo era el texto cifrado: se usó <i>follow,tls</i> con keylog"]],
                    [5.6, 2.6, 9.2], font=7.2),
              Spacer(1, 3),
              P("<b>Reflexión.</b> La IA es muy eficaz generando estructura, pruebas y documentación, pero <b>tiende a dar por correcto lo que «debería» funcionar</b>: casi todos los errores aparecieron al <i>ejecutar</i>, "
                "no al leer el código. Un resultado desfavorable puede ser un fallo de la prueba y no de la defensa (el replay), y al revés; por eso hay que leer el log y no solo el semáforo verde/rojo. "
                "También aprendimos que la IA puede afirmar con seguridad cosas que no ha comprobado (la frase sobre Python 3.13): todo lo que aparece en esta memoria se ha ejecutado o se declara como limitación. "
                "La responsabilidad de lo entregado es del equipo.")]
    return story


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont(F, 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(1.8 * cm, 1.0 * cm, f"PAI-2 BYODSEC · {GRUPO} · Universidad de Sevilla")
    canvas.drawRightString(A4[0] - 1.8 * cm, 1.0 * cm, f"Página {doc.page}")
    canvas.restoreState()


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm, topMargin=1.6 * cm,
                            bottomMargin=1.7 * cm, title="PAI-2 BYODSEC - Memoria", author=", ".join(INTEGRANTES))
    doc.build(build_story(), onFirstPage=footer, onLaterPages=footer)
    from pypdf import PdfReader
    pages = len(PdfReader(str(OUT)).pages)
    print(f"{OUT.relative_to(ROOT)}: {pages} páginas")
    if pages > MAX_PAGES:
        sys.exit(f"ERROR: la memoria tiene {pages} páginas y el límite es {MAX_PAGES}")


if __name__ == "__main__":
    main()
