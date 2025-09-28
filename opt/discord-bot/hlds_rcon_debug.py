# hlds_rcon_debug.py — HLDS/GoldSrc RCON (UDP) robusto + logger/hex dump.
# Uso desde código:
#   from hlds_rcon_debug import hlds_rcon, hlds_rcon_with_dump
#   print(hlds_rcon("IP", 27001, "Pass", "echo RCON_OK"))
#
# CLI:
#   python hlds_rcon_debug.py --ip 131.221.35.10 --port 27001 --password TestA12345 --cmd "status" --debug

from __future__ import annotations
import argparse
import re
import socket
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Tuple

MAGIC = b"\xff\xff\xff\xff"

# --------------------- utilidades de logging ---------------------

def hexdump(b: bytes, cols: int = 16) -> str:
    out_lines = []
    for i in range(0, len(b), cols):
        chunk = b[i:i+cols]
        hexpart = " ".join(f"{x:02x}" for x in chunk)
        asciip = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        out_lines.append(f"{i:08x}  {hexpart:<{cols*3}}  |{asciip}|")
    return "\n".join(out_lines)

def _recv_all_raw(sock: socket.socket, timeout_s: float = 0.35) -> List[bytes]:
    sock.settimeout(timeout_s)
    frames: List[bytes] = []
    while True:
        try:
            data, _ = sock.recvfrom(8192)
            frames.append(data)
        except socket.timeout:
            break
    return frames

# --------------------- helpers de construcción ---------------------

def _to_latin1_safe(s: str) -> str:
    """Normaliza texto a algo que quepa en latin-1 (descarta lo imposible)."""
    s = unicodedata.normalize("NFKD", s)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    try:
        s.encode("latin1")
        return s
    except UnicodeEncodeError:
        return "".join(ch for ch in s if ord(ch) <= 255)

def _build_challenge_packet() -> bytes:
    # challenge con terminadores para compatibilidad
    return MAGIC + b"challenge rcon\n\x00"

def _parse_challenge_from_bytes(frame: bytes) -> str:
    """Extrae dígitos del 'challenge rcon <num>' y limpia NULs."""
    if frame.startswith(MAGIC):
        frame = frame[len(MAGIC):]
    s = frame.decode("latin1", "ignore").replace("\x00", "")
    m = re.search(r"challenge\s+rcon\s+(\d+)", s)
    if m:
        return m.group(1)
    digits = "".join(ch for ch in s if ch.isdigit())
    if not digits:
        raise RuntimeError(f"No pude extraer challenge de: {s!r}")
    return digits

def _build_rcon_packet(challenge: str, password: str, command: str, quote_pass: bool) -> bytes:
    # challenge sólo dígitos
    challenge = "".join(ch for ch in challenge if ch.isdigit())
    if not challenge:
        raise RuntimeError("Challenge vacío tras limpieza")

    pw = f'"{password}"' if quote_pass else password
    line = (
        b"rcon " +
        challenge.encode("ascii") + b" " +
        pw.encode("latin1", "ignore") + b" " +
        _to_latin1_safe(command).encode("latin1", "ignore")
    )
    return MAGIC + line + b"\n\x00"

# --------------------- API principal ---------------------

def hlds_rcon_with_dump(
    ip: str,
    port: int,
    password: str,
    command: str,
    *,
    timeout: float = 1.0,
    read_timeout: float = 0.35,
) -> Tuple[str, Dict[str, Any]]:
    """
    Envía RCON y devuelve (respuesta_texto, dump_dict) con todo lo enviado/recibido.
    dump_dict incluye:
      - challenge_sent / challenge_sent_hex / challenge_sent_ascii
      - challenge_resp_raw / challenge_resp_hex / challenge_resp_text
      - rcon_attempts: lista de intentos (quoted: bool, packet_hex/ascii, responses_* ...)
    """
    addr = (ip, port)
    dump: Dict[str, Any] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)

        # 1) CHALLENGE
        pkt_ch = _build_challenge_packet()
        dump["challenge_sent"] = pkt_ch
        dump["challenge_sent_hex"] = hexdump(pkt_ch)
        dump["challenge_sent_ascii"] = pkt_ch.decode("latin1", "ignore")

        s.sendto(pkt_ch, addr)
        ch_frames = _recv_all_raw(s, timeout_s=timeout)
        dump["challenge_resp_raw"]  = ch_frames
        dump["challenge_resp_hex"]  = [hexdump(f) for f in ch_frames]
        dump["challenge_resp_text"] = [f.decode("latin1", "ignore") for f in ch_frames]

        if not ch_frames:
            raise RuntimeError("Sin respuesta al challenge (IP/PUERTO/UDP/firewall).")

        challenge = _parse_challenge_from_bytes(ch_frames[-1])

        # 2) RCON (probar pass sin y con comillas)
        attempts_log = []
        for quoted in (False, True):
            pkt_cmd = _build_rcon_packet(challenge, password, command, quoted)
            s.sendto(pkt_cmd, addr)
            resp_frames = _recv_all_raw(s, timeout_s=read_timeout)

            entry = {
                "quoted": quoted,
                "packet": pkt_cmd,
                "packet_hex": hexdump(pkt_cmd),
                "packet_ascii": pkt_cmd.decode("latin1", "ignore").replace("\n", "\\n").replace("\x00", "\\x00"),
                "responses_raw": resp_frames,
                "responses_hex": [hexdump(f) for f in resp_frames],
                "responses_text_joined": "".join(
                    (f[len(MAGIC):] if f.startswith(MAGIC) else f).decode("latin1", "ignore")
                    for f in resp_frames
                ).strip(),
            }
            attempts_log.append(entry)

            if entry["responses_text_joined"]:
                dump["rcon_attempts"] = attempts_log
                return entry["responses_text_joined"], dump

        dump["rcon_attempts"] = attempts_log
        # Muchos comandos (p.ej., 'say') no devuelven texto; devolvemos vacío con dump
        return "", dump

def hlds_rcon(
    ip: str,
    port: int,
    password: str,
    command: str,
    *,
    timeout: float = 1.0,
    read_timeout: float = 0.35,
) -> str:
    resp, _ = hlds_rcon_with_dump(ip, port, password, command, timeout=timeout, read_timeout=read_timeout)
    return resp

# --------------------- CLI para pruebas ---------------------

def _main():
    ap = argparse.ArgumentParser(description="Cliente RCON UDP para HLDS/GoldSrc (con logger).")
    ap.add_argument("--ip", required=True, help="IP del servidor")
    ap.add_argument("--port", type=int, required=True, help="Puerto del servidor (mismo que 'status')")
    ap.add_argument("--password", required=True, help="rcon_password del server")
    ap.add_argument("--cmd", required=True, help="Comando a ejecutar (ej. 'status')")
    ap.add_argument("--timeout", type=float, default=1.0, help="Timeout challenge/envío (s)")
    ap.add_argument("--read-timeout", type=float, default=0.35, help="Timeout para leer respuesta(s) (s)")
    ap.add_argument("--debug", action="store_true", help="Imprime hexdumps detallados")

    args = ap.parse_args()
    resp, dump = hlds_rcon_with_dump(
        args.ip, args.port, args.password, args.cmd,
        timeout=args.timeout, read_timeout=args.read_timeout
    )

    if args.debug:
        print("=== CHALLENGE ENVIADO ===")
        print(dump["challenge_sent_hex"])
        print("\n=== CHALLENGE RESPUESTA (texto) ===")
        print("\n---\n".join(dump["challenge_resp_text"]))
        for i, att in enumerate(dump["rcon_attempts"], 1):
            print(f"\n=== RCON INTENTO {i} (quoted_pass={att['quoted']}) ===")
            print(att["packet_hex"])
            print("\nASCII:\n", att["packet_ascii"])
            print("\nRESPUESTA (hex):")
            print("\n---\n".join(att["responses_hex"]))
            print("\nRESPUESTA (texto):")
            print(att["responses_text_joined"] or "(vacía)")
    print("\n=== RESPUESTA FINAL ===")
    print(resp or "(vacía)")

if __name__ == "__main__":
    _main()
