#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Proxy SSH por HTTP/WebSocket (puerto 80 por defecto).
La app del cliente manda un payload HTTP; el proxy responde 101 y conecta con el SSH local.
Solo biblioteca estandar de Python 3.7+."""
import asyncio, os, sys

LISTEN = int(os.environ.get("WS_PORT", "80"))
TARGET_HOST = os.environ.get("WS_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("WS_TARGET_PORT", "22"))
RESPONSE = os.environ.get("WS_RESPONSE", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").encode()
METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"PATCH ", b"DELETE ", b"OPTIONS ", b"CONNECT ", b"TRACE ", b"ACL ", b"PROPFIND ", b"MOVE ")
MAXHDR = 64 * 1024


async def strip_http(reader, buf):
    """Saca las cabeceras HTTP del payload (puede venir partido en varias) y devuelve lo que sigue."""
    while True:
        s = buf.lstrip(b"\r\n")
        if s.startswith(b"SSH-") or (s and not any(m.startswith(s[:len(m)]) or s.startswith(m) for m in METHODS)):
            return s
        if b"\r\n\r\n" in s:
            buf = s.split(b"\r\n\r\n", 1)[1]
            if buf:
                continue
            # puede llegar otro bloque HTTP o directamente el SSH
            try:
                buf = await asyncio.wait_for(reader.read(65536), 15)
            except asyncio.TimeoutError:
                return b""
            if not buf:
                return None
            continue
        if len(s) > MAXHDR:
            return None
        chunk = await asyncio.wait_for(reader.read(65536), 30)
        if not chunk:
            return None
        buf = s + chunk


async def pipe(r, w):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def handle(cr, cw):
    sw = None
    try:
        first = await asyncio.wait_for(cr.read(65536), 30)
        if not first:
            return
        is_http = any(first.lstrip(b"\r\n").startswith(m) for m in METHODS)
        if is_http:
            cw.write(RESPONSE)
            await cw.drain()
            rest = await strip_http(cr, first)
            if rest is None:
                return
        else:
            rest = first
        sr, sw = await asyncio.wait_for(asyncio.open_connection(TARGET_HOST, TARGET_PORT), 10)
        if rest:
            sw.write(rest)
            await sw.drain()
        await asyncio.gather(pipe(cr, sw), pipe(sr, cw))
    except Exception:
        pass
    finally:
        for w in (cw, sw):
            try:
                if w:
                    w.close()
            except Exception:
                pass


async def main():
    srv = await asyncio.start_server(handle, "0.0.0.0", LISTEN, reuse_address=True, backlog=512)
    print("Proxy SSH en el puerto %d -> %s:%d" % (LISTEN, TARGET_HOST, TARGET_PORT), flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except OSError as e:
        sys.exit("No pude abrir el puerto %d: %s" % (LISTEN, e))
