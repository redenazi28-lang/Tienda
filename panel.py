#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Panel SSH: administra cuentas SSH en uno o varios VPS.
Solo usa la biblioteca estandar de Python 3 (3.7+). Debe correr como root."""
import os, sys, shutil, json, sqlite3, subprocess, threading, time, secrets, hashlib, hmac, re, shlex, ssl, math, datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie

APP = os.environ.get("PANEL_DIR", os.path.dirname(os.path.abspath(__file__)))
DATA = os.environ.get("PANEL_DATA", "/var/lib/panelvpn")
PORT = int(os.environ.get("PANEL_PORT", "8443"))
DB = os.path.join(DATA, "panel.db")
KEY = os.path.join(DATA, "id_ed25519")
CERT = os.path.join(DATA, "cert.pem")
CERTKEY = os.path.join(DATA, "key.pem")
KNOWN = os.path.join(DATA, "known_hosts")

USER_RE = re.compile(r"^[a-z][a-z0-9_-]{2,23}$")
PASS_RE = re.compile(r"^[\x21-\x7e]{4,32}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
SUSER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LOCAL = ("local", "localhost", "127.0.0.1")
P = "PATH=/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin; "
SAFE_SHELLS = ("/bin/false", "/usr/bin/false", "/usr/sbin/nologin", "/sbin/nologin")
SESS_COMM = ("sshd", "sshd-session", "dropbear")
NOEXP = "2099-12-31"

DBLOCK = threading.RLock()
OPLOCK = threading.Lock()
_con = None


class ApiError(Exception):
    def __init__(self, msg, code=400):
        Exception.__init__(self, msg)
        self.code = code


# ---------------- base de datos ----------------
def db():
    global _con
    if _con is None:
        os.makedirs(DATA, mode=0o700, exist_ok=True)
        _con = sqlite3.connect(DB, check_same_thread=False, isolation_level=None)
        _con.row_factory = sqlite3.Row
        try:
            os.chmod(DB, 0o600)
        except OSError:
            pass
        _con.executescript("""
        CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, name TEXT, role TEXT,
            salt TEXT, hash TEXT, credits INTEGER DEFAULT 0, suspended INTEGER DEFAULT 0, created INTEGER);
        CREATE TABLE IF NOT EXISTS servers(id INTEGER PRIMARY KEY, name TEXT, host TEXT, port INTEGER, kind TEXT,
            loc TEXT, cap INTEGER, suser TEXT DEFAULT 'root', cat TEXT DEFAULT 'General', poll INTEGER DEFAULT 5);
        CREATE TABLE IF NOT EXISTS clients(id INTEGER PRIMARY KEY, user TEXT, pass TEXT, server_id INTEGER, exp TEXT,
            lim INTEGER, owner INTEGER, note TEXT, suspended INTEGER DEFAULT 0, trial INTEGER DEFAULT 0,
            created INTEGER, UNIQUE(server_id, user));
        """)
        if not q("SELECT 1 FROM settings WHERE k='init'", one=True):
            x("INSERT INTO settings VALUES('init','1')")
            x("INSERT INTO servers(name,host,port,kind,loc,cap) VALUES('Este VPS','local',22,'local','',200)")
    return _con


def q(sql, args=(), one=False):
    with DBLOCK:
        cur = db().execute(sql, args)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def x(sql, args=()):
    with DBLOCK:
        return db().execute(sql, args).lastrowid


def setting(k, default):
    r = q("SELECT v FROM settings WHERE k=?", (k,), one=True)
    return r["v"] if r else default


def today():
    return datetime.date.today()


# ---------------- contrasenas del panel ----------------
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000).hex()
    return salt, h


def check_pw(row, pw):
    return hmac.compare_digest(hash_pw(pw, row["salt"])[1], row["hash"])


# ---------------- ejecutar en un servidor ----------------
def sh(*a):
    return " ".join(shlex.quote(str(i)) for i in a)


def ssh_opts(port):
    return ["-p", str(port), "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + KNOWN,
            "-o", "ConnectTimeout=6"]


def run(s, script, stdin=None, timeout=25):
    if s["kind"] == "local":
        cmd = ["/bin/sh", "-c", script]
    else:
        user = s.get("suser") or "root"
        if user != "root":
            script = "sudo -n /bin/sh -c " + shlex.quote(script)
        cmd = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ControlMaster=auto",
               "-o", "ControlPath=" + os.path.join(DATA, "cm-%C"), "-o", "ControlPersist=120"] \
              + ssh_opts(s["port"]) + [user + "@" + s["host"], script]
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "el servidor no respondió a tiempo"
    except OSError as e:
        return 127, "", "no such file: " + str(e)


def must(s, script, stdin=None, what="la operación"):
    rc, out, err = run(s, script, stdin)
    if rc != 0:
        raise ApiError("Falló %s en %s: %s" % (what, s["name"], (err or "código %d" % rc)[:200]), 502)
    return out


def guard(user):
    # nunca tocar cuentas del sistema (uid menor a 1000)
    return '[ "$(id -u %s 2>/dev/null || echo 0)" -ge 1000 ] || exit 77; ' % shlex.quote(user)


def explain_ssh(err, rc, host, port, user):
    e = (err or "").lower()
    if "permission denied" in e or rc == 5:
        return ("El VPS rechazó el usuario o la contraseña. Revisá la contraseña de %s. Si está bien, ese VPS no deja "
                "entrar a %s con contraseña: en él ejecutá  sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/;"
                "s/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && systemctl restart ssh"
                % (user, user))
    if "connection refused" in e:
        return "El puerto %d está cerrado en %s. Revisá el puerto SSH del VPS." % (port, host)
    if "could not resolve" in e or "name or service not known" in e:
        return "No existe el dominio %s. Probá con la IP." % host
    if "timed out" in e or "no route" in e or "unreachable" in e or rc == 124:
        return ("No llego a %s:%d. Revisá la IP, el puerto y que el firewall del proveedor deje entrar por ese puerto."
                % (host, port))
    if "host key" in e or "identification has changed" in e:
        return "La huella del VPS cambió (¿lo reinstalaste?). Volvé a intentar: el panel la actualiza solo."
    if "sudo" in e:
        return "El usuario %s no puede usar sudo sin contraseña. Usá root." % user
    if rc == 127 or "no such file" in e:
        return "Falta el programa ssh en el VPS del panel. Ejecutá: apt install -y openssh-client sshpass"
    return (err or "código %d" % rc)[:220]


def forget_host(host, port):
    name = host if port == 22 else "[%s]:%d" % (host, port)
    try:
        subprocess.run(["ssh-keygen", "-f", KNOWN, "-R", name], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass


def askpass_file():
    path = os.path.join(DATA, "askpass.sh")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write('#!/bin/sh\nprintf \'%s\\n\' "$PANEL_SSHPASS"\n')
        os.chmod(path, 0o700)
    return path


def install_key(host, port, password, user="root"):
    """Entra una vez con la contraseña y deja la llave del panel. La contraseña no se guarda."""
    pub = open(KEY + ".pub").read().strip()
    script = ("umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "
              "(grep -qxF %s ~/.ssh/authorized_keys || echo %s >> ~/.ssh/authorized_keys) && "
              "chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && "
              "(command -v restorecon >/dev/null && restorecon -R ~/.ssh; true)") % (shlex.quote(pub), shlex.quote(pub))
    base = ["ssh", "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "NumberOfPasswordPrompts=1"] + ssh_opts(port) + [user + "@" + host, script]
    env = dict(os.environ)
    if shutil.which("sshpass"):
        cmd, env["SSHPASS"] = ["sshpass", "-e"] + base, password
    else:  # sin sshpass: ssh le pide la contraseña a un ayudante (SSH_ASKPASS)
        cmd = base
        env.update(PANEL_SSHPASS=password, SSH_ASKPASS=askpass_file(), SSH_ASKPASS_REQUIRE="force",
                   DISPLAY=env.get("DISPLAY", ":0"))
    forget_host(host, port)
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=40, env=env,
                           start_new_session=True)
        rc, err = p.returncode, p.stderr.strip()
    except subprocess.TimeoutExpired:
        rc, err = 124, "timed out"
    except OSError as e:
        rc, err = 127, str(e)
    if rc != 0:
        raise ApiError(explain_ssh(err, rc, host, port, user), 502)


# ---------------- estado en vivo ----------------
STATUS = {}
POLL = P + "cat /proc/loadavg; echo @@; awk '/^MemTotal|^MemAvailable/{print $2}' /proc/meminfo; echo @@; nproc; " \
           "echo @@; ps -eo pid=,user:32=,etimes=,comm="


def poll_server(s):
    rc, out, err = run(s, POLL, timeout=12)
    st = {"up": False, "checked": time.time(), "online": {}, "err": err[:160], "load": 0, "mem": 0, "cpus": 1}
    parts = out.split("@@")
    if rc == 0 and len(parts) == 4:
        try:
            st["load"] = float(parts[0].split()[0])
            m = [int(v) for v in parts[1].split()]
            st["mem"] = round(100 * (m[0] - m[1]) / m[0]) if len(m) == 2 and m[0] else 0
            st["cpus"] = int(parts[2].strip() or 1)
            st["up"] = True
            st["err"] = ""
        except (ValueError, IndexError):
            st["err"] = "respuesta inesperada del servidor"
    if st["up"]:
        rows = dict((r["user"], r) for r in q("SELECT user,lim,exp,suspended FROM clients WHERE server_id=?", (s["id"],)))
        sess = {}
        for line in parts[3].splitlines():
            f = line.split()
            if len(f) >= 4 and f[3] in SESS_COMM and f[1] in rows and f[0].isdigit() and f[2].isdigit():
                sess.setdefault(f[1], []).append((int(f[2]), f[0]))
        kill, t = [], today().isoformat()
        for u, lst in sess.items():
            r = rows[u]
            lst.sort()  # la conexión más nueva primero
            if r["suspended"] or r["exp"] <= t:
                extra = lst
            else:
                extra = lst[:max(0, len(lst) - r["lim"])]
            kill += [pid for _, pid in extra]
            n = len(lst) - len(extra)
            if n:
                st["online"][u] = n
        if kill:
            run(s, P + "kill -KILL " + " ".join(kill), timeout=10)
    STATUS[s["id"]] = st


RUNNING = set()


def poll_guard(s):
    try:
        poll_server(s)
    except Exception as e:
        sys.stderr.write("poll %s: %r\n" % (s.get("name"), e))
    finally:
        RUNNING.discard(s["id"])


def poller():
    last = {}
    while True:
        try:
            now = time.time()
            for s in q("SELECT * FROM servers"):
                if s["id"] in RUNNING or now - last.get(s["id"], 0) < max(3, s["poll"] or 5):
                    continue
                last[s["id"]] = now
                RUNNING.add(s["id"])
                threading.Thread(target=poll_guard, args=(dict(s),), daemon=True).start()
        except Exception as e:  # el panel sigue aunque falle una vuelta
            sys.stderr.write("poller: %s\n" % e)
        time.sleep(1)


# ---------------- sesiones del panel ----------------
SESSIONS, FAILS = {}, {}
SESSION_TTL = 12 * 3600


def session_user(handler):
    c = SimpleCookie(handler.headers.get("Cookie", ""))
    tok = c["sid"].value if "sid" in c else ""
    s = SESSIONS.get(tok)
    if not s or s[1] < time.time():
        SESSIONS.pop(tok, None)
        return None, tok
    u = q("SELECT * FROM users WHERE id=?", (s[0],), one=True)
    if not u or u["suspended"]:
        SESSIONS.pop(tok, None)
        return None, tok
    s[1] = time.time() + SESSION_TTL
    return u, tok


# ---------------- helpers de validación ----------------
def num(d, k, lo, hi, what):
    try:
        v = int(d.get(k))
    except (TypeError, ValueError):
        raise ApiError("%s tiene que ser un número." % what)
    if v < lo or v > hi:
        raise ApiError("%s va de %d a %d." % (what, lo, hi))
    return v


def text(d, k, maxlen=60):
    return str(d.get(k) or "").strip()[:maxlen]


def get_server(sid):
    s = q("SELECT * FROM servers WHERE id=?", (sid,), one=True)
    if not s:
        raise ApiError("Ese servidor ya no existe.", 404)
    return dict(s)


def get_client(me, cid):
    c = q("SELECT * FROM clients WHERE id=?", (cid,), one=True)
    if not c or (me["role"] != "admin" and c["owner"] != me["id"]):
        raise ApiError("Ese cliente no existe.", 404)
    return c


def charge(me, cost):
    if me["role"] == "admin" or cost == 0:
        return
    cur = q("SELECT credits FROM users WHERE id=?", (me["id"],), one=True)["credits"]
    if cur < cost:
        raise ApiError("Tenés %d créditos y hacen falta %d." % (cur, cost))


def pay(me, cost):
    if me["role"] != "admin" and cost:
        x("UPDATE users SET credits=credits-? WHERE id=?", (cost, me["id"]))


# ---------------- acciones ----------------
def a_client_create(me, d):
    user, pw = text(d, "user", 24).lower(), str(d.get("pass") or "")
    if not USER_RE.match(user):
        raise ApiError("El usuario lleva 3 a 24 caracteres: minúsculas, números, guion. Empieza con letra.")
    if not PASS_RE.match(pw):
        raise ApiError("La contraseña lleva 4 a 32 caracteres, sin espacios ni acentos.")
    days, lim = num(d, "days", 1, 365, "Los días"), num(d, "limit", 1, 10, "Las conexiones")
    s = get_server(d.get("server"))
    if q("SELECT 1 FROM clients WHERE server_id=? AND user=?", (s["id"], user), one=True):
        raise ApiError("Ya existe un cliente con ese usuario en ese servidor.")
    trial = 1 if days == 1 else 0
    cost = 0 if trial else max(1, math.ceil(days / 30)) * lim
    if me["role"] != "admin":
        if trial:
            maxt = int(setting("trialsPerDay", "5"))
            start = int(time.mktime(today().timetuple()))
            n = q("SELECT COUNT(*) n FROM clients WHERE owner=? AND trial=1 AND created>=?", (me["id"], start), one=True)["n"]
            if n >= maxt:
                raise ApiError("Ya usaste las %d pruebas de hoy." % maxt)
            lim = 1
        charge(me, cost)
    exp = (today() + datetime.timedelta(days=days)).isoformat()
    must(s, P + "(grep -qx /bin/false /etc/shells || echo /bin/false >> /etc/shells); "
         + sh("useradd", "-M", "-N", "-s", "/bin/false", "-e", exp, user) + " && chpasswd",
         "%s:%s\n" % (user, pw), "crear la cuenta")
    x("INSERT INTO clients(user,pass,server_id,exp,lim,owner,note,trial,created) VALUES(?,?,?,?,?,?,?,?,?)",
      (user, pw, s["id"], exp, lim, None if me["role"] == "admin" else me["id"], text(d, "note"), trial, int(time.time())))
    pay(me, cost)
    return {"cost": cost}


def a_client_renew(me, d):
    c = get_client(me, d.get("id"))
    days = num(d, "days", 1, 365, "Los días")
    cost = max(1, math.ceil(days / 30)) * c["lim"]
    charge(me, cost)
    base = today()
    if c["exp"] != NOEXP and c["exp"] > base.isoformat():
        base = datetime.date.fromisoformat(c["exp"])
    exp = (base + datetime.timedelta(days=days)).isoformat()
    must(get_server(c["server_id"]), P + guard(c["user"]) + sh("chage", "-E", exp, c["user"]), what="renovar")
    x("UPDATE clients SET exp=?, trial=0 WHERE id=?", (exp, c["id"]))
    pay(me, cost)
    return {"exp": exp, "cost": cost}


def a_client_update(me, d):
    c = get_client(me, d.get("id"))
    s = get_server(c["server_id"])
    pw = str(d.get("pass") or "")
    if pw and pw != c["pass"]:
        if not PASS_RE.match(pw):
            raise ApiError("La contraseña lleva 4 a 32 caracteres, sin espacios ni acentos.")
        must(s, P + guard(c["user"]) + "chpasswd", "%s:%s\n" % (c["user"], pw), "cambiar la contraseña")
        x("UPDATE clients SET pass=? WHERE id=?", (pw, c["id"]))
    x("UPDATE clients SET note=? WHERE id=?", (text(d, "note"), c["id"]))
    if me["role"] == "admin":
        if d.get("limit") is not None:
            x("UPDATE clients SET lim=? WHERE id=?", (num(d, "limit", 1, 10, "Las conexiones"), c["id"]))
        exp = str(d.get("exp") or "")
        if exp and exp != c["exp"]:
            if not DATE_RE.match(exp):
                raise ApiError("La fecha de vencimiento no es válida.")
            must(s, P + guard(c["user"]) + sh("chage", "-E", exp, c["user"]), what="cambiar el vencimiento")
            x("UPDATE clients SET exp=? WHERE id=?", (exp, c["id"]))
    return {}


def a_client_suspend(me, d):
    c = get_client(me, d.get("id"))
    s, u = get_server(c["server_id"]), c["user"]
    if d.get("on"):
        must(s, P + guard(u) + sh("usermod", "-L", u) + " && { " + sh("pkill", "-KILL", "-u", u) + "; true; }", what="suspender")
    else:
        must(s, P + guard(u) + sh("usermod", "-U", u), what="activar")
    x("UPDATE clients SET suspended=? WHERE id=?", (1 if d.get("on") else 0, c["id"]))
    return {}


def a_client_delete(me, d):
    c = get_client(me, d.get("id"))
    s, u = get_server(c["server_id"]), c["user"]
    rc, out, err = run(s, P + "id " + shlex.quote(u) + " >/dev/null 2>&1 || exit 0; " + guard(u)
                       + sh("pkill", "-KILL", "-u", u) + "; sleep 0.3; " + sh("userdel", "-f", u))
    if rc != 0:
        raise ApiError("No pude borrar la cuenta en %s: %s" % (s["name"], (err or "código %d" % rc)[:200]), 502)
    x("DELETE FROM clients WHERE id=?", (c["id"],))
    return {}


def connect_check(s):
    rc, out, err = run(s, "id -u", timeout=20)
    if rc != 0 or out.strip() != "0":
        if rc == 0:
            err = "sudo"
        raise ApiError(explain_ssh(err, rc, s["host"], s["port"], s.get("suser") or "root"), 502)


def a_server_add(me, d):
    name, host = text(d, "name", 30), text(d, "host", 253)
    if not name:
        raise ApiError("Ponele un nombre al servidor.")
    if not host:
        raise ApiError("Cargá la IP o el dominio del VPS.")
    kind = "local" if host.lower() in LOCAL else "remote"
    if kind == "remote" and not HOST_RE.match(host):
        raise ApiError("La IP o el dominio no es válido. Escribilo sin http:// y sin espacios, por ejemplo 45.12.34.56")
    port = num(d, "port", 1, 65535, "El puerto SSH")
    if kind == "local":
        host = "local"
    if q("SELECT 1 FROM servers WHERE host=? AND port=?", (host, port), one=True):
        raise ApiError("Ese VPS ya está cargado en el panel.")
    suser = text(d, "suser", 32) or "root"
    if not SUSER_RE.match(suser):
        raise ApiError("El usuario SSH no es válido.")
    s = {"name": name, "host": host, "port": port, "kind": kind, "suser": suser}
    pw = str(d.get("password") or "")
    if kind == "remote":
        if pw:
            install_key(host, port, pw, suser)
        elif not d.get("keyOnly"):
            raise ApiError("Escribí la contraseña de %s." % suser)
    connect_check(s)
    sid = x("INSERT INTO servers(name,host,port,kind,loc,cap,suser,cat,poll) VALUES(?,?,?,?,?,?,?,?,?)",
            (name, host, port, kind, text(d, "loc", 40), num(d, "cap", 1, 100000, "Las cuentas máximas"), suser,
             text(d, "cat", 20) or "General", num(d, "poll", 3, 300, "El intervalo")))
    s["id"] = sid
    try:
        poll_server(s)
    except Exception:
        pass
    return {"id": sid}


def a_server_reconnect(me, d):
    s = get_server(d.get("id"))
    if s["kind"] == "local":
        connect_check(s)
        return {}
    port = num(d, "port", 1, 65535, "El puerto SSH")
    pw = str(d.get("password") or "")
    if not pw:
        raise ApiError("Escribí la contraseña de %s." % s["suser"])
    install_key(s["host"], port, pw, s["suser"])
    s["port"] = port
    connect_check(s)
    x("UPDATE servers SET port=? WHERE id=?", (port, s["id"]))
    poll_server(s)
    return {}


def a_server_update(me, d):
    s = get_server(d.get("id"))
    name = text(d, "name", 30)
    if not name:
        raise ApiError("Ponele un nombre al servidor.")
    x("UPDATE servers SET name=?, loc=?, cap=?, cat=?, poll=? WHERE id=?",
      (name, text(d, "loc", 40), num(d, "cap", 1, 100000, "La capacidad"), text(d, "cat", 20) or "General",
       num(d, "poll", 3, 300, "El intervalo"), s["id"]))
    return {}


def a_server_delete(me, d):
    s = get_server(d.get("id"))
    n = q("SELECT COUNT(*) n FROM clients WHERE server_id=?", (s["id"],), one=True)["n"]
    if n:
        raise ApiError("Ese servidor tiene %d cuentas. Borralas antes de quitarlo del panel." % n)
    x("DELETE FROM servers WHERE id=?", (s["id"],))
    STATUS.pop(s["id"], None)
    return {}


def a_server_sync(me, d):
    """Importa cuentas que ya existen en el VPS (solo las que no tienen shell)."""
    s = get_server(d.get("id"))
    out = must(s, P + "getent passwd; echo @@; cat /etc/shadow", what="leer las cuentas")
    pw, shadow = out.split("@@", 1)
    sh_map = {}
    for line in shadow.splitlines():
        f = line.split(":")
        if len(f) >= 8:
            sh_map[f[0]] = f
    have = set(r["user"] for r in q("SELECT user FROM clients WHERE server_id=?", (s["id"],)))
    n = 0
    for line in pw.splitlines():
        f = line.split(":")
        if len(f) < 7 or not f[2].isdigit():
            continue
        u, uid, shell = f[0], int(f[2]), f[6].strip()
        if uid < 1000 or uid >= 60000 or shell not in SAFE_SHELLS or not USER_RE.match(u) or u in have:
            continue
        sf = sh_map.get(u)
        if not sf or not sf[1].lstrip("!").startswith("$"):
            continue  # sin contraseña cargada: es una cuenta de servicio, no de un cliente
        exp = NOEXP
        if sf[7].isdigit():
            exp = (datetime.date(1970, 1, 1) + datetime.timedelta(days=int(sf[7]))).isoformat()
        locked = 1 if sf[1].startswith("!") else 0
        x("INSERT INTO clients(user,pass,server_id,exp,lim,owner,note,suspended,created) VALUES(?,?,?,?,1,NULL,'importada',?,?)",
          (u, "", s["id"], exp, locked, int(time.time())))
        n += 1
    return {"imported": n}


def a_reseller_create(me, d):
    username, pw, name = text(d, "username", 24).lower(), str(d.get("password") or ""), text(d, "name", 30)
    if not USER_RE.match(username):
        raise ApiError("El usuario lleva 3 a 24 caracteres: minúsculas, números, guion. Empieza con letra.")
    if len(pw) < 8:
        raise ApiError("La contraseña del revendedor necesita 8 caracteres o más.")
    if q("SELECT 1 FROM users WHERE username=?", (username,), one=True):
        raise ApiError("Ese nombre de usuario ya está en uso.")
    salt, h = hash_pw(pw)
    x("INSERT INTO users(username,name,role,salt,hash,credits,created) VALUES(?,?,?,?,?,?,?)",
      (username, name or username, "reseller", salt, h, num(d, "credits", 0, 1000000, "Los créditos"), int(time.time())))
    return {}


def get_reseller(rid):
    r = q("SELECT * FROM users WHERE id=? AND role='reseller'", (rid,), one=True)
    if not r:
        raise ApiError("Ese revendedor ya no existe.", 404)
    return r


def a_reseller_credits(me, d):
    r = get_reseller(d.get("id"))
    delta = num(d, "delta", -1000000, 1000000, "La cantidad")
    if delta == 0:
        raise ApiError("Escribí una cantidad distinta de cero.")
    if r["credits"] + delta < 0:
        raise ApiError("No puede quedar con saldo negativo.")
    x("UPDATE users SET credits=credits+? WHERE id=?", (delta, r["id"]))
    return {}


def a_reseller_suspend(me, d):
    r = get_reseller(d.get("id"))
    x("UPDATE users SET suspended=? WHERE id=?", (1 if d.get("on") else 0, r["id"]))
    return {}


def a_reseller_password(me, d):
    r = get_reseller(d.get("id"))
    pw = str(d.get("password") or "")
    if len(pw) < 8:
        raise ApiError("La contraseña necesita 8 caracteres o más.")
    salt, h = hash_pw(pw)
    x("UPDATE users SET salt=?, hash=? WHERE id=?", (salt, h, r["id"]))
    return {}


def a_reseller_delete(me, d):
    r = get_reseller(d.get("id"))
    x("UPDATE clients SET owner=NULL WHERE owner=?", (r["id"],))
    x("DELETE FROM users WHERE id=?", (r["id"],))
    return {}


def a_settings(me, d):
    x("INSERT OR REPLACE INTO settings VALUES('brand',?)", (text(d, "brand", 24) or "Mi Panel SSH",))
    x("INSERT OR REPLACE INTO settings VALUES('price',?)", (str(num(d, "price", 0, 100000000, "El precio")),))
    x("INSERT OR REPLACE INTO settings VALUES('defDays',?)", (str(num(d, "defDays", 1, 365, "Los días por defecto")),))
    ports = re.sub(r"[^0-9, ]", "", text(d, "ports", 40)).strip(" ,") or "80"
    x("INSERT OR REPLACE INTO settings VALUES('ports',?)", (ports,))
    x("INSERT OR REPLACE INTO settings VALUES('trialsPerDay',?)", (str(num(d, "trialsPerDay", 0, 1000, "Las pruebas por día")),))
    return {}


def a_password(me, d):
    if not check_pw(me, str(d.get("old") or "")):
        raise ApiError("La contraseña actual no coincide.")
    pw = str(d.get("new") or "")
    if len(pw) < 8:
        raise ApiError("La contraseña nueva necesita 8 caracteres o más.")
    salt, h = hash_pw(pw)
    x("UPDATE users SET salt=?, hash=? WHERE id=?", (salt, h, me["id"]))
    return {}


ACTIONS = {  # nombre: (función, solo admin)
    "client/create": (a_client_create, False), "client/renew": (a_client_renew, False),
    "client/update": (a_client_update, False), "client/suspend": (a_client_suspend, False),
    "client/delete": (a_client_delete, False), "password": (a_password, False),
    "server/add": (a_server_add, True), "server/update": (a_server_update, True),
    "server/delete": (a_server_delete, True), "server/reconnect": (a_server_reconnect, True), "server/sync": (a_server_sync, True),
    "reseller/create": (a_reseller_create, True), "reseller/credits": (a_reseller_credits, True),
    "reseller/suspend": (a_reseller_suspend, True), "reseller/password": (a_reseller_password, True),
    "reseller/delete": (a_reseller_delete, True), "settings": (a_settings, True),
}


def state(me):
    admin = me["role"] == "admin"
    now = time.time()
    servers, counts = [], {}
    for r in q("SELECT server_id, COUNT(*) n FROM clients GROUP BY server_id"):
        counts[r["server_id"]] = r["n"]
    for s in q("SELECT * FROM servers ORDER BY id"):
        st = STATUS.get(s["id"], {})
        o = {"id": s["id"], "name": s["name"], "loc": s["loc"], "up": bool(st.get("up")), "known": bool(st)}
        if admin:
            o.update(host=s["host"], port=s["port"], kind=s["kind"], cap=s["cap"], suser=s["suser"], cat=s["cat"], poll=s["poll"], accounts=counts.get(s["id"], 0),
                     load=st.get("load", 0), cpus=st.get("cpus", 1), mem=st.get("mem", 0), err=st.get("err", ""),
                     online=sum(st.get("online", {}).values()), ago=int(now - st["checked"]) if st else None)
        servers.append(o)
    names = dict((u["id"], u["name"]) for u in q("SELECT id,name FROM users"))
    rows = q("SELECT * FROM clients ORDER BY exp") if admin else q("SELECT * FROM clients WHERE owner=? ORDER BY exp", (me["id"],))
    clients = [{"id": c["id"], "user": c["user"], "pass": c["pass"], "server": c["server_id"], "exp": c["exp"],
                "limit": c["lim"], "owner": c["owner"], "ownerName": names.get(c["owner"], "") if admin else "",
                "note": c["note"] or "", "suspended": bool(c["suspended"]), "trial": bool(c["trial"]), "created": c["created"],
                "online": STATUS.get(c["server_id"], {}).get("online", {}).get(c["user"], 0)} for c in rows]
    out = {"me": {"id": me["id"], "username": me["username"], "name": me["name"], "role": me["role"], "credits": me["credits"]},
           "brand": setting("brand", "Mi Panel SSH"), "defDays": int(setting("defDays", "30")),
           "trialsPerDay": int(setting("trialsPerDay", "5")), "ports": setting("ports", "80"), "today": today().isoformat(),
           "servers": servers, "clients": clients}
    if admin:
        out["price"] = int(setting("price", "3500"))
        out["resellers"] = [{"id": u["id"], "username": u["username"], "name": u["name"], "credits": u["credits"],
                             "suspended": bool(u["suspended"])} for u in q("SELECT * FROM users WHERE role='reseller' ORDER BY id")]
        try:
            out["pubkey"] = open(KEY + ".pub").read().strip()
        except OSError:
            out["pubkey"] = ""
    return out


# ---------------- servidor web ----------------
class H(BaseHTTPRequestHandler):
    server_version = "panel"
    timeout = 30
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def out(self, code, body, ctype="application/json; charset=utf-8", cookie=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        if cookie is not None:
            self.send_header("Set-Cookie", "sid=%s; Path=/; HttpOnly; SameSite=Strict%s%s" % (
                cookie, "; Secure" if self.server.tls else "", "" if cookie else "; Max-Age=0"))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(APP, "index.html"), "rb") as f:
                    return self.out(200, f.read(), "text/html; charset=utf-8")
            except OSError:
                return self.out(500, b"Falta index.html", "text/plain; charset=utf-8")
        if path == "/api/state":
            me, _ = session_user(self)
            if not me:
                return self.out(401, {"error": "Iniciá sesión."})
            return self.out(200, state(me))
        self.out(404, {"error": "No existe."})

    def do_POST(self):
        path = self.path.split("?")[0]
        if self.headers.get("X-Requested-With") != "panel" or not path.startswith("/api/"):
            return self.out(403, {"error": "Pedido no permitido."})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 65536:
                return self.out(413, {"error": "Pedido demasiado grande."})
            d = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(d, dict):
                raise ValueError
        except ValueError:
            return self.out(400, {"error": "Pedido mal formado."})
        name = path[5:]
        if name == "login":
            return self.login(d)
        me, tok = session_user(self)
        if name == "logout":
            SESSIONS.pop(tok, None)
            return self.out(200, {}, cookie="")
        if not me:
            return self.out(401, {"error": "Iniciá sesión."})
        act = ACTIONS.get(name)
        if not act or (act[1] and me["role"] != "admin"):
            return self.out(403, {"error": "No tenés permiso para eso."})
        try:
            with OPLOCK:
                res = act[0](me, d)
            self.out(200, res or {})
        except ApiError as e:
            self.out(e.code, {"error": str(e)})
        except Exception as e:
            sys.stderr.write("error en %s: %r\n" % (name, e))
            self.out(500, {"error": "Error interno del panel."})

    def login(self, d):
        ip = self.client_address[0]
        f = FAILS.get(ip, [0, 0])
        if f[1] > time.time():
            return self.out(429, {"error": "Demasiados intentos. Esperá unos minutos."})
        u = q("SELECT * FROM users WHERE username=?", (str(d.get("username") or "").strip().lower(),), one=True)
        ok = bool(u) and check_pw(u, str(d.get("password") or ""))
        if not u:
            hash_pw("x")  # mismo tiempo de respuesta exista o no el usuario
        if not ok or u["suspended"]:
            f[0] += 1
            if f[0] >= 5:
                f = [0, time.time() + 300]
            FAILS[ip] = f
            return self.out(401, {"error": "Tu cuenta está suspendida." if ok else "Usuario o contraseña incorrectos."})
        FAILS.pop(ip, None)
        tok = secrets.token_urlsafe(32)
        SESSIONS[tok] = [u["id"], time.time() + SESSION_TTL]
        self.out(200, {}, cookie=tok)


def serve():
    db()
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    httpd.daemon_threads = True
    httpd.tls = os.path.exists(CERT) and os.path.exists(CERTKEY)
    if httpd.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, CERTKEY)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=poller, daemon=True).start()
    print("Panel SSH en %s://0.0.0.0:%d" % ("https" if httpd.tls else "http", PORT), flush=True)
    httpd.serve_forever()


def set_admin(reset):
    db()
    pw = sys.stdin.readline().strip()
    if len(pw) < 8:
        sys.exit("La contraseña necesita 8 caracteres o más.")
    a = q("SELECT * FROM users WHERE role='admin' ORDER BY id", one=True)
    salt, h = hash_pw(pw)
    if a and not reset:
        sys.exit(3)
    if a:
        x("UPDATE users SET salt=?, hash=?, suspended=0 WHERE id=?", (salt, h, a["id"]))
    else:
        x("INSERT INTO users(username,name,role,salt,hash,created) VALUES('admin','Administrador','admin',?,?,?)",
          (salt, h, int(time.time())))


if __name__ == "__main__":
    if "--init-admin" in sys.argv:
        set_admin(False)
    elif "--reset-admin" in sys.argv:
        set_admin(True)
    else:
        serve()
