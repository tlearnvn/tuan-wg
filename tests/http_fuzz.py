#!/usr/bin/env python3
"""Tuấn WireGuard - gửi request HTTP dị dạng/ngẫu nhiên để kiểm tra độ bền của HTTP parser.
Cách dùng: tests/http_fuzz.py 127.0.0.1 18400 [số_vòng]"""
import os, random, socket, sys, time

host, port = sys.argv[1], int(sys.argv[2])
rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
random.seed(1234)

CASES = [
    b"GET / HTTP/1.1\r\n\r\n",
    b"GET /api/public/info HTTP/1.0\r\n\r\n",
    b"\r\n\r\n",
    b"GARBAGE\r\n\r\n",
    b"GET\r\n\r\n",
    b"GET / HTTP/9.9\r\n\r\n",
    b"get / HTTP/1.1\r\n\r\n",
    b"GET relative HTTP/1.1\r\n\r\n",
    b"GET /%00 HTTP/1.1\r\n\r\n",
    b"GET /%zz%%% HTTP/1.1\r\n\r\n",
    b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\n\r\n",
    b"GET / HTTP/1.1\r\n" + b"X-A: b\r\n" * 200 + b"\r\n",
    b"GET / HTTP/1.1\r\nHost: x\r\n" + b"X: " + b"y" * 40000 + b"\r\n\r\n",
    b"POST /api/login HTTP/1.1\r\nContent-Length: -5\r\n\r\n",
    b"POST /api/login HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n",
    b"POST /api/login HTTP/1.1\r\nContent-Length: 12abc\r\n\r\n",
    b"POST /api/login HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"POST /api/login HTTP/1.1\r\nX-TWG: 1\r\nContent-Length: 10\r\n\r\n{\"a\":[[[[",
    b"POST /api/login HTTP/1.1\r\nX-TWG: 1\r\nContent-Length: 5\r\n\r\n",
    b"GET / HTTP/1.1\r\n folded\r\n\r\n",
    b"GET / HTTP/1.1\r\n:novalue\r\n\r\n",
    b"GET / HTTP/1.1\r\nCookie: twg_sid=" + b"A" * 3000 + b"\r\n\r\n",
    b"GET /api/share/" + b"x" * 300 + b" HTTP/1.1\r\n\r\n",
    b"GET /api/clients/../../etc/passwd HTTP/1.1\r\n\r\n",
    b"GET /s/../../etc/shadow HTTP/1.1\r\n\r\n",
    b"GET / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\nGET /api/public/info HTTP/1.1\r\nConnection: close\r\n\r\n",
    b"POST /api/login HTTP/1.1\r\nX-TWG: 1\r\nContent-Length: 30\r\n\r\n" + b'{"username":"\\ud800\\u0000x"}' + b"  ",
]

def send(data, read=True):
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.sendall(data)
        if read:
            s.settimeout(0.3)
            try:
                s.recv(65536)
            except socket.timeout:
                pass
        s.close()
    except OSError:
        pass

def alive():
    for _ in range(20):
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.sendall(b"GET /api/public/info HTTP/1.0\r\n\r\n")
            d = s.recv(4096)
            s.close()
            if b"200 OK" in d:
                return True
        except OSError:
            pass
        time.sleep(0.2)
    return False

t0 = time.time()
for c in CASES:
    send(c)
assert alive(), "server chết sau các ca dị dạng cố định"
methods = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"X"]
paths = [b"/", b"/api/login", b"/api/clients", b"/api/share/abc", b"/s/abc", b"/app.css", b"/api/clients/c123/config"]
from concurrent.futures import ThreadPoolExecutor

def one(seed):
    rnd = random.Random(seed)
    kind = rnd.random()
    if kind < 0.3:
        data = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 3000)))
    elif kind < 0.7:
        body = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 200)))
        hdrs = b"".join(b"%s: %s\r\n" % (bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 8))).replace(b":", b"x"),
                                          bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 20))))
                        for _ in range(rnd.randint(0, 6)))
        data = b"%s %s HTTP/1.1\r\n%sContent-Length: %d\r\n\r\n%s" % (rnd.choice(methods), rnd.choice(paths), hdrs, len(body), body)
    else:
        body = bytes(rnd.choice(b'{}[]":,0123456789.-eEtruefalsn\\u ') for _ in range(rnd.randint(0, 300)))
        data = b"POST %s HTTP/1.1\r\nX-TWG: 1\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (rnd.choice(paths), len(body), body)
    send(data, read=rnd.random() < 0.5)

with ThreadPoolExecutor(max_workers=32) as ex:
    list(ex.map(one, range(rounds)))
assert alive(), "server chết sau fuzz ngẫu nhiên"
print("fuzz OK: %d ca cố định + %d ca ngẫu nhiên trong %.1fs, server vẫn hoạt động" % (len(CASES), rounds, time.time() - t0))
