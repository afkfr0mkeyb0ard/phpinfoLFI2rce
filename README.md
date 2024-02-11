# php-lfi2rce
A Python3 script to get RCE on a PHP application with LFI and "file_uploads" activated. This attack was discovered in 2011 and here is the full and great research paper:
- https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf

### Requirements:
- Having an LFI on the targeted application
- Access to phpinfo.php (directly or via another script)
- The value `file_uploads` must be set to `on` (see phpinfo page)

### Exploit
- Change the variables at the top of the script
- Set a listener
```
nc -lnvp 4444  
```
- Exploit
```
python3 phpinfo_lfi_to_rce.py
```

### Explanation
In few words:
- If `file_uploads` is allowed, you can upload files on the server **with arbitrary content** via the `phpinfo` page.
- The files are stored in `/tmp` with a name like `php`+`6 random chars (upper, lower, number)`. For example: `/tmp/phpPGJb6o`, `/tmp/phpaVYff7`, `/tmp/phpN20G13`.
- The files are deleted at the end of the request.
- By exceeding the PHP buffer, we can retrieve the uploaded file path **before** the request ends processing on server side 
- To execute the uploaded file through the LFI before its deletion, we need to *win the race* against the server: sending a lot of requests and including them through the LFI **until the server executes the LFI request before the uploading request ends (race condition)**.

