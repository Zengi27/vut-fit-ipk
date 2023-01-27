import socket
import sys
import os 

# Funkcia na poziadavku GET 
def get_request(file_path, server, port, server_name):
    client_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_tcp.connect((server, port))              # pripojenie sa na server        
    get_msg = "GET " + file_path + " FSP/1.0\r\n" + "Hostname: " + server_name + "\r\n" + "Agent: xhomol27\r\n\r\n"
        
    get_msg = str.encode(get_msg)
    client_tcp.sendall(get_msg)                     # zaslanie pozdiadavky GET

    final_data = client_tcp.recv(bufferSize) 
    while True:
        data = client_tcp.recv(bufferSize)

        if not data:
            break
        else:
            final_data = final_data + data

    msg_status = final_data.split(b"\r\n\r\n", 1)[0]    # Ulozenie hlavicky
    final_data = final_data.split(b"\r\n\r\n", 1)[1]    # Odseknutie hlavicky


    if msg_status.find(b"Succes") == -1:
        if msg_status.find(b"Bad Request") != -1:
            print("ERROR: Server nerozumie poziadavke")
            sys.exit(1)
        elif msg_status.find(b"Server Error") != -1:
            print("ERROR: Ina chyba serveru")
            sys.exit(1)

        print("ERROR: Subor sa nenasiel na severy")
        sys.exit(1)
    
    if file_path == "index":                                   
        f = open("index", mode="wb")                    # otvorie suboru index pre zapis 
    else:
        if (file_path.find("/") != -1):    
            try:
                os.makedirs(os.path.dirname(file_path)) # vytvorenie priecinku ak treba
            except:
                pass
        #if (file_path.find("/") != -1):             
        #    os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        f = open(file_path, mode="wb")                  # Otvorenie suboru pre zapis
    
    f.write(final_data)     
    f.close
###


# spracovanie argumentov 
if len(sys.argv) == 5 :
    if sys.argv[1] != "-n" or sys.argv[3] != "-f":
        print("ERROR: Chyba argumentu -n alebo -f")
        sys.exit(1)

    arg_server = sys.argv[2].split(':')[0]
    arg_port = sys.argv[2].split(':')[1]
    arg_surl = sys.argv[4].split('fsp://')[1]
    arg_server_name = arg_surl.split('/')[0]
    arg_file_path = arg_surl.split('/', 1)[1]
    
    if (arg_port.isdigit())  and (int(arg_port) >= 1024 and int(arg_port) <= 65635):
        pass
    else:
        print("ERROR: Chybny port")
        sys.exit(1)

else: 
    print("ERROR: Nespravny pocet argumentov.")
    sys.exit(1)



server_udp = arg_server
port_udp = int(arg_port)
bufferSize = 2048

bytes_to_send = "WHEREIS " + arg_server_name
bytes_to_send = str.encode(bytes_to_send)

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

client.sendto(bytes_to_send, (server_udp, port_udp))

msg, address = client.recvfrom(bufferSize)

msg = str(msg)                              # sprava odpovede na WHEREIS

if (msg.find("ERR Not Found")) != -1:       # kontrola ci dany server existuje
    print("ERROR: Chyba meno servera neexistuje")
    sys.exit(1)

elif (msg.find("ERR Syntax")) != -1:     
    print("ERROR: Chyba syntaxe")
    sys.exit(1)

msg = msg.replace('b', "")                  # odstranenie 'b'
msg = msg.replace("\'", "")                 # odstranenie '

msg = msg.rsplit(" ")
msg_status = msg[0]
server_tcp = msg[1].split(":")[0]
port_tcp = msg[1].split(":")[1]
port_tcp = int(port_tcp)

get_all = False
if arg_file_path == "*":
    get_all = True


if get_all == False:
    get_request(arg_file_path, server_tcp, port_tcp, arg_server_name)
else:
    # Vytvorenie indexu
    get_request("index", server_tcp, port_tcp, arg_server_name)     

    f = open("index", "r")                          # otvorenie suboru index
    lines = f.readlines()                           # precitanie celeho suboru

    for line in lines:
        file_path = line.strip()                    # nacitanie jedneho riadku 
        
        get_request(file_path, server_tcp, port_tcp, arg_server_name)
    f.close
