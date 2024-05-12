from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import asyncio
import websockets
import time
import threading
import datetime
import random
import asyncio
import struct
import socket
import os
import ntplib
from datetime import datetime, timezone
import requests
import os




## ## ## ## ## ## ## ## ## ## ## ## ## 
## Convention
## ## ## ## ## ## ## ## ## ## ## ## ## 

# IID = Index Integer Date 
# IID Server = Server that receive integer and date from client
# IID Gate = Client that send to server and received from server integer and date and it index on the server
# OUTSIDE OF HANDSHAKE RSA SERVER ONLY ACCEPTE BINARY DATA of 4 or 12 bytes
# 4 bytes : integer in little format
# 12 bytes : integer in little format + 8 bytes ulong for a date value choosed by yourself
# Max value of ulong 18446744073709551615
# Max value of int -2147483647 to 2147483647
# Date convention: 
# ulong 17000000000000000000 Request to execute at this NTP date choosed by you on your clients
# ulong 16000000000000000000 Emited at NTP date choosed by you on your clients
# ulong 00000000000000000000 Date is not specified and probably is DateTime.Now() on the client
# IID server and Gate are lot looking at the date format.
# It is just a convention usefull to sync data between your clients.
# Useful if you want to exectute a task at a specific date on all your clients.

# You receive a binary data of 16 bytes from the server
# 4 bytes : index claimed of your RSA key on the server 
# 4 bytes : integer value pushed by one of your clients
# 8 bytes : ulong date value pushed by one of your clients
# if the index is negative it means that you are a guest on the server.
# Guest don't have the same rule and can be kick out at any time when server has difficulty to handle the load.
# The server can be configure to refuse guest connection.



## ## ## ## ## ## ## ## ## ## ## ## ## 
## Hello
## ## ## ## ## ## ## ## ## ## ## ## ## 



print("Hello World :) !")
print("This script it a gate to Integer RSA Tunneling Server IID.")
print("GitHub: https://github.com/EloiStree/2024_04_04_IndexIntegerDateTunnelingRSA")
print("Question(s): https://discord.gg/Jbh57NqNDH")
print("Want to play: https://discord.gg/TZvyzrMXMx")

## ## ## ## ## ## ## ## ## ## ## ## ## 
## PUBLIC
## ## ## ## ## ## ## ## ## ## ## ## ## 



## Launch a thread listening to the UDP port to relay to the server
use_local_websocket_listener=True
## This port is use to host a local websocket server to receive data from the client
## The aim is to be able to send data from webbrowser to server on unsecure websocket.
local_websocket_server_port=7073

## Launch a thread listening to the UDP port to relay to the server
use_local_udp_port_listener=True
## This port is use to listen to the UDP port to relay the data to the server
udp_port_to_listen = 3614

## This is the url of the server to fetch the websocket server to connect to
webpage_fetch_websocket_server_iid_url = "https://raw.githubusercontent.com/EloiStree/IP/main/IIDWS/SERVER.txt"
## webpage_fetch_websocket_server_iid_url =""
## This is the url of the server to connect to as a IID server web socket.
websocket_server_iid_url = "ws://81.240.94.97:4501"


## Will hidre most of the print use to debug
use_print_debug= False
## Use a random push of integer to debug the connection
use_random_push=True

use_print_on_int_change=True


## RSA Keys relative path
## It is store by default near the script execution
## You can use relative or absolute path
## keys_relative_path= "C:\\RSA_KEYS" # store on the computer
## keys_relative_path= "Keys" # store near the script execution
keys_relative_path= "Keys"

## List of local port to broadcast the data to load from PORT.txt
## Use to send int change to local application on computer 
local_port_list= ["7000", "7002", "7003", "7004", "7005",]

## List of ipv4 port to broadcast the data to load from IPV4.txt
## Use to send int change to local machine on the network
ipv4_port_list= ["168.192.1.3:3616"]


## Server NTP to listen to in aim to sync the client time with other clients.
NTP_SERVERS = ['3.be.pool.ntp.org']



## ## ## ## ## ## ## ## ## ## ## ## ## 
## PRIVATE
## ## ## ## ## ## ## ## ## ## ## ## ## 

public_key =None
private_key =None

## Time between random push in seconds
time_between_random_push=5
## Random range min and max for random push
random_range_min=15000
## Random range min and max for random push
random_range_max=45000


given_index_lock_is_set=False
given_index_lock=-1


is_connected_to_server = False
websocket_linked=None



def print_debug_params(message, value):
    if use_print_debug:
        print(message, value)

### USE ONLY THIS PRINT TO ALLOWS DISABLING PRINT FOR PERFORMANCE
def print_debug(message):
    if use_print_debug:
        print(message)











if webpage_fetch_websocket_server_iid_url:
    response = requests.get(webpage_fetch_websocket_server_iid_url)
    content = response.text
    print(f"Server IP fetched: {content}")


## ## ## ## ## ## ## ## ## ## ## ## ## 
## LOAD CONFIGURATION FILE
## ## ## ## ## ## ## ## ## ## ## ## ## 

# Read the contents of the "PORT.txt" file
if not os.path.exists('PORT.txt'):
    with open('PORT.txt', 'w') as f:
        f.write('1234,5648')

with open('PORT.txt', 'r') as f:
    port_txt = f.read().strip()
    local_port_list_sting = port_txt.split(',')
    local_port_list = [int(port) for port in local_port_list_sting]

# Read the contents of the "PORT.txt" file
if not os.path.exists('IPV4.txt'):
    with open('IPV4.txt', 'w') as f:
        f.write('168.192.1.3:3616\n168.192.1.3:3615')

with open('IPV4.txt', 'r') as f:
    ivp4_txt = f.read().strip()
    ipv4_port_list = ivp4_txt.split('\n')
    


print_debug_params(f"Local Port List:",local_port_list)
print_debug_params(f"IPv4 Port List:",ipv4_port_list)





## ## ## ## ## ## ## ## ## ## ## ## ## 
## LOAD RSA FILES
## ## ## ## ## ## ## ## ## ## ## ## ## 

private_pem_relative_path_private = os.path.join(keys_relative_path, 'RSA_PRIVATE_PEM.txt')
private_pem_relative_path_public = os.path.join(keys_relative_path, 'RSA_PUBLIC_PEM.txt')

private_key_path_file = os.path.abspath(private_pem_relative_path_private)
public_key_path_file = os.path.abspath(private_pem_relative_path_public)

print_debug_params("---- RSA_PRIVATE_PEM.txt Path |", private_key_path_file)

if not os.path.exists(private_key_path_file):
    print ("Generating new keys")
    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )
    public_key = private_key.public_key()

    # Serialize the keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )         


    folder_path = os.path.dirname(private_key_path_file)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # Save the keys to files
    with open(private_key_path_file, 'wb') as f:
        f.write(private_pem)

    with open(public_key_path_file, 'wb') as f:
        f.write(public_pem)



# Load the private key from file
with open(private_key_path_file, 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )
    
public_key = private_key.public_key()

# Serialize the keys to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1
)  

## Refuid public if lost from private given
if not os.path.exists(public_key_path_file):
    with open(public_key_path_file, 'wb') as f:
        f.write(public_pem)

       


# Print the public and private keys
print_debug_params("Public Key:\n", public_pem.decode('utf-8'))
#print_debug_params("Private Key:\n", private_pem.decode('utf-8'))







## ## ## ## ## ## ## ## ## ## ## ## ## 
## LOAD NTP TIMER OF SERVER TO SYNC TIME BETWEEN CLIENTS
## ## ## ## ## ## ## ## ## ## ## ## ## 

response = None
for server in NTP_SERVERS:
    client = ntplib.NTPClient()
    response = client.request(server, version=3)
    print_debug(f"server: {server}")
    print_debug(f"client time of request: {datetime.fromtimestamp(response.orig_time, timezone.utc)}")
    print_debug(f"server responded with: {datetime.fromtimestamp(response.tx_time, timezone.utc)}")
    print_debug(f"current time: {datetime.now(timezone.utc)}")
    print_debug(f"offset: {response.offset}") 
    orig_timestamp = response.orig_time
    tx_timestamp = response.tx_time

    # Convert NTP timestamps to datetime objects
    orig_datetime = datetime.fromtimestamp(orig_timestamp,timezone.utc).timestamp()
    tx_datetime = datetime.fromtimestamp(tx_timestamp,timezone.utc).timestamp()

    print_debug(f"{orig_datetime}\t\t:Client UTC")
    print_debug(f"{tx_datetime} \t\t: Server UTC")


def get_current_time_with_offset():
    global response
    offset = response.offset
    current_datetime = datetime.now(timezone.utc)
    current_timestamp_utc = current_datetime.timestamp()
    current_timestamp_with_offset = current_timestamp_utc + offset
    return current_timestamp_with_offset

print_debug(f"{get_current_time_with_offset()} \t\t: Client with offset")
time.sleep(3)
print_debug(f"{get_current_time_with_offset()} \t\t: Client with offset 3s later")




# Check if 'private_key.pem' exists




async def broadcast_iid_on_udp_port(byte_data):
    global local_port_list
    
    sock= socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for port in local_port_list:
        sock.sendto(byte_data, ('localhost', port))
    for ipv4_port in ipv4_port_list:
        ip, port = ipv4_port.strip().split(':')
        sock.sendto(byte_data, (ip, int(port)))
    sock.close()


    



def sign_message(message):
    global private_key
    global public_key
    # Sign a message
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Convert the signature to base64
    signature_b64 = base64.b64encode(signature)



    # Print the base64 encoded signature
    print_debug_params("Signature (Base64):\n", signature_b64.decode('utf-8'))

    # Convert the base64 encoded signature back to bytes
    signature_bytes = base64.b64decode(signature_b64)

    # Verify the signature
    public_key = private_key.public_key()
    try:
        public_key.verify(
            signature_bytes,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print_debug("Signature is valid.")
    except Exception as e:
        print_debug("Signature is invalid.")


    return signature_b64.decode('utf-8')



 


async def push_byte_as_raw_to_server_iid(bytes_4_12):
    if(len(bytes_4_12) == 4 or len(bytes_4_12) == 12):
        if(websocket_linked is not None and is_connected_to_server):
            await websocket_linked.send(bytes_4_12)

async def push_int_to_server_iid(random_int):
    if(websocket_linked is not None and is_connected_to_server):
        useUTF8= False
        ulong_milliseconds = 15000000000000000000
        ulong_milliseconds+=int(get_current_time_with_offset() * 1000)

        # Send the current time in milliseconds with the integer value
        #ulong_milliseconds = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)          
        data = bytearray(12)
        
        random_bytes = random_int.to_bytes(4, byteorder='little')
        milliseconds_bytes = ulong_milliseconds.to_bytes(8, byteorder='little')
        data = random_bytes + milliseconds_bytes

        if(use_print_debug): 
            print_debug_params("Debug: ", data)
            print_debug_params("Size: ", len(data))
            print_debug_params("B64: ", datab64)
        try:
            print_debug(f"Random Push: {random_int} Milliseconds: {ulong_milliseconds}")
            if(useUTF8):
                datab64 =f"b|{base64.b64encode(data).decode('utf-8')}" 
                await websocket_linked.send(datab64)
                if(use_print_debug): 
                    print_debug_params("Data sent:", datab64)
            else :
                await websocket_linked.send(data)
        except:
            print_debug("Error sending data")






## ## ## ## ## ## ## ## ## ## ## ## ## 
## SETUP RANDOM PUSH THREAD FOR DEBUG
## ## ## ## ## ## ## ## ## ## ## ## ## 


async def push_random_int_to_server_iid():
    if(is_connected_to_server):
        if websocket_linked is not None:
            random_int = random.randint(random_range_min, random_range_max)
            await push_int_to_server_iid(random_int)





def loop_thread_perform_action_random_int_push_server():
    while True:
        asyncio.run(push_random_int_to_server_iid())
        time.sleep(time_between_random_push)


if(use_random_push):
    udp_thread = threading.Thread(target=loop_thread_perform_action_random_int_push_server)
    udp_thread.start()



## ## ## ## ## ## ## ## ## ## ## ## ## 
## LISTEN TO UDP PORT AS RELAY
## ## ## ## ## ## ## ## ## ## ## ## ## 



def loop_thread_listen_udp():
    global udp_port_to_listen
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('0.0.0.0', udp_port_to_listen))
    while True:
        # Receive data from the socket
        data, address = udp_socket.recvfrom(64)

        # Process the received data
        if(websocket_linked is not None and  is_connected_to_server):
            try:
                if data.startswith(b'i:'):
                    rest_of_byte = data[2:]
                    try:
                        parsed_int = int(rest_of_byte)
                        asyncio.run(push_int_to_server_iid(parsed_int))
                    except ValueError:
                        print("")
                elif len(data) ==4:
                    int_to_push = struct.unpack('<i', data[0:4])[0]
                    print_debug(f"UDP Int message from {address}: {int_to_push}")
                    asyncio.run(push_int_to_server_iid(int_to_push))
                elif len(data) ==12:                    
                    asyncio.run(push_byte_as_raw_to_server_iid(data))
                                    
            except Exception as e:
                print_debug_params("Error sending data:", str(e))

if use_local_udp_port_listener:
    udp_thread = threading.Thread(target=loop_thread_listen_udp)
    udp_thread.start()



## ## ## ## ## ## ## ## ## ## ## ## ## 
## FUNCTIONS TO HANDLE WEBSOCKET
## ## ## ## ## ## ## ## ## ## ## ## ## 

async def on_byte_received_as_int_to_be_broadcast(ws, byte_received):

    if byte_received is not None:
        if len(byte_received) == 16:
            index = struct.unpack('<i', byte_received[0:4])[0]
            value = struct.unpack('<i', byte_received[4:8])[0]
            ulong_milliseconds = struct.unpack('<q', byte_received[8:16])[0]
            await broadcast_iid_on_udp_port(byte_received)
            if use_print_on_int_change:
                print(f"R: {index} | {value} | { ulong_milliseconds}")






async def on_message_from_iid_server(ws, message):
    global is_connected_to_server , given_index_lock_is_set , given_index_lock
    print_debug(f"Received message: {message}")



    if message.startswith("IndexLock:"):
        given_index_lock_is_set=True
        given_index_lock=int(message[10:].strip())
        print("Given Index Lock on server IID: ", given_index_lock)
    if message.startswith("SIGNIN:"):
        # Extract the signed message from the response
        signed_message = message[7:].strip()
        signature_b64s = sign_message(signed_message.encode('utf-8'))
        print_debug(f"SIGNED:{signature_b64s}")
        to_send = f"SIGNED:{signature_b64s}"
        # Send the signature
        await ws.send(to_send)
    
    if message.startswith("RSA:Verified"):
        print_debug(f"RSA Verified :) ")
        is_connected_to_server = True
 
async def on_error_from_iid_server(ws, error):
    print_debug(f"Error: {error}")
    global is_connected_to_server
    is_connected_to_server = False

async def on_close_from_iid_server(ws):
    global websocket_linked
    print_debug("WebSocket connection closed")
    websocket_linked=None

async def on_open_from_iid_server(ws):
    global websocket_linked
    print_debug("WebSocket connection opened")
    websocket_linked=ws
    
    message = "Hello "+public_pem.decode('utf-8')
    await ws.send(message)


async def websocket_listener_to_iid_server(uri):
    
    while True:
        async with websockets.connect(uri) as websocket:

            await on_open_from_iid_server(websocket)
            while websocket.open:
                try:
                    async for message in websocket:
                        if isinstance(message, bytes):
                            #print_debug_params("Received binary message:", message)
                            await on_byte_received_as_int_to_be_broadcast(websocket, message)
                        elif isinstance(message, str):
                            #print_debug_params("Received text message:", message)
                            await on_message_from_iid_server(websocket, message)
                        
                            
                except Exception as e:
                    print_debug_params("Error receiving data:", str(e))
                    await on_error_from_iid_server(websocket, str(e))
                    
            await on_close_from_iid_server(websocket)
        await asyncio.sleep(5)
        print_debug("Reconnecting to server...")
        
            
async def handler_local_websocket_server(websocket, path):
    while True:
        global target_port
        try:
            data = await websocket.recv()
        except Exception as e:
                print_debug_params("Client to server error:", str(e))
        if data is not None and len(data) > 0:
            if len(data) == 4 or len(data) == 12 :
                await push_byte_as_raw_to_server_iid(data)
            else:
                print_debug(f"Key Value| {data}")
                date_parts = data.split(":")
                if(len(date_parts) == 2):
                    key = date_parts[0]
                    value = date_parts[1]
                    print_debug(f"Key {key}  |  Value {value}")
                    try:
                        intvalue = int(value)
                        await push_int_to_server_iid(intvalue)
                    except ValueError:
                        pass


async def side_thread_function_websocket_server():
    global local_websocket_server_port
    print_debug(f"Start Local Websocket Server on port {local_websocket_server_port}")
    await websockets.serve(handler_local_websocket_server, "localhost", local_websocket_server_port)
    #asyncio.get_event_loop().run_until_complete(start_server_local)

def get_public_ip():
        response = requests.get('https://api.ipify.org')
        if response.status_code == 200:
            return response.text
        else:
            return None
    
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
        

async def main():
    
    # Create tasks
    if use_local_websocket_listener:
        task_1 = asyncio.create_task(side_thread_function_websocket_server())
        await task_1
    
    task_2 = asyncio.create_task(websocket_listener_to_iid_server(websocket_server_iid_url))
    await task_2


if __name__ == "__main__":
    print(f"Connecting to IID Server: {websocket_server_iid_url}")
    if use_local_websocket_listener:
        print(f"Using local websocket listener on port:{local_websocket_server_port}")
    if use_local_udp_port_listener:
        print(f"Using local UDP listener on port:{udp_port_to_listen}")
    print(f"Broadcasting server int change to local app ports: {local_port_list}")
    print(f"Broadcasting server int changeto local device ports: {ipv4_port_list}") 
    print(f"Network Time Protocol (NTP) used: {NTP_SERVERS}") 

   

    public_ip = get_public_ip()
    if public_ip:
        print(f"Public IP: {public_ip}")
 
    
    print(f"Current IPV4 address: {get_ip()}")


    asyncio.run(main())
    print(f"Exiting... ") 
    
  

    