
import ctypes, hashlib, re, shutil, socket, textwrap, time, os, subprocess, json, calendar, sys
from datetime import datetime

import struct
import bcrypt
from ecdsa import NIST256p, SigningKey, VerifyingKey, BadSignatureError

access_user = None
list_msgs = [
    {'From': 'Dr.Brown@btf.net', 'To': 'all@btf.net', 'when': '', 'msg': '[NOTIFY] Travel Info : From (1980) To (2017.04.02 12:17:34).', 'next_time': '2017.04.02 12:17:34', 'sign': '858bb2748370e0fab1b4c3363577b5787cd4239767fd96d77e97e7e5232439aa2849d9727e47fe17837729ddcb440da06841995505041502c4343ac9fba247e3'}
]

server_private_key = None
server_public_key = None
system_time = None

def display_banner():
    banner = r"""
 _____  _                   _                 
|_   _|(_)                 | |                
  | |   _  _ __ ___    ___ | |  ___  ___  ___ 
  | |  | || '_ ` _ \  / _ \| | / _ \/ __|/ __|
  | |  | || | | | | ||  __/| ||  __/\__ \\__ \
  \_/  |_||_| |_| |_| \___||_| \___||___/|___/
                                              
___  _________  _____ 
|  \/  ||  _  \/  ___|
| .  . || | | |\ `--. 
| |\/| || | | | `--. \
| |  | || |/ / /\__/ /
\_|  |_/|___/  \____/ 
"""
    line_width = 50
    print("*" * line_width)
    for line in banner.splitlines():
        print("*" + line.center(line_width - 2) + "*")
    print("*" * line_width)

def display_section_banner():
    print('\n')
    print("="*50)
    print("[Timeless MDS]")
    print("="*50)

def display_menu():

    print(f"(Welcome, {access_user})\n")
    print("1. Send message")
    print("2. View received messages")
    print("3. Notify")
    print("4. Shutdown")

def handle_login():
    global access_user

    print("\n< login >")
    username = input("username > ")
    password = input("password > ")
    
    if username == "Marty" and password == "L0veIsNot4Science":
        print("[V] Login successful")
        access_user = username
        
        return True
    else:
        print("[!] Login Failed")
        return False

def handle_send_message():
    global access_user

    From = f"{access_user}@btf.net"
    To, when, msg, sign = prompt_user_message_inputs()

    if not is_valid_email_receiver(To):
        print("[!] Failed to send - Invalid receiver")
        return

    if not is_valid_time_format(when):
        print("[!] Failed to send - Invalid when")
        return

    message = {
        "From": From,
        "To": To,
        "when": when,
        "msg": msg,
        "sign": sign
    }

    if is_valid_signature(server_public_key, msg, sign):
        
        if not has_invalid_command_chars(msg):
            if run_timepostman_command(message):
                list_msgs.append(message)
        else:
            print("[!] Failed to send - Message contains invalid characters.")
        


def handle_view_messages():
    global access_user
    global list_msgs

    print("<2 - Received message>\n")
    
    print(f"[*] The total number of received messages is {len(list_msgs)}.\n")
    
    if not list_msgs:
        print("No messages found.")
        return
    
    for idx, entry in enumerate(list_msgs):
        print(f"{'='*10} Entry #{idx+1} {'='*10}")
        print(f"{'From':6}: {entry['From']}\n")
        print(f"{'To':6}: {entry['To']}\n")
        
        msg = entry['msg']
        wrapped_msg = textwrap.fill(
            msg,
            width=60,
            initial_indent=f"{'Msg':6}: ",
            subsequent_indent=' ' * 8
        )
        print(wrapped_msg + "\n")
        
        sign = entry['sign']
        wrapped_sign = textwrap.fill(
            sign,
            width=60,
            initial_indent=f"{'Sign':6}: ",
            subsequent_indent=' ' * 8
        )
        print(wrapped_sign + "\n")


def send_notify(username):
    global server_private_key, list_msgs, system_time

    if username != "Dr.Brown":
        print("[!] This feature is only available to Dr.Brown.")
        return

    when = system_time
    when_year = when.split('.')[0]

    k, next_time = get_next_time_and_k(when)  
    
    msg = f"[NOTIFY] Travel Info : From ({when_year}) To ({next_time})."

    message = {
        "From": f"Dr.Brown@btf.net",
        "To": "all@btf.net",
        "when": "",
        "msg": msg,
        "next_time": next_time,
        "sign": server_private_key.sign(msg.encode(), hashfunc=hashlib.sha256, k=k).hex(),
    }


    if run_timepostman_command(message):
        list_msgs.append(message)

def run_timepostman_command(message):
    To = message['To']
    when = message['when'].replace(" ", "_")
    msg = message['msg']
    
    command = f"timepostman -t {To} -w {when} -c '{msg}'"
    ret_code = os.system(command)

    if ret_code != 0:
       print("[!] timepostman command execution failed (code:", ret_code, ")")
       return False # 
    return True # 
    

def get_next_time_and_k(when: str):
    libc = ctypes.CDLL("libc.so.6")
    seed = get_timestamp_seed(when)

    libc.srand(seed)
    k1 = libc.rand()
    k2 = libc.rand()
    k3 = libc.rand()

    k = (k1<<64)+(k2<<32)+k3
    
    
    next_time = datetime.fromtimestamp(k3).strftime("%Y.%m.%d %H:%M:%S")
    return k, next_time

def prompt_user_message_inputs():
    print("<1 - send message>")
    To = input("To: ")
    print()
    when = input("When: ")
    print()
    msg = read_msg()
    print()
    print("(Sign)\nex) 12345678abcdef")
    sign = input("> ")
    print()
    return To, when, msg, sign

def read_msg():
    print("(Content)\n> ")
    data = sys.stdin.read(0x40)
    eof_index = data.find("<EOF>")
    if eof_index != -1:
        return data[:eof_index]
    return data


def generate_key_pair():
    private_key = SigningKey.generate(curve=NIST256p)
    public_key = private_key.get_verifying_key()
    print(f"Generated public_key: {public_key.to_string().hex()}")
    print(f"Generated private_key: {private_key.to_string().hex()}")

def load_server_keys():
    global server_private_key, server_public_key, system_time
    with open("key.json") as f:
        key = json.load(f)
    server_private_key = SigningKey.from_string(bytes.fromhex(key['private_key']), curve=NIST256p)
    server_public_key = VerifyingKey.from_string(bytes.fromhex(key['public_key']), curve=NIST256p)
    system_time = key['current_time']

def sign_message_with_key(private_key, msg, k):
    return private_key.sign(msg.encode(), hashfunc=hashlib.sha256, k=k)

def is_hex_string(s):
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False

def is_valid_signature(public_key, msg, signature):
    print(signature)
    if not is_hex_string(signature):
        print("[!] Signature is not a valid hex string.")
        return False
    try:
        public_key.verify(bytes.fromhex(signature), msg.encode(), hashfunc=hashlib.sha256)
        print("[*] Signature verification successed.")
        return True
    except BadSignatureError:
        print("[!] Signature verification failed.")
        return False

def is_valid_email_format(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

def is_valid_email_receiver(receiver):
    return is_valid_email_format(receiver)

def has_invalid_command_chars(command):
    blocked_special_chars = set(r'''~!@#$%^&*()_-+={}[]<>:;",.?/`|''')

    invalid_chars = set()
    for c in command:
        if c in blocked_special_chars:
            invalid_chars.add(c)

    if invalid_chars:
        print(f"[!] Invalid characters found: {''.join(sorted(invalid_chars))}")
        return True
    return False

def is_valid_time_format(when: str) -> time.struct_time:
    pattern = r"^\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}$"
    if not re.match(pattern, when):
        return False
    try:
        return time.strptime(when, "%Y.%m.%d %H:%M:%S")
    except ValueError:
        return False

def get_timestamp_seed(when):
    try:
        full_time = time.strptime(when, "%Y.%m.%d %H:%M:%S")
    except ValueError:
        raise ValueError("[!] Invalid time format. Use 'YYYY.MM.DD HH:MM:SS'")
    return int(calendar.timegm(full_time))
# main

def main_loop():
    global access_user

    while True:
        display_section_banner()
        display_menu()
        print()
        try:
            choice = input("Select> ")
            print()
        except ValueError:
            continue

        if choice == "1":
            handle_send_message()
        elif choice == "2":
            handle_view_messages()
        elif choice == "3":
            send_notify(access_user)
        elif choice == "4":
            print("<4 - Shutdown>")
            print("\nBye~")
            break
        else:
            print("[!] Invalid option")

if __name__ == "__main__":
    load_server_keys()
    
    display_banner()
    while True:
        if handle_login():
            main_loop()

