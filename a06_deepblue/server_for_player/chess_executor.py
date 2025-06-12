import chess
import json
import subprocess
from base64 import b64encode, b64decode
from pwn import *
import sys

BASE64_MAP = [
    ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'],
    ['I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X'],
    ['Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f'],
    ['g', 'h', 'i', 'j', 'k', 'l', 'm', 'n'],
    ['o', 'p', 'q', 'r', 's', 't', 'u', 'v'],
    ['w', 'x', 'y', 'z', '0', '1', '2', '3'],
    ['4', '5', '6', '7', '8', '9', '+', '/']
]

def to_base64(square):
    column = chess.square_file(square)
    row = 7 - chess.square_rank(square)
    return BASE64_MAP[row][column]

def from_base64(b64_char):
    for row, line in enumerate(BASE64_MAP):
        if b64_char in line:
            col = line.index(b64_char)
            square = chess.square(col, 7 - row)
            return chess.square_name(square)
    return None

def add_padding(b64_string):
    return b64_string + '=' * (-len(b64_string) % 4)

def execute_shellcode(shellcode):
    EXE_FILE = "./elf" 
    with open(EXE_FILE, "wb") as f:
        f.write(make_elf(shellcode, arch='amd64', extract=True))
        os.chmod(EXE_FILE, 0o755)

    try:
        result = subprocess.run(EXE_FILE, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout_output = result.stdout
        stderr_output = result.stderr

        print("[+] STDOUT Raw:", stdout_output)
        print("[+] STDERR Raw:", stderr_output)
        os.remove(EXE_FILE) 
    except Exception as e:
        print(f"[-] Error executing shellcode: {e}")
    

def process_moves(moves):
    game = chess.Board()
    all_positions = []

    for move in moves:
        try:
            uci_move = f"{move['from']}{move['to']}"

            if (move['to'].endswith('1') or move['to'].endswith('8')) and game.piece_at(chess.parse_square(move['from'])).symbol().lower() == 'p':
                uci_move += 'q'

            if game.is_legal(chess.Move.from_uci(uci_move)):
                game.push(chess.Move.from_uci(uci_move))
                all_positions.append(chess.parse_square(move['to']))
            else:
                raise ValueError(f"[-] Illegal move detected: {uci_move}")
        except Exception as e:
            print(f"[-] Error: {e}")
            return json.dumps({"status": "error", "message": str(e)})

    if game.is_checkmate():
        shellcode_base64 = ''.join([to_base64(pos) for pos in all_positions])
        shellcode_base64 = add_padding(shellcode_base64)

        try:
            shellcode_bytes = b64decode(shellcode_base64)
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})

        execute_shellcode(shellcode_bytes)
        return json.dumps({"status": "success", "output": shellcode_base64})
    else:
        print("[-] Not a valid checkmate")
        return json.dumps({"status": "error", "message": "Not a valid checkmate"})

if __name__ == "__main__":
    try:
        moves = json.loads(sys.argv[1])
        result = process_moves(moves)
    except Exception as e:
        print(f"[-] Execution failed: {e}")

