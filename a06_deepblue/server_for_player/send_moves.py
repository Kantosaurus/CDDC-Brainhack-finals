import requests
import json
import chess.pgn
import io

def pgn_to_moves(pgn_string):
    # Parse the PGN
    pgn = io.StringIO(pgn_string)
    game = chess.pgn.read_game(pgn)
    
    # Convert moves to the format expected by the server
    moves = []
    board = chess.Board()
    
    for move in game.mainline_moves():
        # Get the source and destination squares
        from_square = chess.square_name(move.from_square)
        to_square = chess.square_name(move.to_square)
        
        # Add the move
        moves.append({
            "from": from_square,
            "to": to_square
        })
        
        # Make the move on the board
        board.push(move)
    
    return moves

def send_moves_to_server(moves):
    # Server endpoint
    url = "http://localhost:4000/api/verify-and-execute"
    
    # Prepare the request
    data = {
        "moves": moves
    }
    
    # Send the request
    try:
        response = requests.post(url, json=data)
        print("Response status:", response.status_code)
        print("Response body:", response.text)
        return response.json()
    except Exception as e:
        print(f"Error sending request: {e}")
        return None

def main():
    # Replace this with your PGN string
    pgn_string = """
    [Your PGN string goes here]
    """
    
    # Convert PGN to moves
    moves = pgn_to_moves(pgn_string)
    
    # Send moves to server
    result = send_moves_to_server(moves)
    
    if result:
        print("\nServer response:", json.dumps(result, indent=2))

if __name__ == "__main__":
    main() 