# client.py
import socket, sys, hashlib, sqlparse
from fe_scheme import decrypt

def load_public_key():
    try:
        with open("public_key.txt", "r") as f:
            lines = f.read().splitlines()
            n = int(lines[0].strip())
            g = int(lines[1].strip())
            return (n, g)
    except Exception as e:
        print(f"[Client] Error loading public key: {e}")
        sys.exit(1)

def load_ta_rsa_pub():
    try:
        with open("ta_rsa_pub.txt", "r") as f:
            lines = f.read().splitlines()
            N = int(lines[0].strip())
            e = int(lines[1].strip())
            return (N, e)
    except Exception as e:
        print(f"[Client] Error loading TA RSA public key: {e}")
        sys.exit(1)

def get_fkey():
    host = "localhost"
    port = 8000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        command = "GET_FKEY AGG"
        print(f"[Client] Requesting functional key with command: {command}")
        s.sendall(command.encode())
        data = s.recv(4096)
        fkey = data.decode().strip()
        print(f"[Client] Received functional key: {fkey}")
        return fkey

def validate_and_parse_query(query):
    parsed = sqlparse.parse(query)
    if not parsed:
        raise ValueError("Invalid SQL query.")
    statement = parsed[0]
    if statement.get_type() != "SELECT":
        raise ValueError("Only SELECT queries are allowed.")
    return True

def send_query_to_server(fkey, query):
    host = "localhost"
    port = 9000
    message = f"QUERY\n{fkey}\n{query}"
    print(f"[Client] Sending query message to server:\n{message}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(message.encode())
        data = s.recv(4096)
        response = data.decode().strip()
        print(f"[Client] Received response from server: {response}")
        return response

def verify_fkey(fkey_full, rsa_pub):
    if "|" not in fkey_full:
        return None
    fkey_data, sig_str = fkey_full.split("|", 1)
    try:
        signature = int(sig_str)
    except ValueError:
        return None
    import hashlib
    N, e = rsa_pub
    h = int(hashlib.sha256(fkey_data.encode()).hexdigest(), 16) % N
    h_from_sig = pow(signature, e, N)
    if h == h_from_sig and "FKEY:AGG" in fkey_data:
        try:
            parts = fkey_data.split(";")
            lam_part = [p for p in parts if p.startswith("lam:")][0]
            mu_part = [p for p in parts if p.startswith("mu:")][0]
            lam = int(lam_part.split(":")[1])
            mu = int(mu_part.split(":")[1])
            return (lam, mu)
        except Exception as e:
            print(f"[Client] Error parsing functional key: {e}")
            return None
    else:
        return None

def main():
    print("[Client] Functional Encryption Client started.")
    public_key = load_public_key()
    rsa_pub = load_ta_rsa_pub()
    fkey_full = get_fkey()
    fkey = verify_fkey(fkey_full, rsa_pub)
    if fkey is None:
        print("[Client] Functional key verification failed. Exiting.")
        sys.exit(1)
    else:
        print(f"[Client] Functional key verified: {fkey}")
    while True:
        try:
            query = input("[Client] Enter SQL aggregation query: ")
            if not query:
                continue
            print(f"[Client] You entered: {query}")
            query_hash = hashlib.sha256(query.encode()).hexdigest()
            print(f"[Client] Query hash (SHA256): {query_hash}")
            try:
                validate_and_parse_query(query)
            except Exception as e:
                print(f"[Client] Query validation error: {str(e)}\n")
                continue
            response = send_query_to_server(fkey_full, query)
            if response.startswith("ERROR"):
                print(f"[Client] Error: {response}\n")
                continue
            # If AVG, response contains two lines: encrypted sum and plaintext count.
            if "\n" in response:
                lines = response.splitlines()
                if len(lines) < 2:
                    print("[Client] Error: Expected two values for AVG.\n")
                    continue
                try:
                    agg_sum = int(lines[0].strip())
                    count_plain = int(lines[1].strip())
                except ValueError:
                    print(f"[Client] Error: Server returned an error: {response}\n")
                    continue
                sum_result = decrypt(agg_sum, fkey, public_key)
                if count_plain == 0:
                    print("[Client] Error: Count is zero; cannot compute AVG.\n")
                    continue
                avg_result = sum_result / count_plain
                print(f"[Client] Final result (AVG) decrypted locally: {avg_result}\n")
            else:
                try:
                    agg_ciphertext = int(response)
                except ValueError:
                    print(f"[Client] Error: Server returned an error: {response}\n")
                    continue
                result = decrypt(agg_ciphertext, fkey, public_key)
                print(f"[Client] Final result of query decrypted locally: {result}\n")
        except KeyboardInterrupt:
            print("\n[Client] Shutting down client.")
            sys.exit(0)
        except Exception as e:
            print(f"[Client] Error: {e}")

if __name__ == "__main__":
    main()
