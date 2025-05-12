from pathlib import Path
import shlex
import sys
import threading

from fileshare_client import FileShareClient
from fileshare_peer   import FileSharePeer

def main():
    cli = FileShareClient()
    while True:
        try:
            parts = shlex.split(input("p2p> "), posix=False)
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not parts:
            continue

        cmd, *a = parts
        try:
            match cmd:
                case "connect":   cli.connect(a[0], int(a[1]))
                case "register":  cli.register()
                case "login":     cli.login()
                case "list":      cli.list()
                case "upload":    cli.upload(Path(a[0]))
                case "download":  cli.download(a[0])
                case "request":   cli.request(a[0], a[1], int(a[2]), a[3])
                case "grant":     cli.grant(a[0], a[1])
                case "peerlist":  cli.peerlist()
                case "quit":      break
                case _:           print(FileShareClient.HELP)
        except Exception as e:
            print("[CLIENT ERROR]", e)
            print(FileShareClient.HELP)

def start_peer(port_no: int):
    peer = FileSharePeer(port=port_no)
    peer.start_peer()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python index.py <port>")
        sys.exit(1)

    port_no = int(sys.argv[1])

    # Start peer server in its own thread
    threading.Thread(target=start_peer, args=(port_no,), daemon=False).start()

    # Then run the client REPL
    main()
