import time
import socket

# Set up listen socket
addr = ('0.0.0.0', 4245)
s = socket.socket()
s.bind(addr)
s.listen(True)

# Listen for connections
print('listening on', addr)
while True:
    try:
        cl, addr = s.accept()
        print('client connected from', addr)

        while True:
            message = cl.recv(1024)
            if message == b"":
                break # end of file on input from socket cl
            print(message)
            cl.send(message)
        cl.close()
        print("client disconnected")

    except OSError as e:
        cl.close()
        print('error - connection closed', e)
     
