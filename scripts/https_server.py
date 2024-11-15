import http.server
import ssl

server_address = ('localhost', 4445)

handler = http.server.SimpleHTTPRequestHandler

httpd = http.server.HTTPServer(server_address, handler)

httpd.socket = ssl.wrap_socket(httpd.socket,
                               certfile="server.pem",
                               server_side=True)

print("Running on https://localhost:4445")
httpd.serve_forever()
