# -*- coding: utf-8 -*-

from http.server import SimpleHTTPRequestHandler
import socketserver

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

PORT = 8000

Handler = CORSRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("文件服务器正在运行，访问地址:http://localhost:{}".format(PORT))
    httpd.serve_forever()
