"""Owned local browser execution fixture; no blind target code."""
import html, json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from harness.testing_fixtures.loopback_port import bind_browser_safe

class App:
    def __init__(self, secure=False, mode=""):
        self.secure, self.requests, self.message = secure, [], ''
        self.mode, self.writes, self.cookies, self.targets = mode, [], [], []
        app = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def send(self, status, body, content_type='text/html'):
                data=body.encode(); self.send_response(status)
                self.send_header('Content-Type',content_type)
                self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
            def do_GET(self):
                app.requests.append(('GET',urlsplit(self.path).path))
                app.cookies.append(self.headers.get('Cookie',''))
                app.targets.append(self.path)
                path=urlsplit(self.path).path
                prefix = ('<script>window.alert=x=>console.log(String(x))</script>' if app.mode=='console' else '<script>alert(123)</script>' if app.mode=='contaminated' else '<script src="http://outside.invalid/blocked.js"></script>' if app.mode=='blocked' else '')
                if app.mode=='crossorigin':prefix += '<img src="'+app.peer_url+'/cookie">'
                if app.mode=='serviceworker':prefix += '<script>navigator.serviceWorker.register("/worker.js").catch(()=>{})</script>'
                if app.mode=='websocket':prefix += '<script>new WebSocket("'+app.base.replace('http:','ws:')+'/socket")</script>'
                if path == '/worker.js':return self.send(200, 'self.addEventListener("fetch",()=>{})', 'application/javascript')
                if path == '/dom':
                    sink='textContent' if app.secure else 'innerHTML'
                    return self.send(200, prefix + "<div id='sink'></div><script>const h=location.hash; "
                        "if(h.startsWith('#/search?')) {const q=new URLSearchParams(h.split('?')[1]).get('q')||'';"
                        f"document.getElementById('sink').{sink}=q;"+"}</script>")
                if path == '/messages/board' and app.mode == 'redirect':
                    self.send_response(302);self.send_header('Location','/other');self.end_headers();return
                if path in ('/messages/board','/other'):
                    value='' if app.mode == 'wrongconsumer' else html.escape(app.message) if app.secure else app.message
                    return self.send(200, prefix+'<html><main>'+value+'</main></html>')
                if path == '/api/messages':
                    return self.send(200, json.dumps({'text':app.message}), 'application/json')
                return self.send(404,'missing')
            def do_POST(self):
                app.requests.append(('POST',urlsplit(self.path).path))
                data=self.rfile.read(int(self.headers.get('Content-Length','0'))).decode()
                app.targets.append(self.path)
                if urlsplit(self.path).path == '/register':
                    return self.send(422 if app.secure else 201,
                                     'weak password rejected' if app.secure else 'created', 'text/plain')
                if urlsplit(self.path).path == '/api/messages':
                    app.writes.append(json.loads(data))
                    if app.mode in ('write404','write500','write302'):
                        return self.send(int(app.mode[5:]),'write failed','text/plain')
                    value=json.loads(data).get('text','')
                    swallowed = app.mode == 'swallowed' or (app.mode == 'stale_baseline' and (':attack:' in value or ':control:' in value)) or (app.mode == 'swallow_attack' and ':attack:' in value) or (app.mode == 'swallow_control' and ':control:' in value)
                    if not swallowed:app.message=value
                    return self.send(201,json.dumps({'id':1}), 'application/json')
                return self.send(404,'missing')
        self.server=bind_browser_safe(lambda: ThreadingHTTPServer(('127.0.0.1',0),Handler))
        self.base=f'http://127.0.0.1:{self.server.server_port}'
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

