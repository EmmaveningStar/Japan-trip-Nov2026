#!/usr/bin/env python3
"""Private family itinerary server. Standard library only; deploy behind HTTPS."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('TRIP_DATA_DIR', str(Path.home() / '.local/share/japan-trip')))
SESSIONS = {}
ATTEMPTS = {}
MAX_BODY = 200_000

def db():
    conn = sqlite3.connect(DATA / 'trip.sqlite3', timeout=10)
    conn.execute('CREATE TABLE IF NOT EXISTS plan (id INTEGER PRIMARY KEY, revision INTEGER, data TEXT, editor TEXT, updated TEXT)')
    conn.execute('INSERT OR IGNORE INTO plan VALUES (1, 0, ?, ?, ?)', (json.dumps(json.loads((ROOT / 'trip.json').read_text())), '', ''))
    conn.commit()
    return conn

def valid_plan(p):
    if not isinstance(p, dict) or set(p) != {'logistics', 'days'}: return False
    if not isinstance(p['logistics'], dict) or set(p['logistics']) != {'arrival', 'departure', 'hotel', 'rental', 'notes'}: return False
    if any(not isinstance(v, str) or len(v) > 3000 for v in p['logistics'].values()): return False
    if not isinstance(p['days'], list) or len(p['days']) != 4: return False
    for day in p['days']:
        if not isinstance(day, dict) or set(day) != {'date','title','notes','stops','meals'}: return False
        if any(not isinstance(day[k], str) or len(day[k]) > 3000 for k in ('date','title','notes')): return False
        if not isinstance(day['stops'], list) or not 2 <= len(day['stops']) <= 20: return False
        for stop in day['stops']:
            if not isinstance(stop, dict) or set(stop) != {'time','name','query','mode','status','detail'}: return False
            if any(not isinstance(v,str) or len(v)>3000 for v in stop.values()): return False
            if stop['mode'] not in ('driving','transit','walking') or stop['status'] not in ('待確認','已確認','候選'): return False
        if not isinstance(day['meals'], dict) or set(day['meals']) != {'早餐','午餐','晚餐'}: return False
        for choices in day['meals'].values():
            if not isinstance(choices,list) or not 1 <= len(choices) <= 8: return False
            for c in choices:
                if not isinstance(c,dict) or set(c) != {'name','query','note','selected'}: return False
                if any(not isinstance(c[k],str) or len(c[k]) > 3000 for k in ('name','query','note')) or not isinstance(c['selected'],bool): return False
    return True

class Handler(SimpleHTTPRequestHandler):
    def __init__(self,*a,**kw): super().__init__(*a,directory=str(ROOT),**kw)
    def end_headers(self):
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','strict-origin-when-cross-origin')
        self.send_header('Cache-Control','no-store')
        super().end_headers()
    def reply(self,status,obj,cookie=None):
        body=json.dumps(obj,ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        if cookie: self.send_header('Set-Cookie',cookie)
        self.end_headers(); self.wfile.write(body)
    def session(self):
        c=SimpleCookie()
        try: c.load(self.headers.get('Cookie',''))
        except Exception: return None
        token=c.get('trip_session')
        s=SESSIONS.get(token.value) if token else None
        return s if s and s['expires']>time.time() else None
    def do_GET(self):
        path=self.path.split('?')[0]
        if path=='/api/status': return self.reply(200,{'shared':True,'authenticated':bool(self.session())})
        if path=='/api/plan':
            if not self.session(): return self.reply(401,{'error':'請先輸入家庭共用密碼。'})
            with db() as conn: row=conn.execute('SELECT revision,data,editor,updated FROM plan WHERE id=1').fetchone()
            return self.reply(200,{'revision':row[0],'plan':json.loads(row[1]),'editor':row[2],'updated':row[3]})
        if path not in ('/','/index.html','/app.js','/style.css','/trip.json','/favicon.ico','/standalone.html'):
            return self.reply(404,{'error':'Not found'})
        return super().do_GET()
    def do_POST(self):
        # Require JSON + custom header: cross-origin HTML forms cannot mutate data.
        if self.headers.get('X-Trip-Request')!='1' or self.headers.get('Content-Type','').split(';')[0]!='application/json':
            return self.reply(403,{'error':'不允許此請求。'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0 < length <= MAX_BODY: return self.reply(413,{'error':'資料過大。'})
            body=json.loads(self.rfile.read(length))
            if not isinstance(body,dict): raise ValueError()
        except (ValueError, json.JSONDecodeError): return self.reply(400,{'error':'資料格式錯誤。'})
        if self.path=='/api/login':
            ip=self.client_address[0]; now=time.time()
            ATTEMPTS[ip]=[t for t in ATTEMPTS.get(ip,[]) if t>now-300]
            if len(ATTEMPTS[ip])>=10: return self.reply(429,{'error':'嘗試次數過多，請五分鐘後再試。'})
            code=body.get('code','')
            if not isinstance(code,str) or not hmac.compare_digest(hashlib.sha256(code.encode()).digest(), hashlib.sha256(ACCESS_CODE.encode()).digest()):
                ATTEMPTS[ip].append(now); return self.reply(401,{'error':'家庭共用密碼不正確。'})
            ATTEMPTS.pop(ip,None)
            token=secrets.token_urlsafe(32)
            SESSIONS[token]={'expires':now+43200}
            # Bound in-memory session growth and discard expired sessions.
            for old in list(SESSIONS):
                if SESSIONS[old]['expires']<=now: SESSIONS.pop(old,None)
            secure='; Secure' if os.environ.get('TRIP_SECURE_COOKIE')=='1' else ''
            return self.reply(200,{'ok':True},f'trip_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{secure}')
        if not self.session(): return self.reply(401,{'error':'登入已到期，請重新登入。'})
        if self.path=='/api/logout':
            c=SimpleCookie(self.headers.get('Cookie','')); SESSIONS.pop(c['trip_session'].value,None)
            return self.reply(200,{'ok':True},'trip_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
        if self.path!='/api/plan': return self.reply(404,{'error':'Not found'})
        if not valid_plan(body.get('plan')) or body.get('editor') not in ('媽媽','爸爸') or type(body.get('revision')) is not int:
            return self.reply(400,{'error':'行程格式不完整，無法儲存。'})
        updated=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        with db() as conn:
            cur=conn.execute('UPDATE plan SET revision=revision+1,data=?,editor=?,updated=? WHERE id=1 AND revision=?', (json.dumps(body['plan'],ensure_ascii=False),body['editor'],updated,body['revision']))
            if cur.rowcount!=1: return self.reply(409,{'error':'另一人已更新行程。請先下載你的草稿，再載入共用最新版後重新套用修改。'})
        return self.reply(200,{'revision':body['revision']+1,'editor':body['editor'],'updated':updated})

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--host',default='127.0.0.1'); parser.add_argument('--port',type=int,default=8001); args=parser.parse_args()
    DATA.mkdir(parents=True,exist_ok=True,mode=0o700)
    code_file=DATA/'access-code'
    ACCESS_CODE=os.environ.get('TRIP_ACCESS_CODE','')
    if not ACCESS_CODE:
        if not code_file.exists():
            fd=os.open(code_file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f: f.write(secrets.token_urlsafe(24))
        ACCESS_CODE=code_file.read_text().strip()
    if len(ACCESS_CODE)<12: raise SystemExit('TRIP_ACCESS_CODE must contain at least 12 characters')
    with db(): pass
    print(f'Trip server ready on {args.host}:{args.port}. Access code file: {code_file} (unless environment override is set).',flush=True)
    ThreadingHTTPServer((args.host,args.port),Handler).serve_forever()
