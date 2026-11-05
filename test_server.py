"""Integration checks against an isolated temporary data directory."""
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

class SharedPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        with socket.socket() as s:
            s.bind(('127.0.0.1',0)); cls.port=s.getsockname()[1]
        cls.base=f'http://127.0.0.1:{cls.port}'
        cls.env=dict(os.environ,TRIP_DATA_DIR=cls.temp.name,TRIP_ACCESS_CODE='integration-test-only-code')
        cls.start()
    @classmethod
    def start(cls):
        cls.proc=subprocess.Popen([sys.executable,str(Path(__file__).with_name('server.py')),'--port',str(cls.port)],env=cls.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.base+'/api/status',timeout=.3);return
            except OSError: time.sleep(.05)
        raise RuntimeError('server did not start')
    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate();cls.proc.wait(timeout=5);cls.temp.cleanup()
    def client(self): return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def request(self,c,path,body=None,headers=True):
        req=urllib.request.Request(self.base+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','X-Trip-Request':'1'} if headers else {})
        try:
            with c.open(req) as r: return r.status,json.load(r)
        except urllib.error.HTTPError as e: return e.code,json.load(e)
    def test_shared_editing_and_security(self):
        mom,dad=self.client(),self.client()
        self.assertEqual(self.request(mom,'/api/plan')[0],401)
        self.assertEqual(self.request(mom,'/api/login',{'code':'wrong'})[0],401)
        self.assertEqual(self.request(mom,'/api/login',{'code':self.env['TRIP_ACCESS_CODE']},False)[0],403)
        for c in (mom,dad): self.assertEqual(self.request(c,'/api/login',{'code':self.env['TRIP_ACCESS_CODE']})[0],200)
        _,a=self.request(mom,'/api/plan');_,b=self.request(dad,'/api/plan')
        a['plan']['logistics']['hotel']='Family Hotel Test'
        body={'revision':a['revision'],'plan':a['plan'],'editor':'媽媽'}
        self.assertEqual(self.request(mom,'/api/plan',body)[0],200)
        self.assertEqual(self.request(dad,'/api/plan',{'revision':b['revision'],'plan':b['plan'],'editor':'爸爸'})[0],409)
        _,latest=self.request(dad,'/api/plan');self.assertEqual(latest['plan']['logistics']['hotel'],'Family Hotel Test')
        self.assertEqual(latest['editor'],'媽媽')
        bad=dict(body,revision=latest['revision'],plan={})
        self.assertEqual(self.request(dad,'/api/plan',bad)[0],400)
        self.assertEqual(self.request(dad,'/server.py')[0],404)
        self.assertEqual(self.request(dad,'/../trip-runtime/access-code')[0],404)
        self.proc.terminate();self.proc.wait(timeout=5);self.start()
        self.assertEqual(self.request(dad,'/api/plan')[0],401)
        self.request(dad,'/api/login',{'code':self.env['TRIP_ACCESS_CODE']})
        _,restored=self.request(dad,'/api/plan');self.assertEqual(restored['plan']['logistics']['hotel'],'Family Hotel Test')
        self.request(dad,'/api/logout',{})
        self.assertEqual(self.request(dad,'/api/plan')[0],401)

if __name__=='__main__': unittest.main(verbosity=2)
