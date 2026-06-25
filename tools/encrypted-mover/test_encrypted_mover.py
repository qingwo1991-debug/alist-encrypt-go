import datetime as dt
import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
import http.server
import subprocess
import sys
import threading
import logging
import urllib.parse
from pathlib import Path

MODULE = Path(__file__).with_name("encrypted_mover.py")
spec = importlib.util.spec_from_file_location("encrypted_mover", MODULE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class MoverTests(unittest.TestCase):
    def test_infohash_and_parity_import(self):
        with tempfile.TemporaryDirectory() as d:
            db = m.Database(str(Path(d)/"m.db"))
            db.add_source("x","https://example.invalid")
            sid = db.source_rows()[0]["id"]
            lines = [f"magnet:?xt=urn:btih:{i:040x}" for i in range(1,7)]
            self.assertEqual(db.import_lines(sid, lines, "odd"), 3)
            rows = list(db.db.execute("select line_no from tasks order by line_no"))
            self.assertEqual([r[0] for r in rows],[1,3,5])
            # Reordering a hash onto the other parity disables its queued copy here.
            moved = [lines[1], lines[0], *lines[2:]]
            db.import_lines(sid, moved, "odd")
            enabled = {r["infohash"]:r["enabled"] for r in db.db.execute("select infohash,enabled from tasks")}
            self.assertEqual(enabled[m.infohash(lines[0])], 0)
            db.db.close()

    def test_signature_ad_rule(self):
        with tempfile.TemporaryDirectory() as d:
            db = m.Database(str(Path(d)/"m.db"))
            f={"path":"promo.ass","length":12345}
            db.record_signatures([f]); db.record_signatures([f]); db.record_signatures([f])
            self.assertEqual(db.signature_count(f["path"],f["length"]),3)
            db.db.close()

    def test_default_source_does_not_overwrite_cli_change(self):
        with tempfile.TemporaryDirectory() as d:
            db=m.Database(str(Path(d)/"m.db"))
            db.ensure_source("x","https://old")
            db.add_source("x","https://new",120)
            db.ensure_source("x","https://default")
            row=db.source_rows()[0]
            self.assertEqual(row["url"],"https://new")
            self.assertEqual(row["refresh_seconds"],120)
            db.db.close()

    def test_manual_add_deduplicates_infohash(self):
        with tempfile.TemporaryDirectory() as d:
            db=m.Database(str(Path(d)/"m.db"))
            uri="magnet:?xt=urn:btih:"+"A"*40
            first=db.add_manual(uri); second=db.add_manual(uri+"&dn=renamed")
            self.assertEqual(first,second)
            self.assertEqual(db.db.execute("select count(*) from tasks").fetchone()[0],1)
            db.db.close()

    def test_file_filter(self):
        self.assertTrue(m.is_selected_file("movie.mkv", 200*m.MIB, 200*m.MIB))
        self.assertFalse(m.is_selected_file("sample.mp4", 199*m.MIB, 200*m.MIB))
        self.assertTrue(m.is_selected_file("movie.zh.ass", 1000, 200*m.MIB))
        self.assertFalse(m.is_selected_file("readme.txt", 500*m.MIB, 200*m.MIB))

    def test_encrypted_size(self):
        self.assertEqual(m.encrypted_size(123),155)

    def test_window(self):
        cfg={"schedule":{"timezone":"Asia/Shanghai","start":"01:00","end":"07:00"}}
        from zoneinfo import ZoneInfo
        z=ZoneInfo("Asia/Shanghai")
        self.assertTrue(m.in_start_window(cfg,dt.datetime(2026,6,25,2,0,tzinfo=z)))
        self.assertFalse(m.in_start_window(cfg,dt.datetime(2026,6,25,8,0,tzinfo=z)))

    def test_openlist_stream_has_exact_length_and_path(self):
        received={}
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_PUT(self):
                length=int(self.headers["Content-Length"])
                received["length"]=length
                received["path"]=urllib.parse.unquote(self.headers["File-Path"])
                received["body"]=self.rfile.read(length)
                body=json.dumps({"code":200,"message":"ok"}).encode()
                self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
        server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                key=Path(d)/"pw"; key.write_text("x")
                ol=m.OpenList({"base_url":f"http://127.0.0.1:{server.server_port}","username":"admin","password_file":str(key)},logging.getLogger("test"))
                ol.token="token"
                proc=subprocess.Popen([sys.executable,"-c","import sys;sys.stdout.buffer.write(b'x'*35)"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                ol.upload_stream("/156联通云盘/encrypt/a.bin",proc,35,10)
                self.assertEqual(received["length"],35)
                self.assertEqual(len(received["body"]),35)
                self.assertEqual(received["path"],"/156联通云盘/encrypt/a.bin")
        finally:
            server.shutdown(); server.server_close()

    def test_v2_remote_header_validation(self):
        cfg={"base_url":"http://127.0.0.1:1","username":"a","password_file":"x"}
        ol=m.OpenList(cfg,logging.getLogger("test"))
        plain=1234
        header=b"AECTR2"+bytes([2,0])+b"n"*16+plain.to_bytes(8,"big")
        ol.range_header=lambda item: header
        dummy=object.__new__(m.Mover); dummy.openlist=ol
        self.assertTrue(m.Mover.valid_remote(dummy,{"size":plain+32,"raw_url":"x"},plain))
        self.assertFalse(m.Mover.valid_remote(dummy,{"size":plain+31,"raw_url":"x"},plain))

    def test_real_encrypted_upload_tracks_done_and_deletes_plaintext(self):
        exe=Path(__file__).parents[2]/".tmp-encrypt-tool.exe"
        if not exe.exists(): self.skipTest("build .tmp-encrypt-tool.exe first")
        state={"body":b"","path":"","done":False}
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def reply(self,obj,status=200,ctype="application/json"):
                body=obj if isinstance(obj,bytes) else json.dumps(obj).encode()
                self.send_response(status); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
            def do_GET(self):
                if self.path=="/api/task/upload/undone": return self.reply({"code":200,"data":[]})
                if self.path=="/api/task/upload/done":
                    data=[{"id":"u1","state":2,"name":"upload "+Path(state["path"]).name+" to [mock]"}] if state["done"] else []
                    return self.reply({"code":200,"data":data})
                if self.path=="/raw": return self.reply(state["body"][:32],ctype="application/octet-stream")
                return self.reply({},404)
            def do_POST(self):
                length=int(self.headers.get("Content-Length","0")); raw=self.rfile.read(length); payload=json.loads(raw or b"{}")
                if self.path=="/api/auth/login": return self.reply({"code":200,"data":{"token":"tok"}})
                if self.path=="/api/fs/mkdir": return self.reply({"code":200})
                if self.path=="/api/fs/get":
                    if state["done"] and payload.get("path")==state["path"]:
                        return self.reply({"code":200,"data":{"name":Path(state["path"]).name,"size":len(state["body"]),"raw_url":f"http://127.0.0.1:{self.server.server_port}/raw"}})
                    return self.reply({"code":500,"message":"not found"})
                if self.path=="/api/fs/list":
                    content=[]
                    if state["done"]: content=[{"name":Path(state["path"]).name,"size":len(state["body"]),"raw_url":f"http://127.0.0.1:{self.server.server_port}/raw"}]
                    return self.reply({"code":200,"data":{"content":content}})
                return self.reply({},404)
            def do_PUT(self):
                length=int(self.headers["Content-Length"]); state["path"]=urllib.parse.unquote(self.headers["File-Path"]); state["body"]=self.rfile.read(length); state["done"]=True
                return self.reply({"code":200,"message":"ok"})
        server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler); threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as d:
                root=Path(d); plain=root/"movie.mkv"; plain.write_bytes(os.urandom(128*1024+17)); key=root/"key"; key.write_text("unit-test-password")
                admin=root/"admin"; admin.write_text("admin-password")
                cfg={
                  "node":{"id":"t","parity":"odd"},"sources":[],"schedule":{"timezone":"Asia/Shanghai","start":"00:00","end":"23:59"},
                  "paths":{"database":str(root/"m.db"),"work_dir":str(root/"work"),"log":str(root/"m.log")},
                  "limits":{"max_task_bytes":12*m.GIB,"reserve_bytes":0,"metadata_timeout_seconds":10,"no_progress_seconds":10,"low_speed_window_seconds":10,"min_average_bytes_per_second":1,"max_runtime_seconds":60,"retry_cooldown_seconds":1,"max_attempts":1,"poll_seconds":1},
                  "filters":{"min_video_bytes":1},"aria2":{"rpc_url":"http://127.0.0.1:1/jsonrpc","secret":""},
                  "openlist":{"base_url":f"http://127.0.0.1:{server.server_port}","username":"admin","password_file":str(admin),"target_dir":"/156联通云盘/encrypt"},
                  "encryption":{"tool":str(exe),"password_file":str(key),"type":"aesctr","suffix":".bin"},
                  "upload":{"task_appear_timeout_seconds":2,"task_timeout_seconds":10,"stream_timeout_seconds":10,"poll_seconds":1}
                }
                mover=m.Mover(cfg); mover.openlist.login()
                n=m.now_ts(); mover.db.db.execute("insert into tasks(uri,infohash,state,created_at,updated_at) values(?,?,?,?,?)",("magnet:?x","h","uploading",n,n)); task=mover.db.db.execute("select * from tasks").fetchone()
                mover.upload_file(task,plain)
                self.assertFalse(plain.exists())
                self.assertEqual(len(state["body"]),128*1024+17+32)
                self.assertEqual(state["body"][:6],b"AECTR2")
                self.assertNotEqual(Path(state["path"]).name,"movie.mkv")
                mover.close()
        finally:
            server.shutdown(); server.server_close()

if __name__ == "__main__": unittest.main()
