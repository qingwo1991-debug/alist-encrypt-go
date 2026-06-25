#!/usr/bin/env python3
"""Encrypted mover: magnet queue -> aria2 -> V2 stream encryption -> local OpenList."""
from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import http.client
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any, Iterable

GIB = 1024 ** 3
MIB = 1024 ** 2
MAGNET_RE = re.compile(r"^magnet:\?", re.I)
BTIH_RE = re.compile(r"(?:^|[?&])xt=urn:btih:([^&]+)", re.I)
VIDEO_EXTS = {".mkv", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".ts", ".m2ts"}
SUB_EXTS = {".srt", ".ass", ".ssa", ".vtt", ".sub", ".idx"}
TERMINAL = {"completed", "skipped_existing", "rejected", "dead", "canceled"}


def now_ts() -> int:
    return int(time.time())


def infohash(uri: str) -> str:
    m = BTIH_RE.search(uri)
    if not m:
        return hashlib.sha256(uri.encode()).hexdigest()
    value = urllib.parse.unquote(m.group(1)).upper()
    if len(value) == 32:
        try:
            value = base64.b32decode(value).hex().upper()
        except Exception:
            pass
    return value


def encrypted_size(plain_size: int) -> int:
    return plain_size + 32


def is_selected_file(path: str, size: int, min_video_size: int) -> bool:
    ext = Path(path).suffix.lower()
    if ext in SUB_EXTS:
        return True
    return ext in VIDEO_EXTS and size >= min_video_size


def in_start_window(config: dict[str, Any], now: dt.datetime | None = None) -> bool:
    from zoneinfo import ZoneInfo
    sch = config["schedule"]
    now = now or dt.datetime.now(ZoneInfo(sch.get("timezone", "Asia/Shanghai")))
    start = dt.time.fromisoformat(sch.get("start", "01:00"))
    end = dt.time.fromisoformat(sch.get("end", "07:00"))
    t = now.time().replace(tzinfo=None)
    return start <= t < end if start < end else (t >= start or t < end)


def setup_logger(path: str, verbose: bool = False) -> logging.Logger:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("encrypted-mover")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


class Database:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS sources(
          id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, url TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1, refresh_seconds INTEGER NOT NULL DEFAULT 3600,
          last_sync INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS tasks(
          id INTEGER PRIMARY KEY, source_id INTEGER, line_no INTEGER, uri TEXT NOT NULL,
          infohash TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued', enabled INTEGER NOT NULL DEFAULT 1,
          aria_gid TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', total_size INTEGER NOT NULL DEFAULT 0,
          selected_json TEXT NOT NULL DEFAULT '[]', task_dir TEXT NOT NULL DEFAULT '',
          attempt INTEGER NOT NULL DEFAULT 0, next_retry INTEGER NOT NULL DEFAULT 0,
          last_progress INTEGER NOT NULL DEFAULT 0, last_progress_at INTEGER NOT NULL DEFAULT 0,
          error TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
          UNIQUE(source_id, infohash)
        );
        CREATE INDEX IF NOT EXISTS idx_tasks_pick ON tasks(state, enabled, next_retry, line_no);
        CREATE TABLE IF NOT EXISTS uploads(
          id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, local_path TEXT NOT NULL,
          plain_name TEXT NOT NULL, encrypted_name TEXT NOT NULL, plain_size INTEGER NOT NULL,
          remote_path TEXT NOT NULL, remote_actual_name TEXT NOT NULL DEFAULT '',
          openlist_task_id TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'pending',
          error TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
          UNIQUE(task_id, local_path)
        );
        CREATE TABLE IF NOT EXISTS file_signatures(
          signature TEXT PRIMARY KEY, seen_count INTEGER NOT NULL DEFAULT 0,
          sample_name TEXT NOT NULL DEFAULT '', size INTEGER NOT NULL DEFAULT 0
        );
        """)

    def ensure_source(self, name: str, url: str, refresh: int = 3600) -> None:
        self.db.execute("INSERT OR IGNORE INTO sources(name,url,refresh_seconds) VALUES(?,?,?)", (name, url, refresh))

    def add_source(self, name: str, url: str, refresh: int = 3600) -> None:
        self.db.execute("INSERT INTO sources(name,url,refresh_seconds) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET url=excluded.url,enabled=1,refresh_seconds=excluded.refresh_seconds", (name, url, refresh))

    def add_manual(self, uri: str) -> int:
        if not MAGNET_RE.match(uri): raise ValueError("manual task must be a magnet URI")
        h = infohash(uri)
        row = self.db.execute("SELECT id FROM tasks WHERE infohash=? ORDER BY id LIMIT 1", (h,)).fetchone()
        if row: return int(row[0])
        n = now_ts()
        cur = self.db.execute("INSERT INTO tasks(source_id,line_no,uri,infohash,state,created_at,updated_at) VALUES(NULL,0,?,?,'queued',?,?)", (uri,h,n,n))
        return int(cur.lastrowid)

    def source_rows(self, due_only: bool = False) -> list[sqlite3.Row]:
        q = "SELECT * FROM sources WHERE enabled=1"
        rows = list(self.db.execute(q))
        if due_only:
            n = now_ts()
            rows = [r for r in rows if r["last_sync"] + r["refresh_seconds"] <= n]
        return rows

    def import_lines(self, source_id: int, lines: list[str], parity: str) -> int:
        seen: set[str] = set()
        assigned_seen: set[str] = set()
        count = 0
        n = now_ts()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            task_no = 0
            for _, raw in enumerate(lines, 1):
                uri = raw.strip()
                if not uri or uri.startswith("#") or not MAGNET_RE.match(uri):
                    continue
                task_no += 1
                line_no = task_no
                h = infohash(uri)
                seen.add(h)
                assigned = (line_no % 2 == 1) if parity == "odd" else (line_no % 2 == 0)
                if not assigned:
                    continue
                assigned_seen.add(h)
                self.db.execute("""INSERT INTO tasks(source_id,line_no,uri,infohash,state,created_at,updated_at)
                    VALUES(?,?,?,?, 'queued',?,?) ON CONFLICT(source_id,infohash) DO UPDATE SET
                    line_no=excluded.line_no,uri=excluded.uri,enabled=1,updated_at=excluded.updated_at""",
                    (source_id, line_no, uri, h, n, n))
                count += 1
            if assigned_seen:
                marks = ",".join("?" for _ in assigned_seen)
                self.db.execute(f"UPDATE tasks SET enabled=0,updated_at=? WHERE source_id=? AND state IN ('queued','retry_wait') AND infohash NOT IN ({marks})", (n, source_id, *assigned_seen))
            else:
                self.db.execute("UPDATE tasks SET enabled=0,updated_at=? WHERE source_id=? AND state IN ('queued','retry_wait')", (n, source_id))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return count

    def source_result(self, sid: int, error: str = "") -> None:
        self.db.execute("UPDATE sources SET last_sync=?,last_error=? WHERE id=?", (now_ts(), error, sid))

    def recover_transient(self) -> None:
        n = now_ts()
        self.db.execute("UPDATE tasks SET state='retry_wait',next_retry=?,error='recovered after service restart',updated_at=? WHERE state IN ('probing','metadata')", (n,n))

    def next_task(self) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM tasks WHERE enabled=1 AND ((state IN ('queued','retry_wait','upload_retry') AND next_retry<=?) OR state IN ('downloading','downloaded','uploading')) ORDER BY CASE state WHEN 'uploading' THEN 0 WHEN 'upload_retry' THEN 1 WHEN 'downloaded' THEN 2 WHEN 'downloading' THEN 3 ELSE 4 END,line_no,id LIMIT 1", (now_ts(),)).fetchone()

    def update_task(self, tid: int, state: str | None = None, **fields: Any) -> None:
        if state is not None:
            fields["state"] = state
        fields["updated_at"] = now_ts()
        cols = ",".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE tasks SET {cols} WHERE id=?", (*fields.values(), tid))

    def task(self, tid: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()

    def tasks(self, limit: int = 50) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM tasks ORDER BY id DESC LIMIT ?", (limit,)))

    def add_upload(self, task_id: int, local: str, plain_name: str, enc_name: str, size: int, remote: str) -> sqlite3.Row:
        n = now_ts()
        self.db.execute("""INSERT INTO uploads(task_id,local_path,plain_name,encrypted_name,plain_size,remote_path,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(task_id,local_path) DO UPDATE SET encrypted_name=excluded.encrypted_name,plain_size=excluded.plain_size,remote_path=excluded.remote_path,updated_at=excluded.updated_at""",
          (task_id, local, plain_name, enc_name, size, remote, n, n))
        return self.db.execute("SELECT * FROM uploads WHERE task_id=? AND local_path=?", (task_id, local)).fetchone()

    def uploads_for_task(self, task_id: int) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM uploads WHERE task_id=? ORDER BY id", (task_id,)))

    def update_upload(self, uid: int, state: str, **fields: Any) -> None:
        fields["state"] = state
        fields["updated_at"] = now_ts()
        cols = ",".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE uploads SET {cols} WHERE id=?", (*fields.values(), uid))

    def signature_count(self, path: str, size: int) -> int:
        name = Path(path).name.lower().strip()
        sig = hashlib.sha256(f"{name}\0{size}".encode()).hexdigest()
        row = self.db.execute("SELECT seen_count FROM file_signatures WHERE signature=?", (sig,)).fetchone()
        return int(row[0]) if row else 0

    def record_signatures(self, files: list[dict[str, Any]]) -> None:
        for f in files:
            name = Path(f["path"]).name.lower().strip()
            sig = hashlib.sha256(f"{name}\0{f['length']}".encode()).hexdigest()
            self.db.execute("INSERT INTO file_signatures(signature,seen_count,sample_name,size) VALUES(?,1,?,?) ON CONFLICT(signature) DO UPDATE SET seen_count=seen_count+1", (sig, name, f["length"]))


class Aria2:
    def __init__(self, url: str, secret: str = ""):
        self.url = url
        self.secret = secret
        self.seq = 0

    def call(self, method: str, *params: Any) -> Any:
        self.seq += 1
        args = list(params)
        if self.secret:
            args.insert(0, "token:" + self.secret)
        body = json.dumps({"jsonrpc":"2.0","id":self.seq,"method":"aria2."+method,"params":args}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            result = json.load(resp)
        if "error" in result:
            raise RuntimeError(result["error"].get("message", str(result["error"])))
        return result.get("result")

    def status(self, gid: str) -> dict[str, Any]:
        keys = ["gid","status","totalLength","completedLength","downloadSpeed","uploadSpeed","connections","errorCode","errorMessage","followedBy","files","bittorrent","infoHash","dir"]
        return self.call("tellStatus", gid, keys)

    def remove_and_purge(self, gid: str) -> None:
        if not gid:
            return
        with contextlib.suppress(Exception): self.call("forceRemove", gid)
        with contextlib.suppress(Exception): self.call("removeDownloadResult", gid)


class OpenList:
    def __init__(self, cfg: dict[str, Any], logger: logging.Logger):
        self.base = cfg["base_url"].rstrip("/")
        self.user = cfg["username"]
        self.password_file = cfg["password_file"]
        self.logger = logger
        self.token = ""

    def _request(self, method: str, path: str, payload: Any = None, headers: dict[str,str] | None = None, timeout: int = 60) -> Any:
        data = None if payload is None else json.dumps(payload).encode()
        hs = {"Content-Type":"application/json"}
        if self.token: hs["Authorization"] = self.token
        if headers: hs.update(headers)
        req = urllib.request.Request(self.base + path, data=data, headers=hs, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}

    def login(self) -> None:
        password = Path(self.password_file).read_text(encoding="utf-8").rstrip("\r\n")
        res = self._request("POST", "/api/auth/login", {"username":self.user,"password":password})
        if res.get("code") != 200:
            raise RuntimeError("OpenList login failed: " + str(res.get("message")))
        self.token = res["data"]["token"]

    def fs_get(self, path: str) -> dict[str, Any] | None:
        try:
            res = self._request("POST", "/api/fs/get", {"path":path,"password":""})
            return res.get("data") if res.get("code") == 200 else None
        except urllib.error.HTTPError as e:
            if e.code == 404: return None
            raise

    def fs_list(self, path: str, refresh: bool = False) -> list[dict[str, Any]]:
        res = self._request("POST", "/api/fs/list", {"path":path,"password":"","page":1,"per_page":0,"refresh":refresh})
        return (res.get("data") or {}).get("content") or [] if res.get("code") == 200 else []

    def mkdir(self, path: str) -> None:
        res = self._request("POST", "/api/fs/mkdir", {"path":path})
        if res.get("code") != 200 and "exist" not in str(res.get("message","")).lower():
            raise RuntimeError("mkdir failed: " + str(res))

    def tasks(self, done: bool) -> list[dict[str, Any]]:
        endpoint = "/api/task/upload/done" if done else "/api/task/upload/undone"
        res = self._request("GET", endpoint)
        return res.get("data") or [] if res.get("code") == 200 else []

    def create_storage(self, storage: dict[str, Any]) -> int:
        res = self._request("GET", "/api/admin/storage/list?page=1&per_page=100")
        content = ((res.get("data") or {}).get("content") or []) if res.get("code") == 200 else []
        for item in content:
            if item.get("mount_path") == storage.get("mount_path"):
                self.logger.info("storage already exists: %s", storage.get("mount_path"))
                return int(item.get("id") or 0)
        allowed = {"mount_path","order","driver","cache_expiration","custom_cache_policies","addition","remark","disabled","disable_index","enable_sign","order_by","order_direction","extract_folder","web_proxy","webdav_policy","proxy_range","down_proxy_url","disable_proxy_sign"}
        payload = {k:v for k,v in storage.items() if k in allowed}
        created = self._request("POST", "/api/admin/storage/create", payload)
        if created.get("code") != 200:
            raise RuntimeError("create storage failed: " + str(created))
        return int((created.get("data") or {}).get("id") or 0)

    def upload_stream(self, remote_path: str, process: subprocess.Popen[bytes], length: int, timeout: int, disk_guard: Any = None) -> dict[str, Any]:
        u = urllib.parse.urlsplit(self.base)
        conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(u.hostname, u.port, timeout=timeout)
        sent = 0
        try:
            path = (u.path.rstrip("/") + "/api/fs/put") or "/api/fs/put"
            conn.putrequest("PUT", path)
            conn.putheader("Authorization", self.token)
            conn.putheader("File-Path", urllib.parse.quote(remote_path, safe="/"))
            conn.putheader("As-Task", "true")
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(length))
            conn.endheaders()
            assert process.stdout is not None
            while True:
                chunk = process.stdout.read(512 * 1024)
                if not chunk: break
                conn.send(chunk)
                sent += len(chunk)
                if disk_guard is not None and not disk_guard():
                    raise OSError("disk free dropped below reserve during OpenList upload")
            response = conn.getresponse()
            raw = response.read()
        finally:
            conn.close()
        rc = process.wait(timeout=30)
        stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
        if process.stdout: process.stdout.close()
        if process.stderr: process.stderr.close()
        if rc != 0: raise RuntimeError(f"encrypt-tool exited {rc}: {stderr[-1000:]}")
        if sent != length: raise RuntimeError(f"encrypted stream length mismatch: sent={sent} expected={length}")
        if response.status >= 400: raise RuntimeError(f"OpenList upload HTTP {response.status}: {raw[:500]!r}")
        result = json.loads(raw) if raw else {}
        if result.get("code") != 200: raise RuntimeError("OpenList upload rejected: " + str(result))
        return result

    def range_header(self, item: dict[str, Any]) -> bytes:
        raw_url = item.get("raw_url") or item.get("rawUrl")
        if not raw_url: return b""
        req = urllib.request.Request(raw_url, headers={"Range":"bytes=0-31"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read(32)


class Mover:
    def __init__(self, cfg: dict[str, Any], verbose: bool = False):
        self.cfg = cfg
        Path(cfg["paths"]["work_dir"]).mkdir(parents=True, exist_ok=True)
        self.log = setup_logger(cfg["paths"]["log"], verbose)
        self.db = Database(cfg["paths"]["database"])
        self.aria = Aria2(cfg["aria2"]["rpc_url"], cfg["aria2"].get("secret", ""))
        self.openlist = OpenList(cfg["openlist"], self.log)
        self.stop = False
        self.last_source_check = 0
        for src in cfg.get("sources", []):
            self.db.ensure_source(src["name"], src["url"], int(src.get("refresh_seconds", 3600)))
        self.db.recover_transient()

    def sync_sources(self, force: bool = False) -> None:
        rows = self.db.source_rows(False if force else True)
        for row in rows:
            try:
                req = urllib.request.Request(row["url"], headers={"User-Agent":"encrypted-mover/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    text = resp.read().decode("utf-8-sig")
                count = self.db.import_lines(row["id"], text.splitlines(), self.cfg["node"]["parity"])
                self.db.source_result(row["id"])
                self.log.info("source %s synced: %d assigned tasks", row["name"], count)
            except Exception as exc:
                self.db.source_result(row["id"], str(exc))
                self.log.error("source %s sync failed: %s", row["name"], exc)

    def maybe_sync(self) -> None:
        if time.time() - self.last_source_check >= 60:
            self.sync_sources()
            self.last_source_check = time.time()

    def disk_free(self) -> int:
        return shutil.disk_usage(self.cfg["paths"]["work_dir"]).free

    def task_dir(self, task: sqlite3.Row) -> Path:
        return Path(self.cfg["paths"]["work_dir"]) / f"task-{task['id']}-{task['infohash'][:12]}"

    def fail(self, task: sqlite3.Row, reason: str, retry: bool = True, preserve_download: bool = False) -> None:
        attempt = int(task["attempt"]) + 1
        if attempt >= self.cfg["limits"].get("max_attempts",3) or not retry:
            state = "dead"
        else:
            state = "upload_retry" if preserve_download else "retry_wait"
        next_retry = now_ts() + self.cfg["limits"].get("retry_cooldown_seconds",86400) if state in ("retry_wait", "upload_retry") else 0
        self.db.update_task(task["id"], state, attempt=attempt, next_retry=next_retry, error=reason)
        self.log.error("task %s -> %s: %s", task["id"], state, reason)

    def cleanup_download(self, gid: str, directory: Path) -> None:
        self.aria.remove_and_purge(gid)
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)

    def acquire_metadata(self, task: sqlite3.Row, directory: Path) -> tuple[str, dict[str,Any]]:
        directory.mkdir(parents=True, exist_ok=True)
        opts = {"dir":str(directory),"bt-save-metadata":"true","bt-metadata-only":"true","pause-metadata":"true","seed-time":"0","seed-ratio":"0"}
        gid = self.aria.call("addUri", [task["uri"]], opts)
        metadata_gid = gid
        self.db.update_task(task["id"], "metadata", aria_gid=gid, task_dir=str(directory))
        deadline = time.time() + self.cfg["limits"]["metadata_timeout_seconds"]
        while time.time() < deadline and not self.stop:
            self.maybe_sync()
            st = self.aria.status(gid)
            followed = st.get("followedBy") or []
            if followed:
                gid = followed[0]
                st = self.aria.status(gid)
                with contextlib.suppress(Exception): self.aria.call("removeDownloadResult", metadata_gid)
                return gid, st
            files = st.get("files") or []
            if st.get("bittorrent") and files:
                return gid, st
            if st.get("status") == "error":
                raise RuntimeError(st.get("errorMessage") or "metadata error")
            time.sleep(3)
        raise TimeoutError("metadata acquisition stalled")

    def prepare_download(self, task: sqlite3.Row, gid: str, st: dict[str,Any], directory: Path) -> list[dict[str,Any]]:
        files = []
        raw_files = st.get("files") or self.aria.call("getFiles", gid)
        for f in raw_files:
            item = {"index":str(f["index"]),"path":f["path"],"length":int(f["length"])}
            files.append(item)
        self.db.record_signatures(files)
        selected = []
        for f in files:
            if not is_selected_file(f["path"], f["length"], self.cfg["filters"]["min_video_bytes"]):
                continue
            # A small identical attachment seen in three torrents is treated as advertising.
            if f["length"] < self.cfg["filters"]["min_video_bytes"] and self.db.signature_count(f["path"], f["length"]) >= 3:
                continue
            selected.append(f)
        if not selected:
            raise ValueError("no eligible video or subtitle files")
        total = sum(f["length"] for f in selected)
        if total > self.cfg["limits"]["max_task_bytes"]:
            raise OverflowError(f"selected size {total} exceeds limit")
        if self.disk_free() < total + self.cfg["limits"]["reserve_bytes"]:
            raise OSError(f"insufficient disk: need task bytes + reserve ({total})")
        indexes = ",".join(f["index"] for f in selected)
        self.aria.call("changeOption", gid, {"select-file":indexes,"dir":str(directory),"bt-metadata-only":"false","seed-time":"0","seed-ratio":"0","max-upload-limit":"1K"})
        with contextlib.suppress(Exception): self.aria.call("unpause", gid)
        name = ((st.get("bittorrent") or {}).get("info") or {}).get("name") or f"task-{task['id']}"
        self.db.update_task(task["id"], "downloading", aria_gid=gid, name=name, total_size=total, selected_json=json.dumps(selected), last_progress=0, last_progress_at=now_ts())
        return selected

    def monitor_download(self, task: sqlite3.Row, gid: str, directory: Path) -> None:
        cfg = self.cfg["limits"]
        started = time.time()
        last_progress = 0
        last_change = time.time()
        speed_window_started = time.time()
        speed_window_bytes = 0
        while not self.stop:
            self.maybe_sync()
            st = self.aria.status(gid)
            status = st.get("status")
            completed = int(st.get("completedLength") or 0)
            if completed > last_progress:
                last_progress, last_change = completed, time.time()
                self.db.update_task(task["id"], last_progress=completed, last_progress_at=now_ts())

            if status == "complete": return
            if status in ("error","removed"):
                raise RuntimeError(st.get("errorMessage") or f"aria2 status {status}")
            if self.disk_free() < cfg["reserve_bytes"]:
                raise OSError("disk free below reserve; active task evicted")
            if time.time() - last_change > cfg["no_progress_seconds"]:
                raise TimeoutError("no completed bytes within stall window")
            if time.time() - started > cfg["max_runtime_seconds"]:
                raise TimeoutError("task exceeded maximum runtime")
            if time.time() - speed_window_started >= cfg["low_speed_window_seconds"]:
                elapsed = time.time() - speed_window_started
                avg = (completed - speed_window_bytes) / max(elapsed,1)
                if avg < cfg["min_average_bytes_per_second"]:
                    raise TimeoutError(f"average speed too low: {avg:.0f} B/s")
                speed_window_started = time.time()
                speed_window_bytes = completed
            time.sleep(cfg.get("poll_seconds",10))

    def encrypt_name(self, plain: str) -> str:
        cmd = [self.cfg["encryption"]["tool"],"name","--password-file",self.cfg["encryption"]["password_file"],"-i",plain,"-t",self.cfg["encryption"].get("type","aesctr"),"-s",self.cfg["encryption"].get("suffix",".bin")]
        return subprocess.check_output(cmd, text=True).strip()

    def valid_remote(self, item: dict[str,Any] | None, plain_size: int) -> bool:
        if not item or int(item.get("size") or -1) != encrypted_size(plain_size): return False
        header = self.openlist.range_header(item)
        return len(header) == 32 and header[:6] == b"AECTR2" and header[6] == 2 and struct.unpack(">Q", header[24:32])[0] == plain_size

    def find_existing(self, remote_dir: str, enc_name: str, plain_size: int, refresh: bool = False) -> str | None:
        exact_path = remote_dir.rstrip("/") + "/" + enc_name
        item = self.openlist.fs_get(exact_path)
        if self.valid_remote(item, plain_size): return enc_name
        for f in self.openlist.fs_list(remote_dir, refresh=refresh):
            if f.get("name") == enc_name and self.valid_remote(f, plain_size): return str(f["name"])
        return None

    def wait_upload_task(self, before: set[str], enc_name: str, remote_dir: str, plain_size: int) -> str:
        cfg = self.cfg["upload"]
        deadline = time.time() + cfg["task_timeout_seconds"]
        appeared_deadline = time.time() + cfg["task_appear_timeout_seconds"]
        matched = ""
        while time.time() < deadline:
            undone = self.openlist.tasks(False)
            done = self.openlist.tasks(True)
            all_tasks = undone + done
            for t in all_tasks:
                tid = str(t.get("id") or t.get("uuid") or "")
                text = json.dumps(t, ensure_ascii=False)
                if tid not in before and (enc_name in text or remote_dir in text):
                    matched = tid
                    state = int(t.get("state",0))
                    if state == 2:
                        return tid
                    if state in (4,5,6,7):
                        raise RuntimeError("OpenList upload task failed: " + str(t.get("error") or t.get("message") or state))
            if not matched and time.time() > appeared_deadline:
                existing = self.find_existing(remote_dir, enc_name, plain_size, refresh=True)
                if existing: return "verified-without-task"
            time.sleep(cfg.get("poll_seconds",5))
        raise TimeoutError("OpenList upload task timeout")

    def upload_file(self, task: sqlite3.Row, local: Path) -> None:
        size = local.stat().st_size
        enc_name = self.encrypt_name(local.name)
        remote_dir = self.cfg["openlist"]["target_dir"]
        remote_path = remote_dir.rstrip("/") + "/" + enc_name
        upload = self.db.add_upload(task["id"], str(local), local.name, enc_name, size, remote_path)
        existing = self.find_existing(remote_dir, enc_name, size, refresh=True)
        if existing:
            self.db.update_upload(upload["id"], "skipped_existing", remote_actual_name=existing)
            local.unlink(missing_ok=True)
            self.log.info("remote already verified; deleted local %s", local)
            return
        before = {str(t.get("id") or t.get("uuid") or "") for t in self.openlist.tasks(False)+self.openlist.tasks(True)}
        before_names = {str(f.get("name")) for f in self.openlist.fs_list(remote_dir, refresh=True)}
        cmd = [self.cfg["encryption"]["tool"],"enc","--password-file",self.cfg["encryption"]["password_file"],"-i",str(local),"-t",self.cfg["encryption"].get("type","aesctr"),"--stdout"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.db.update_upload(upload["id"], "uploading")
        try:
            self.openlist.upload_stream(
                remote_path, proc, encrypted_size(size), self.cfg["upload"]["stream_timeout_seconds"],
                disk_guard=lambda: self.disk_free() >= self.cfg["limits"]["reserve_bytes"],
            )
            task_id = self.wait_upload_task(before, enc_name, remote_dir, size)
            actual = self.find_existing(remote_dir, enc_name, size, refresh=True)
            if not actual:
                # Cloud providers may auto-rename; only accept a fresh exact-size V2 candidate.
                candidates = []
                stem, suffix = os.path.splitext(enc_name)
                rename_re = re.compile(r"^" + re.escape(stem) + r"(?:\([0-9]+\)|_[0-9]+)" + re.escape(suffix) + r"$")
                for f in self.openlist.fs_list(remote_dir, refresh=True):
                    name = str(f.get("name"))
                    if name not in before_names and rename_re.match(name) and self.valid_remote(f, size):
                        candidates.append(name)
                if len(candidates) == 1: actual = candidates[0]
            if not actual: raise RuntimeError("remote verification failed after successful task")
            self.db.update_upload(upload["id"], "completed", openlist_task_id=task_id, remote_actual_name=actual)
            local.unlink(missing_ok=True)
            self.log.info("uploaded and verified: %s -> %s", local.name, actual)
        except Exception:
            with contextlib.suppress(Exception): proc.kill()
            with contextlib.suppress(Exception): proc.wait(timeout=10)
            if proc.stdout: proc.stdout.close()
            if proc.stderr: proc.stderr.close()
            raise

    def selected_paths(self, task: sqlite3.Row) -> list[Path]:
        selected = json.loads(task["selected_json"] or "[]")
        paths = []
        root = Path(task["task_dir"]).resolve()
        for f in selected:
            p = Path(f["path"])
            if not p.is_absolute(): p = root / p
            p = p.resolve()
            if p != root and root not in p.parents:
                raise RuntimeError(f"aria2 returned a path outside task directory: {p}")
            if p.exists() and p.is_file(): paths.append(p)
        return paths

    def process(self, task: sqlite3.Row) -> None:
        directory = Path(task["task_dir"]) if task["task_dir"] else self.task_dir(task)
        gid = str(task["aria_gid"] or "")
        phase = "download" if task["state"] in ("queued","retry_wait","probing","metadata","downloading") else "upload"
        try:
            if task["state"] not in ("downloading", "downloaded", "uploading", "upload_retry"):
                self.db.update_task(task["id"], "probing", error="")
                gid, st = self.acquire_metadata(task, directory)
                selected = self.prepare_download(task, gid, st, directory)
                task = self.db.task(task["id"])
                self.log.info("task %s downloading %d selected files, %.2f GiB", task["id"], len(selected), task["total_size"]/GIB)
            if task["state"] == "downloading":
                if not gid: raise RuntimeError("cannot resume download without aria2 gid")
                self.monitor_download(task, gid, directory)
                self.aria.remove_and_purge(gid)
                self.db.update_task(task["id"], "downloaded")
                task = self.db.task(task["id"])
            phase = "upload"
            self.openlist.login()
            self.openlist.mkdir(self.cfg["openlist"]["target_dir"])
            task = self.db.task(task["id"])
            paths = self.selected_paths(task)
            completed_uploads = self.db.uploads_for_task(task["id"])
            if not paths:
                if completed_uploads and all(u["state"] in ("completed","skipped_existing") for u in completed_uploads):
                    self.cleanup_download(gid, directory)
                    self.db.update_task(task["id"], "completed", error="")
                    return
                raise RuntimeError("download completed but selected files are missing")
            self.db.update_task(task["id"], "uploading")
            for path in paths:
                self.upload_file(task, path)
            self.cleanup_download(gid, directory)
            self.db.update_task(task["id"], "completed", error="")
            self.log.info("task %s completed", task["id"])
        except (OverflowError, ValueError) as exc:
            self.cleanup_download(gid, directory)
            self.db.update_task(task["id"], "rejected", error=str(exc))
        except Exception as exc:
            if phase == "download":
                self.cleanup_download(gid, directory)
            self.fail(self.db.task(task["id"]) or task, str(exc), retry=True, preserve_download=(phase == "upload"))

    def close(self) -> None:
        with contextlib.suppress(Exception): self.db.db.close()
        for handler in list(self.log.handlers):
            handler.close()
            self.log.removeHandler(handler)

    def run(self, once: bool = False) -> None:
        self.sync_sources(force=True)
        while not self.stop:
            self.maybe_sync()
            task = self.db.next_task()
            if task and in_start_window(self.cfg):
                self.process(task)
                if once: return
                continue
            if once: return
            time.sleep(20)


def load_config(path: str) -> dict[str,Any]:
    with open(path, encoding="utf-8") as f: return json.load(f)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/etc/encrypted-mover/config.json")
    ap.add_argument("--verbose", action="store_true")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("daemon")
    sub.add_parser("run-once")
    sub.add_parser("sync")
    sub.add_parser("status")
    src = sub.add_parser("source-add"); src.add_argument("name"); src.add_argument("url"); src.add_argument("--refresh",type=int,default=3600)
    sub.add_parser("source-list")
    sd = sub.add_parser("source-disable"); sd.add_argument("name")
    retry = sub.add_parser("retry"); retry.add_argument("id",type=int)
    cancel = sub.add_parser("cancel"); cancel.add_argument("id",type=int)
    provision = sub.add_parser("storage-create"); provision.add_argument("json_file")
    add = sub.add_parser("add"); add.add_argument("uri")
    args = ap.parse_args()
    cfg = load_config(args.config)
    mover = Mover(cfg,args.verbose)
    signal.signal(signal.SIGTERM, lambda *_: setattr(mover,"stop",True))
    signal.signal(signal.SIGINT, lambda *_: setattr(mover,"stop",True))
    try:
        if args.command == "daemon": mover.run(False)
        elif args.command == "run-once": mover.run(True)
        elif args.command == "sync": mover.sync_sources(True)
        elif args.command == "source-add": mover.db.add_source(args.name,args.url,args.refresh)
        elif args.command == "add": print(mover.db.add_manual(args.uri))
        elif args.command == "source-list":
            for row in mover.db.source_rows(False):
                print(f"{row['name']} enabled={row['enabled']} refresh={row['refresh_seconds']} url={row['url']} error={row['last_error']}")
        elif args.command == "source-disable": mover.db.db.execute("UPDATE sources SET enabled=0 WHERE name=?", (args.name,))
        elif args.command == "retry": mover.db.update_task(args.id,"queued",next_retry=0,error="")
        elif args.command == "cancel": mover.db.update_task(args.id,"canceled",enabled=0)
        elif args.command == "storage-create":
            mover.openlist.login()
            with open(args.json_file,encoding="utf-8") as f: storage=json.load(f)
            print(mover.openlist.create_storage(storage))
        elif args.command == "status":
            for row in mover.db.tasks(100):
                print(f"{row['id']:4} line={row['line_no'] or 0:3} {row['state']:<18} {row['name'] or row['infohash'][:12]} {row['error'][:80]}")
    finally:
        mover.close()
    return 0

if __name__ == "__main__": raise SystemExit(main())
