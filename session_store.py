# session_store.py

import threading
import time
from typing import Dict, Optional
from uuid import uuid4

class Session:
    def __init__(self, client_id: str, timeout: int = 60):
        self.session_id = f"session-{uuid4().hex[:12]}"
        self.client_id = client_id
        self.created_at = time.time()
        self.last_active = self.created_at
        self.timeout = timeout
        self.data = {}  # Arbitrary session metadata
        self.lock = threading.Lock()

    def is_expired(self) -> bool:
        return time.time() - self.last_active > self.timeout

    def touch(self):
        with self.lock:
            self.last_active = time.time()

    def set(self, key: str, value):
        with self.lock:
            self.data[key] = value

    def get(self, key: str):
        with self.lock:
            return self.data.get(key)

class SessionStore:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.lock = threading.Lock()

    def create_session(self, client_id: str, timeout: int = 60) -> Session:
        session = Session(client_id, timeout)
        with self.lock:
            self.sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        with self.lock:
            return self.sessions.get(session_id)

    def cleanup_expired(self):
        with self.lock:
            expired = [sid for sid, s in self.sessions.items() if s.is_expired()]
            for sid in expired:
                del self.sessions[sid]

    def terminate_session(self, session_id: str):
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]

    def list_active_sessions(self) -> Dict[str, Session]:
        with self.lock:
            return {sid: s for sid, s in self.sessions.items() if not s.is_expired()}
