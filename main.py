"""
FreshGuard IoT API — v2.2.0
Backend for AI-Powered Food Freshness Monitoring — The Obsidian Pulse

Run locally:
    pip install -r requirements.txt
    python main.py

Render deployment:
    Start command: uvicorn main:app --host 0.0.0.0 --port $PORT
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from datetime import datetime, timedelta
from typing import Optional
import jwt
import hashlib
import sqlite3
import logging
import os
import uvicorn

# ─────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("freshguard")

# ─────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "freshguard-ultra-secure-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440          # 24 hours
DB_PATH = os.getenv("DB_PATH", "freshguard.db")

app = FastAPI(
    title="FreshGuard IoT API",
    description="Backend for Food Freshness Monitoring — The Obsidian Pulse",
    version="2.2.0",
)

# ─────────────────────────────────────────
#  CORS  — allows browser + ESP32 access
# ─────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten to your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)

# ─────────────────────────────────────────
#  SQLITE SETUP  (persists across restarts)
# ─────────────────────────────────────────
def get_db():
    """Return a thread-local SQLite connection."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables on first run."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    UNIQUE NOT NULL,
                password TEXT    NOT NULL,
                created  TEXT    DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sensor_readings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                gas         REAL,
                temperature REAL,
                humidity    REAL,
                status      TEXT,
                timestamp   TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.commit()
    logger.info("Database initialised: %s", DB_PATH)


# In-memory latest reading (fastest for 2-second polling)
latest_reading: dict = {}

# ─────────────────────────────────────────
#  PYDANTIC MODELS
# ─────────────────────────────────────────
class UserAuth(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty.")
        return v.lower()

    @field_validator("password")
    @classmethod
    def password_length(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Access key must be at least 6 characters.")
        return v


class SensorData(BaseModel):
    """
    Payload the ESP32 POSTs to /sensor-data
    {
      "gas":         450.5,
      "temperature": 4.2,
      "humidity":    67.3
    }
    """
    gas: float
    temperature: float
    humidity: float

    @field_validator("gas", "temperature", "humidity")
    @classmethod
    def finite_number(cls, v: float) -> float:
        import math
        if math.isnan(v) or math.isinf(v):
            raise ValueError("Sensor value must be a finite number.")
        return round(v, 2)


# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_access_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM
    )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> str:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authorization header missing.")
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
        )
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload.")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials.")


def classify_freshness(gas: float, temp: float, hum: float) -> str:
    """
    Rule-based freshness classifier.
    Thresholds calibrated for MQ-135 + DHT11 in a cold room.
    Tune these values once you see real ESP32 numbers.

    Returns: FRESH | MODERATE | SPOILED!
    """
    if gas < 1300 and hum < 65 and temp < 8:
        return "FRESH"
    elif gas < 1800 and hum < 82 and temp < 15:
        return "MODERATE"
    else:
        return "SPOILED!"


# ─────────────────────────────────────────
#  STARTUP
# ─────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    init_db()


# ─────────────────────────────────────────
#  MIDDLEWARE — request logger
# ─────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info("→ %s %s  client=%s", request.method, request.url.path, request.client.host)
    response = await call_next(request)
    logger.info("← %s", response.status_code)
    return response


# ─────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────

@app.get("/", tags=["Health"])
def health_check():
    return {
        "status": "online",
        "system": "FreshGuard Obsidian Pulse",
        "version": "2.2.0",
        "timestamp": datetime.now().isoformat(),
    }


# ── AUTHENTICATION ────────────────────────

@app.post("/signup", status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def signup(user: UserAuth):
    """
    Register a new user.
    POST /signup  { "username": "...", "password": "..." }
    Returns a JWT token so the user is logged in immediately.
    """
    username = user.username   # already lowercased by validator

    with get_db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="Username already exists. Please choose another.",
            )

        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hash_password(user.password)),
        )
        conn.commit()

    logger.info("New user registered: %s", username)
    token = create_access_token(username)
    return {
        "message": f"Account created for '{username}'.",
        "access_token": token,
        "token_type": "bearer",
    }


@app.post("/login", tags=["Auth"])
async def login(user: UserAuth):
    """
    Authenticate and get a JWT.
    POST /login  { "username": "...", "password": "..." }
    """
    username = user.username

    with get_db() as conn:
        row = conn.execute(
            "SELECT password FROM users WHERE username = ?", (username,)
        ).fetchone()

    if not row or row["password"] != hash_password(user.password):
        logger.warning("Failed login attempt for: %s", username)
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    token = create_access_token(username)
    logger.info("User logged in: %s", username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
    }


# ── SENSOR DATA (ESP32 → Backend) ─────────

@app.post("/sensor-data", tags=["Sensor"])
async def receive_sensor_data(data: SensorData):
    """
    ESP32 POSTs here every N seconds. No auth required.

    Arduino sketch example:
        http.begin("http://<YOUR_IP>:8000/sensor-data");
        http.addHeader("Content-Type", "application/json");
        String body = "{\\"gas\\":"+String(gas,1)+",\\"temperature\\":"+String(temp,1)+",\\"humidity\\":"+String(hum,1)+"}";
        int code = http.POST(body);
    """
    status_val = classify_freshness(data.gas, data.temperature, data.humidity)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    reading = {
        "gas": data.gas,
        "temperature": data.temperature,
        "humidity": data.humidity,
        "status": status_val,
        "timestamp": timestamp,
    }

    # Update in-memory latest (fast)
    latest_reading.clear()
    latest_reading.update(reading)

    # Persist to SQLite (keep last 500 readings)
    with get_db() as conn:
        conn.execute(
            """INSERT INTO sensor_readings (gas, temperature, humidity, status, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (data.gas, data.temperature, data.humidity, status_val, timestamp),
        )
        # Prune old rows — keep only latest 500
        conn.execute("""
            DELETE FROM sensor_readings
            WHERE id NOT IN (
                SELECT id FROM sensor_readings ORDER BY id DESC LIMIT 500
            )
        """)
        conn.commit()

    logger.info(
        "Sensor: T=%.1f°C  H=%.1f%%  Gas=%.0f  → %s",
        data.temperature, data.humidity, data.gas, status_val,
    )

    return {
        "message": "Data logged successfully",
        "classification": status_val,
        "timestamp": timestamp,
    }


# Alias — some setups call /data
@app.post("/data", tags=["Sensor"])
async def receive_sensor_data_alias(data: SensorData):
    return await receive_sensor_data(data)


# ── FRONTEND POLLING ENDPOINTS ─────────────

@app.get("/status", tags=["Dashboard"])
async def get_latest_status(current_user: str = Depends(get_current_user)):
    """
    Dashboard polls this every 2 s.
    Returns { data: { temperature, humidity, gas, status, timestamp } }
    """
    if not latest_reading:
        # Try to load last row from DB (server restart case)
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM sensor_readings ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row:
            latest_reading.update(dict(row))
        else:
            raise HTTPException(
                status_code=404,
                detail="No sensor data yet. Waiting for ESP32...",
            )

    return {"user_context": current_user, "data": latest_reading}


@app.get("/latest", tags=["Dashboard"])
async def get_latest_public():
    """
    Same as /status but without auth.
    Useful for quick testing from browser or curl.
    """
    if not latest_reading:
        raise HTTPException(status_code=404, detail="No sensor data yet.")
    return {"data": latest_reading}


@app.get("/history", tags=["Dashboard"])
async def get_history(
    limit: int = 50,
    current_user: str = Depends(get_current_user),
):
    """
    Returns up to `limit` recent readings (newest first).
    Used by the Analytics page.
    """
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM sensor_readings ORDER BY id DESC LIMIT ?", (min(limit, 500),)
        ).fetchall()

    return {
        "user_context": current_user,
        "count": len(rows),
        "data": [dict(r) for r in rows],
    }


@app.get("/users/me", tags=["Auth"])
async def get_me(current_user: str = Depends(get_current_user)):
    return {"username": current_user}


# ─────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  FreshGuard Obsidian Pulse  —  Backend v2.2.0")
    print("=" * 55)
    print("  Local:   http://localhost:8000")
    print("  Docs:    http://localhost:8000/docs")
    print("=" * 55 + "\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)