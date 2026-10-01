import os
import random
import sqlite3
from datetime import datetime

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

DB_NAME = "financial_security.db"

USERS = [f"user_{i:03d}" for i in range(1, 21)]
ROLES = ["Employee", "Manager", "Finance", "Admin"]
DEVICES = ["Laptop", "Desktop", "Mobile", "Tablet"]
LOCATIONS = ["Lucknow", "Delhi", "Mumbai", "Bangalore", "Hyderabad", "Pune"]
EVENT_TYPES = ["Login", "Transaction", "File Download", "Password Change", "Account Access"]


def db_connection():
    return sqlite3.connect(DB_NAME)


def create_database():
    conn = db_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            device TEXT NOT NULL,
            location TEXT NOT NULL,
            event_type TEXT NOT NULL,
            login_hour INTEGER NOT NULL,
            transactions INTEGER NOT NULL,
            failed_logins INTEGER NOT NULL,
            download_mb REAL NOT NULL,
            firewall_action TEXT NOT NULL,
            ids_alert TEXT NOT NULL,
            ai_anomaly INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            decision TEXT NOT NULL,
            access_outcome TEXT NOT NULL DEFAULT 'ACCESS GRANTED',
            severity TEXT NOT NULL,
            incident_status TEXT NOT NULL,
            risk_reasons TEXT NOT NULL DEFAULT ''
        )
    """)

    # Migrate databases created by earlier versions of the project.
    existing_columns = {
        row[1]
        for row in cur.execute("PRAGMA table_info(security_logs)").fetchall()
    }

    if "access_outcome" not in existing_columns:
        cur.execute(
            "ALTER TABLE security_logs ADD COLUMN access_outcome TEXT NOT NULL DEFAULT 'ACCESS GRANTED'"
        )

    if "risk_reasons" not in existing_columns:
        cur.execute(
            "ALTER TABLE security_logs ADD COLUMN risk_reasons TEXT NOT NULL DEFAULT ''"
        )

    # Normalize the old MFA label so the database now stores the actual
    # Zero Trust policy decision separately from the simulated access result.
    cur.execute("""
        UPDATE security_logs
        SET decision = 'MFA REQUIRED',
            access_outcome = 'MFA VERIFIED - ACCESS GRANTED'
        WHERE decision = 'MFA VERIFIED - ACCESS GRANTED'
    """)

    cur.execute("""
        UPDATE security_logs
        SET access_outcome = CASE
            WHEN decision = 'DENY' THEN 'ACCESS DENIED'
            WHEN decision = 'MFA REQUIRED' THEN 'MFA VERIFIED - ACCESS GRANTED'
            ELSE 'ACCESS GRANTED'
        END
        WHERE access_outcome IS NULL OR access_outcome = ''
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT
        )
    """)

    conn.commit()
    conn.close()


def audit(action, details=""):
    conn = db_connection()
    conn.execute(
        "INSERT INTO admin_audit (timestamp, action, details) VALUES (?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, details),
    )
    conn.commit()
    conn.close()


class Firewall:
    def check(self, location, event_type):
        if location == "Unknown":
            return "BLOCK"
        if event_type in {"Malware", "Port Scan"}:
            return "BLOCK"
        return "ALLOW"


class IDS:
    def detect(self, failed_logins, transactions, download_mb):
        alerts = []
        if failed_logins >= 4:
            alerts.append("Multiple failed login attempts")
        if transactions >= 8:
            alerts.append("Unusually high transaction activity")
        if download_mb >= 500:
            alerts.append("Large data download")
        return " | ".join(alerts) if alerts else "NORMAL"


class BehaviorAI:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=150,
            contamination=0.15,
            random_state=42,
        )
        self.trained = False

    def train(self, df):
        features = df[
            ["login_hour", "transactions", "failed_logins", "download_mb"]
        ]
        scaled = self.scaler.fit_transform(features)
        self.model.fit(scaled)
        self.trained = True

    def predict(self, event):
        if not self.trained:
            return 0

        values = np.array([[
            event["login_hour"],
            event["transactions"],
            event["failed_logins"],
            event["download_mb"],
        ]])

        scaled = self.scaler.transform(values)
        return 1 if self.model.predict(scaled)[0] == -1 else 0


class RiskEngine:
    def calculate(self, firewall_action, ids_alert, ai_anomaly, event):
        risk = 0
        reasons = []

        if firewall_action == "BLOCK":
            risk += 30
            reasons.append("Firewall blocked the activity")

        if ids_alert != "NORMAL":
            risk += 20
            reasons.append("IDS detected suspicious activity")

        if ai_anomaly:
            risk += 25
            reasons.append("AI behavior model detected an anomaly")

        if event["failed_logins"] >= 3:
            risk += 15
            reasons.append("Multiple failed login attempts")

        if event["transactions"] >= 7:
            risk += 10
            reasons.append("Unusually high transaction activity")

        if event["download_mb"] >= 300:
            risk += 10
            reasons.append("Large data download detected")

        return min(risk, 100), reasons


def zero_trust_decision(risk):
    if risk >= 70:
        return "DENY"
    if risk >= 40:
        return "MFA REQUIRED"
    return "ACCESS GRANTED"


def severity(risk):
    if risk >= 70:
        return "CRITICAL"
    if risk >= 40:
        return "HIGH"
    if risk >= 20:
        return "MEDIUM"
    return "LOW"


def incident_status(level):
    if level == "CRITICAL":
        return "OPEN"
    if level == "HIGH":
        return "INVESTIGATING"
    return "MONITORED"


def generate_event():
    suspicious = random.random() < 0.15

    event = {
        "user_id": random.choice(USERS),
        "role": random.choice(ROLES),
        "device": random.choice(DEVICES),
        "location": random.choice(LOCATIONS),
        "event_type": random.choice(EVENT_TYPES),
        "login_hour": random.randint(8, 20),
        "transactions": random.randint(0, 5),
        "failed_logins": random.randint(0, 2),
        "download_mb": round(random.uniform(10, 250), 2),
    }

    if suspicious:
        event.update({
            "login_hour": random.choice([0, 1, 2, 3, 23]),
            "transactions": random.randint(8, 15),
            "failed_logins": random.randint(4, 8),
            "download_mb": round(random.uniform(500, 1500), 2),
        })

    return event


def load_logs():
    conn = db_connection()
    df = pd.read_sql_query(
        "SELECT * FROM security_logs ORDER BY id DESC",
        conn,
    )
    conn.close()
    return df


def train_behavior_model():
    df = load_logs()

    if len(df) < 20:
        return None

    ai = BehaviorAI()
    ai.train(df)
    return ai


def process_event(event, ai):
    firewall = Firewall()
    ids = IDS()
    risk_engine = RiskEngine()

    firewall_action = firewall.check(
        event["location"],
        event["event_type"],
    )

    ids_alert = ids.detect(
        event["failed_logins"],
        event["transactions"],
        event["download_mb"],
    )

    ai_anomaly = ai.predict(event) if ai else 0

    risk, reasons = risk_engine.calculate(
        firewall_action,
        ids_alert,
        ai_anomaly,
        event,
    )

    # Keep the Zero Trust policy decision separate from the simulated
    # access outcome. This prevents the UI/Copilot from calling an MFA
    # challenge simply "ACCESS GRANTED" and losing the security context.
    decision = zero_trust_decision(risk)

    if decision == "DENY":
        access_outcome = "ACCESS DENIED"
    elif decision == "MFA REQUIRED":
        access_outcome = "MFA VERIFIED - ACCESS GRANTED"
    else:
        access_outcome = "ACCESS GRANTED"

    level = severity(risk)
    status = incident_status(level)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_reasons = " | ".join(reasons) if reasons else "No elevated risk signals"

    conn = db_connection()

    conn.execute("""
        INSERT INTO security_logs (
            timestamp,
            user_id,
            role,
            device,
            location,
            event_type,
            login_hour,
            transactions,
            failed_logins,
            download_mb,
            firewall_action,
            ids_alert,
            ai_anomaly,
            risk_score,
            decision,
            access_outcome,
            severity,
            incident_status,
            risk_reasons
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        event["user_id"],
        event["role"],
        event["device"],
        event["location"],
        event["event_type"],
        event["login_hour"],
        event["transactions"],
        event["failed_logins"],
        event["download_mb"],
        firewall_action,
        ids_alert,
        ai_anomaly,
        risk,
        decision,
        access_outcome,
        level,
        status,
        risk_reasons,
    ))

    conn.commit()
    conn.close()

    return {
        **event,
        "timestamp": timestamp,
        "firewall_action": firewall_action,
        "ids_alert": ids_alert,
        "ai_anomaly": ai_anomaly,
        "risk_score": risk,
        "decision": decision,
        "access_outcome": access_outcome,
        "severity": level,
        "incident_status": status,
        "risk_reasons": risk_reasons,
        "reasons": reasons,
    }


def seed_database(count=100):
    """Create a balanced synthetic baseline with realistic anomalies."""
    events = [generate_event() for _ in range(count)]

    raw_df = pd.DataFrame(events)
    ai = BehaviorAI()
    ai.train(raw_df)

    for event in events:
        process_event(event, ai)


def ensure_initial_data():
    if len(load_logs()) == 0:
        seed_database()


def rebuild_demo_database(count=100):
    """Reset only this educational demo database and rebuild fresh data."""
    conn = db_connection()
    conn.execute("DELETE FROM security_logs")
    conn.commit()
    conn.close()
    seed_database(count)


def local_security_analysis(question, data):
    risk = int(data.get("risk_score", 0))
    anomaly = int(data.get("ai_anomaly", 0))
    failed = int(data.get("failed_logins", 0))
    transactions = int(data.get("transactions", 0))
    download_mb = float(data.get("download_mb", 0))
    firewall = data.get("firewall_action", "UNKNOWN")
    ids = data.get("ids_alert", "NORMAL")
    decision = data.get("decision", "UNKNOWN")
    access = data.get("access_outcome", "UNKNOWN")
    severity_name = data.get("severity", "UNKNOWN")

    reasons = []

    if firewall == "BLOCK":
        reasons.append("the firewall blocked the activity (+30 risk)")

    if ids != "NORMAL":
        reasons.append(f"the IDS generated an alert: {ids} (+20 risk)")

    if anomaly:
        reasons.append("the ML behavior model marked the event as anomalous (+25 risk)")

    if failed >= 3:
        reasons.append(f"there were {failed} failed login attempts (+15 risk)")

    if transactions >= 7:
        reasons.append(f"there were {transactions} transactions (+10 risk)")

    if download_mb >= 300:
        reasons.append(f"{download_mb:.2f} MB of data was downloaded (+10 risk)")

    is_flagged = risk >= 20 or firewall == "BLOCK" or ids != "NORMAL" or anomaly

    if reasons:
        signal_text = "; ".join(reasons)
    else:
        signal_text = "no elevated risk signal was recorded"

    if is_flagged:
        classification = (
            f"The risk engine classified this event as **{severity_name}** "
            f"with a score of **{risk}/100**."
        )
    else:
        classification = (
            f"This event was **recorded for monitoring**, but it was not "
            f"flagged as suspicious by the risk engine. The score is **{risk}/100** "
            f"and the severity is **{severity_name}**."
        )

    return f"""
## 🔵 Local Security Copilot

**Question:** {question}

### Security classification

{classification}

### Recorded decision

- **Zero Trust policy:** `{decision}`
- **Simulated access outcome:** `{access}`

### Why was it flagged?

{signal_text}.

### ML result

AI anomaly status: **{"ANOMALY DETECTED" if anomaly else "NORMAL"}**

An ML anomaly is one input to the risk engine; it does not independently
mean that an event is malicious.

### Analyst checklist

1. Review recent login history for the same user.
2. Verify failed authentication attempts.
3. Review transaction activity and timing.
4. Check download volume and related file activity.
5. Review firewall and IDS records.
6. Verify the device and location.
7. Check related events for the same user.
8. Confirm whether an MFA challenge was required.

This local fallback uses only the incident data stored in the application database.
"""


def ask_security_copilot(
    question,
    incident_data,
    gemini_key,
    groq_key,
):
    prompt = f"""
You are a cybersecurity analyst inside an educational
financial cybersecurity monitoring system.

Analyze ONLY this simulated incident:

{incident_data}

User question:

{question}

Explain:

1. Why the event was flagged.
2. Which recorded signals increased risk.
3. What the ML anomaly result means.
4. What the firewall and IDS contributed.
5. What the Zero Trust decision means.
6. What an analyst should investigate next.

Do not invent facts that are absent from the incident data.

Consistency rules:
- Treat the local risk_score, severity, firewall_action, ids_alert, and ai_anomaly as authoritative.
- If risk_score < 20 and firewall_action is ALLOW, ids_alert is NORMAL, and ai_anomaly is 0, explicitly say the event was recorded for monitoring and was NOT flagged as suspicious by the risk engine.
- Do not call a LOW-risk event suspicious unless the recorded signals support that statement.
- Explain the numeric risk using the documented scoring rules: Firewall BLOCK +30, IDS alert +20, ML anomaly +25, failed logins >=3 +15, transactions >=7 +10, download >=300 MB +10, capped at 100.
- Distinguish the Zero Trust policy decision (ACCESS GRANTED / MFA REQUIRED / DENY) from the simulated access outcome.
"""

    # =========================================================
    # LAYER 1 — GOOGLE GEMINI
    # =========================================================

    if gemini_key:

        try:
            st.info("🟢 Layer 1: Trying Google Gemini...")

            from google import genai

            client = genai.Client(
                api_key=gemini_key
            )

            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=prompt,
            )

            if response and response.text:
                return (
                    "### 🟢 Gemini Security Copilot\n\n"
                    + response.text
                )

        except Exception as exc:
            st.warning(
                "⚠️ Gemini unavailable. "
                "Switching to Groq..."
            )

    # =========================================================
    # LAYER 2 — GROQ
    # =========================================================

    if groq_key:

        try:
            st.info("🟡 Layer 2: Trying Groq...")

            from groq import Groq

            client = Groq(
                api_key=groq_key
            )

            response = client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity "
                            "security analyst."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                temperature=0.2,
            )

            answer = response.choices[0].message.content

            if answer:
                return (
                    "### 🟡 Groq Security Copilot\n\n"
                    + answer
                )

        except Exception as exc:
            st.warning(
                "⚠️ Groq unavailable. "
                "Switching to local analysis..."
            )

    # =========================================================
    # LAYER 3 — LOCAL FALLBACK
    # =========================================================

    st.info(
        "🔵 Layer 3: Running local security analysis..."
    )

    return local_security_analysis(
        question,
        incident_data,
    )


def admin_panel():
    st.header("🔐 Admin Panel")

    admin_username = os.getenv(
        "ADMIN_USERNAME",
        "admin",
    )

    admin_password = os.getenv(
        "ADMIN_PASSWORD",
        "admin123",
    )

    username = st.text_input(
        "Admin username"
    )

    password = st.text_input(
        "Admin password",
        type="password",
    )

    if username != admin_username or password != admin_password:
        st.info(
            "Enter valid admin credentials to continue."
        )
        return

    st.success("✅ Admin access granted.")
    st.session_state["admin_audited"] = True

    df = load_logs()

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Database Events",
        len(df),
    )

    col2.metric(
        "Critical Events",
        int(
            (df["severity"] == "CRITICAL").sum()
        ) if len(df) else 0,
    )

    col3.metric(
        "Users",
        df["user_id"].nunique()
        if len(df)
        else 0,
    )

    st.subheader("Database Information")

    st.code(
        os.path.abspath(DB_NAME)
    )

    if len(df):

        csv_data = df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            "⬇️ Export Security Logs CSV",
            data=csv_data,
            file_name="security_logs.csv",
            mime="text/csv",
        )

    conn = db_connection()

    audit_df = pd.read_sql_query(
        "SELECT * FROM admin_audit ORDER BY id DESC",
        conn,
    )

    conn.close()

    st.subheader(
        "Admin Audit Log"
    )

    st.dataframe(
        audit_df,
        use_container_width=True,
        hide_index=True,
    )

    st.subheader(
        "Demo Database Controls"
    )

    st.caption(
        "Rebuild creates fresh synthetic data and recalibrates the ML anomaly baseline. "
        "It does not touch any real financial system."
    )

    rebuild_count = st.number_input(
        "Fresh synthetic events",
        min_value=50,
        max_value=1000,
        value=100,
        step=50,
    )

    if st.button("♻️ Rebuild Demo Database"):
        rebuild_demo_database(int(rebuild_count))
        audit(
            "REBUILD_DATABASE",
            f"Rebuilt demo database with {int(rebuild_count)} synthetic events.",
        )
        st.success("Demo database rebuilt with a fresh ML baseline.")
        st.rerun()

    st.subheader(
        "Danger Zone"
    )

    confirm = st.checkbox(
        "I understand that deleting the security logs cannot be undone."
    )

    if st.button(
        "🗑️ Delete All Security Logs",
        disabled=not confirm,
    ):

        conn = db_connection()

        conn.execute(
            "DELETE FROM security_logs"
        )

        conn.commit()
        conn.close()

        audit(
            "DELETE_LOGS",
            "All security logs deleted by admin.",
        )

        st.success(
            "Security logs deleted."
        )

        st.rerun()


def dashboard():

    st.set_page_config(
        page_title="Financial Security Command Center",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # =========================================================
    # PROFESSIONAL SOC DASHBOARD STYLING
    # =========================================================
    st.markdown("""
    <style>
        /* ===== Figma-inspired LIGHT UI ===== */

        .stApp {
            background: #f7f7f9;
            color: #202124;
        }

        [data-testid="stHeader"] {
            background: rgba(255,255,255,.92);
            border-bottom: 1px solid #ececf1;
        }

        [data-testid="stSidebar"] {
            background: #ffffff;
            border-right: 1px solid #e8e8ee;
        }

        [data-testid="stSidebar"] > div:first-child {
            padding-top: 1.1rem;
        }

        .block-container {
            max-width: 1480px;
            padding-top: 1.4rem;
            padding-bottom: 2.5rem;
        }

        /* Main hero */
        .soc-hero {
            background: #ffffff;
            border: 1px solid #e9e9ef;
            border-radius: 18px;
            padding: 24px 28px;
            margin-bottom: 18px;
            box-shadow: 0 8px 26px rgba(30, 30, 60, .055);
        }

        .soc-title {
            color: #202124;
            font-size: 2rem;
            font-weight: 800;
            letter-spacing: -.7px;
            margin: 0;
        }

        .soc-subtitle {
            color: #777784;
            margin-top: 6px;
            font-size: .96rem;
        }

        .online-pill {
            display: inline-block;
            margin-top: 14px;
            padding: 5px 12px;
            border-radius: 999px;
            background: #f0fbf4;
            border: 1px solid #ccefd7;
            color: #238a4b;
            font-size: .78rem;
            font-weight: 700;
        }

        .section-title {
            color: #262631;
            font-size: 1.12rem;
            font-weight: 750;
            margin: 18px 0 10px 0;
        }

        /* Metric cards */
        div[data-testid="stMetric"] {
            background: #ffffff;
            border: 1px solid #e8e8ee;
            padding: 14px 16px;
            border-radius: 14px;
            box-shadow: 0 5px 18px rgba(30,30,60,.045);
        }

        div[data-testid="stMetricLabel"] {
            color: #777784;
        }

        div[data-testid="stMetricValue"] {
            color: #25252d;
            font-weight: 750;
        }

        /* Status cards */
        .status-card {
            background: #ffffff;
            border: 1px solid #e8e8ee;
            border-radius: 14px;
            padding: 14px 16px;
            min-height: 76px;
            box-shadow: 0 5px 18px rgba(30,30,60,.035);
        }

        .status-label {
            color: #888894;
            font-size: .76rem;
            text-transform: uppercase;
            letter-spacing: .5px;
        }

        .status-value {
            color: #2b2b34;
            font-size: 1.05rem;
            font-weight: 750;
            margin-top: 5px;
        }

        .status-good { color: #239653; }
        .status-warn { color: #b47700; }
        .status-danger { color: #d33a3a; }

        /* Copilot */
        .copilot-box {
            background: linear-gradient(135deg, #ffffff 0%, #fbf9ff 100%);
            border: 1px solid #e5defa;
            border-radius: 16px;
            padding: 19px;
            box-shadow: 0 7px 24px rgba(92, 63, 170, .055);
        }

        .small-muted {
            color: #888894;
            font-size: .82rem;
        }

        /* Architecture */
        .architecture-box {
            background: #ffffff;
            border: 1px solid #e8e8ee;
            border-radius: 14px;
            padding: 18px;
            line-height: 1.8;
            color: #3c3c46;
            box-shadow: 0 5px 18px rgba(30,30,60,.035);
        }

        /* Tables */
        [data-testid="stDataFrame"] {
            border: 1px solid #e8e8ee;
            border-radius: 12px;
            overflow: hidden;
        }

        /* Inputs */
        div[data-baseweb="select"] > div,
        div[data-baseweb="input"] > div,
        textarea {
            border-radius: 9px !important;
            border-color: #dedee7 !important;
            background: #ffffff !important;
        }

        /* Buttons */
        .stButton > button {
            border-radius: 9px;
            border: 1px solid #dedee7;
            background: #ffffff;
            color: #30303a;
            font-weight: 600;
            transition: .15s ease;
        }

        .stButton > button:hover {
            border-color: #b9a7ef;
            color: #6547c7;
            box-shadow: 0 4px 12px rgba(101,71,199,.09);
        }

        /* Primary button */
        .stButton > button[kind="primary"] {
            background: #6d4bd2;
            border-color: #6d4bd2;
            color: #ffffff;
        }

        .stButton > button[kind="primary"]:hover {
            background: #5d3fc0;
            border-color: #5d3fc0;
            color: #ffffff;
        }

        /* Tabs */
        button[data-baseweb="tab"] {
            color: #777784;
            font-weight: 600;
        }

        button[data-baseweb="tab"][aria-selected="true"] {
            color: #6245c7;
        }

        /* Sidebar */
        [data-testid="stSidebar"] .stMarkdown h2,
        [data-testid="stSidebar"] .stMarkdown h3 {
            color: #272731;
        }

        /* Dividers */
        hr {
            border-color: #ececf1 !important;
        }

        /* Alerts */
        [data-testid="stAlert"] {
            border-radius: 12px;
        }
    </style>
    """, unsafe_allow_html=True)


    # =========================================================
    # DATA INITIALIZATION
    # =========================================================

    ensure_initial_data()
    df = load_logs()

    # =========================================================
    # SIDEBAR
    # =========================================================

    with st.sidebar:
        st.markdown("## 🛡️ Security Command Center")
        st.caption("AI-powered financial security monitoring")

        st.divider()

        st.markdown("### ⚡ System Status")
        st.success("● Database Online")
        st.success("● Firewall Online")
        st.success("● IDS Online")
        st.success("● ML Engine Online")
        st.success("● Zero Trust Online")

        st.divider()

        st.markdown("### 🤖 AI Providers")

        gemini_api_key = st.text_input(
            "Gemini API Key",
            type="password",
            help="Used only for the current Streamlit session.",
        )

        groq_api_key = st.text_input(
            "Groq API Key",
            type="password",
            help="Used only for the current Streamlit session.",
        )

        if gemini_api_key:
            st.success("Gemini: Ready")
        else:
            st.info("Gemini: Not configured")

        if groq_api_key:
            st.success("Groq: Ready")
        else:
            st.info("Groq: Not configured")

        st.caption("Failover: Gemini → Groq → Local")

        st.divider()

        if st.button(
            "⚡ Generate Security Event",
            use_container_width=True,
        ):
            ai = train_behavior_model()

            if ai is None:
                seed_database(30)
                ai = train_behavior_model()

            result = process_event(generate_event(), ai)

            st.session_state["last_event"] = result
            st.success("New security event generated.")
            st.rerun()

        if st.button(
            "🔄 Refresh Dashboard",
            use_container_width=True,
        ):
            st.rerun()

        st.divider()
        st.caption("Educational cybersecurity simulation")
        st.caption("No real firewall or financial system is modified.")

    # =========================================================
    # HERO
    # =========================================================

    critical_count = int((df["severity"] == "CRITICAL").sum())
    high_count = int((df["severity"] == "HIGH").sum())
    medium_count = int((df["severity"] == "MEDIUM").sum())
    anomaly_count = int(df["ai_anomaly"].sum())
    avg_risk = round(float(df["risk_score"].mean()), 1) if len(df) else 0
    active_count = int(
        (
            (df["severity"].isin(["CRITICAL", "HIGH"]))
            | (df["decision"] == "DENY")
        ).sum()
    )

    st.markdown("""
    <div class="soc-hero">
        <div class="soc-title">🛡️ Financial Security Command Center</div>
        <div class="soc-subtitle">
            AI-powered threat detection • Firewall • IDS • Behavioral Analytics •
            Zero Trust • Multi-LLM Security Copilot
        </div>
        <div class="online-pill">● SYSTEM OPERATIONAL</div>
    </div>
    """, unsafe_allow_html=True)

    # =========================================================
    # TOP METRICS
    # =========================================================

    m1, m2, m3, m4, m5, m6 = st.columns(6)

    m1.metric("Total Events", f"{len(df):,}")
    m2.metric("Critical", critical_count)
    m3.metric("High", high_count)
    m4.metric("AI Anomalies", anomaly_count)
    m5.metric("Avg Risk", f"{avg_risk}/100")
    m6.metric("Active Incidents", active_count)

    st.markdown("<br>", unsafe_allow_html=True)

    # =========================================================
    # NAVIGATION TABS
    # =========================================================

    overview_tab, incidents_tab, users_tab, copilot_tab, admin_tab = st.tabs(
        [
            "🏠 Overview",
            "🚨 Incidents",
            "👤 User Behavior",
            "🤖 AI Copilot",
            "🔐 Admin",
        ]
    )

    # =========================================================
    # OVERVIEW
    # =========================================================

    with overview_tab:

        st.markdown('<div class="section-title">📊 Security Overview</div>',
                    unsafe_allow_html=True)

        c1, c2, c3 = st.columns([1.05, 1.05, .9])

        with c1:
            counts = (
                df["severity"]
                .value_counts()
                .reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"], fill_value=0)
                .reset_index()
            )
            counts.columns = ["Severity", "Count"]

            fig = px.bar(
                counts,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map={
                    "CRITICAL": "#ef4444",
                    "HIGH": "#f97316",
                    "MEDIUM": "#facc15",
                    "LOW": "#22c55e",
                },
                title="Threat Severity",
                template="plotly_white",
            )
            fig.update_layout(
                paper_bgcolor="#ffffff",
                plot_bgcolor="#ffffff",
                showlegend=False,
                margin=dict(l=10, r=10, t=50, b=10),
            )
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            fig = px.histogram(
                df,
                x="risk_score",
                nbins=10,
                title="Risk Score Distribution",
                color_discrete_sequence=["#8b5cf6"],
                template="plotly_white",
            )
            fig.update_layout(
                paper_bgcolor="#ffffff",
                plot_bgcolor="#ffffff",
                margin=dict(l=10, r=10, t=50, b=10),
            )
            st.plotly_chart(fig, use_container_width=True)

        with c3:
            decision_counts = (
                df["decision"]
                .value_counts()
                .reset_index()
            )
            decision_counts.columns = ["Decision", "Count"]

            fig = px.pie(
                decision_counts,
                names="Decision",
                values="Count",
                hole=.58,
                title="Zero Trust Decisions",
                color="Decision",
                color_discrete_map={
                    "ACCESS GRANTED": "#22c55e",
                    "MFA REQUIRED": "#facc15",
                    "DENY": "#ef4444",
                },
                template="plotly_white",
            )
            fig.update_layout(
                paper_bgcolor="#ffffff",
                margin=dict(l=10, r=10, t=50, b=10),
            )
            st.plotly_chart(fig, use_container_width=True)

        st.markdown('<div class="section-title">🧩 Security Engine Status</div>',
                    unsafe_allow_html=True)

        s1, s2, s3, s4, s5 = st.columns(5)

        status_items = [
            (s1, "Firewall", "ACTIVE", "status-good"),
            (s2, "IDS", "MONITORING", "status-good"),
            (s3, "Behavior AI", "ACTIVE", "status-good"),
            (s4, "Zero Trust", "ENFORCED", "status-good"),
            (s5, "Copilot", "FAILOVER READY", "status-good"),
        ]

        for col, label, value, css in status_items:
            with col:
                st.markdown(
                    f"""
                    <div class="status-card">
                        <div class="status-label">{label}</div>
                        <div class="status-value {css}">● {value}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown('<div class="section-title">📡 Recent Activity</div>',
                    unsafe_allow_html=True)

        recent = df.head(10).copy()

        if len(recent):
            display_cols = [
                "timestamp", "user_id", "event_type", "location",
                "firewall_action", "ids_alert", "ai_anomaly",
                "risk_score", "severity", "decision",
            ]
            st.dataframe(
                recent[display_cols],
                use_container_width=True,
                hide_index=True,
            )

    # =========================================================
    # INCIDENTS
    # =========================================================

    with incidents_tab:

        st.markdown('<div class="section-title">🚨 Incident Command</div>',
                    unsafe_allow_html=True)

        i1, i2, i3, i4 = st.columns(4)
        i1.metric("Critical", critical_count)
        i2.metric("High", high_count)
        i3.metric("Medium", medium_count)
        i4.metric("Denied", int((df["decision"] == "DENY").sum()))

        st.markdown("#### 🔥 Critical & High Incidents")

        incidents = df[
            df["severity"].isin(["CRITICAL", "HIGH"])
        ].copy()

        if len(incidents):
            incident_cols = [
                "id", "timestamp", "user_id", "role", "device",
                "location", "event_type", "firewall_action",
                "ids_alert", "ai_anomaly", "risk_score",
                "severity", "decision", "access_outcome",
                "incident_status",
            ]
            st.dataframe(
                incidents[incident_cols],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success("No critical or high-severity incidents.")

        st.markdown("#### 🤖 AI-Detected Anomalies")

        anomalies = df[df["ai_anomaly"] == 1].copy()

        if len(anomalies):
            anomaly_cols = [
                "id", "timestamp", "user_id", "role", "location",
                "event_type", "transactions", "failed_logins",
                "download_mb", "risk_score", "severity",
                "decision", "access_outcome",
            ]
            st.dataframe(
                anomalies[anomaly_cols],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No AI anomalies detected.")

    # =========================================================
    # USER BEHAVIOR
    # =========================================================

    with users_tab:

        st.markdown('<div class="section-title">👤 User Behavior Analytics</div>',
                    unsafe_allow_html=True)

        user_risk = (
            df.groupby("user_id")
            .agg(
                avg_risk=("risk_score", "mean"),
                events=("id", "count"),
                anomalies=("ai_anomaly", "sum"),
                denied=("decision", lambda x: (x == "DENY").sum()),
            )
            .reset_index()
            .sort_values("avg_risk", ascending=False)
        )

        left, right = st.columns([1.3, .9])

        with left:
            fig = px.bar(
                user_risk.head(12),
                x="user_id",
                y="avg_risk",
                color="avg_risk",
                color_continuous_scale="Turbo",
                title="Highest Average User Risk",
                template="plotly_white",
            )
            fig.update_layout(
                paper_bgcolor="#ffffff",
                plot_bgcolor="#ffffff",
                coloraxis_showscale=False,
                margin=dict(l=10, r=10, t=50, b=10),
            )
            st.plotly_chart(fig, use_container_width=True)

        with right:
            selected_user = st.selectbox(
                "Investigate user",
                user_risk["user_id"].tolist(),
            )

            user_events = df[
                df["user_id"] == selected_user
            ].copy()

            if len(user_events):
                st.metric(
                    "User Average Risk",
                    f"{user_events['risk_score'].mean():.1f}/100",
                )
                st.metric(
                    "AI Anomalies",
                    int(user_events["ai_anomaly"].sum()),
                )
                st.metric(
                    "Denied Events",
                    int((user_events["decision"] == "DENY").sum()),
                )

        st.markdown("#### User Risk Table")

        user_table = user_risk.copy()
        user_table["avg_risk"] = user_table["avg_risk"].round(1)
        user_table.columns = [
            "User", "Average Risk", "Events",
            "AI Anomalies", "Denied",
        ]

        st.dataframe(
            user_table,
            use_container_width=True,
            hide_index=True,
        )

    # =========================================================
    # AI COPILOT
    # =========================================================

    with copilot_tab:

        st.markdown("""
        <div class="copilot-box">
            <h2 style="margin:0;">🤖 AI Security Copilot</h2>
            <div class="small-muted">
                Investigation and explanation layer — it does not replace
                the local Risk Engine or Zero Trust policy.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("")

        if len(df):

            selected_id = st.selectbox(
                "Select incident to investigate",
                df["id"].tolist(),
                key="copilot_incident",
            )

            selected = df[
                df["id"] == selected_id
            ].iloc[0]

            incident_data = selected.to_dict()

            selected_risk = int(selected["risk_score"])

            selected_flagged = (
                selected_risk >= 20
                or selected["firewall_action"] == "BLOCK"
                or selected["ids_alert"] != "NORMAL"
                or int(selected["ai_anomaly"]) == 1
            )

            if selected_flagged:
                st.warning(
                    f"🚨 {selected['severity']} — "
                    f"Risk {selected_risk}/100 — elevated signals recorded."
                )
            else:
                st.success(
                    f"🟢 LOW RISK — {selected_risk}/100 — "
                    "monitoring event; no elevated signal recorded."
                )

            a, b, c, d = st.columns(4)

            a.metric("Risk Score", f"{selected_risk}/100")
            b.metric("Severity", str(selected["severity"]))
            c.metric("AI Anomaly", "YES" if int(selected["ai_anomaly"]) else "NO")
            d.metric("Zero Trust", str(selected["decision"]))

            with st.expander("📋 View Full Incident Data"):
                st.json(incident_data)

            st.markdown("#### Ask the Copilot")

            if "copilot_question" not in st.session_state:
                st.session_state["copilot_question"] = (
                    "Why was this user flagged as suspicious?"
                )

            q1, q2, q3 = st.columns(3)

            with q1:
                if st.button(
                    "🔎 Why was this flagged?",
                    use_container_width=True,
                ):
                    st.session_state["copilot_question"] = (
                        "Why was this activity flagged?"
                    )

            with q2:
                if st.button(
                    "📊 Explain the risk score",
                    use_container_width=True,
                ):
                    st.session_state["copilot_question"] = (
                        "Explain the risk score and its contributing signals."
                    )

            with q3:
                if st.button(
                    "🧭 What should an analyst check?",
                    use_container_width=True,
                ):
                    st.session_state["copilot_question"] = (
                        "What should an analyst investigate next?"
                    )

            question = st.text_input(
                "Investigation question",
                key="copilot_question",
            )

            if st.button(
                "🔍 Analyze Incident",
                type="primary",
                use_container_width=True,
            ):

                if not gemini_api_key and not groq_api_key:
                    st.info(
                        "No external LLM key configured. "
                        "Local Security Copilot will be used."
                    )

                with st.spinner("Security Copilot is analyzing..."):
                    result = ask_security_copilot(
                        question,
                        incident_data,
                        gemini_api_key,
                        groq_api_key,
                    )

                st.markdown("### 🧠 Copilot Analysis")
                st.markdown(result)

        else:
            st.info("No security events are available for investigation.")

    # =========================================================
    # ADMIN
    # =========================================================

    with admin_tab:
        admin_panel()

    # =========================================================
    # ARCHITECTURE
    # =========================================================

    st.divider()

    with st.expander("🏗️ View System Architecture", expanded=False):

        st.markdown("""
        <div class="architecture-box">

        <b>Security Event</b>
        ↓<br>
        SQLite Log Collector
        ↓<br>
        <b>Firewall</b> + <b>IDS</b>
        ↓<br>
        <b>Isolation Forest Behavior AI</b>
        ↓<br>
        <b>Risk Engine</b>
        ↓<br>
        <b>Zero Trust Policy</b>
        ↓<br>
        ALLOW / MFA / DENY
        ↓<br>
        <b>Dashboard + Security Copilot</b>

        <hr>

        <b>LLM Failover:</b>
        Gemini → Groq → Local Deterministic Analysis

        <br><br>
        <span class="small-muted">
        The LLM layer explains incidents. The local security pipeline
        remains authoritative for risk scoring and access policy.
        </span>

        </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    create_database()
    dashboard()
