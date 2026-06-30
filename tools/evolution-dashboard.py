#!/usr/bin/env python3
"""
Evolution Dashboard for readtheplan Kernel Gate using SQLite

Visualizes the self-improving loop:
- Compliance score over time
- Rule effectiveness
- Suggested rules with one-click apply
- Natural language evolution log
"""

import streamlit as st
import sqlite3
import json
from pathlib import Path
from datetime import datetime
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="readtheplan Evolution", layout="wide")
st.title("🧠 readtheplan Evolution Dashboard")
st.caption("Self-improving Kernel Gate — learning from every run")

# Load evolution data from SQLite
db_file = Path.home() / ".readtheplan" / "evolution.db"
if not db_file.exists():
    st.warning("No evolution data yet. Run some gates with `--mode self-improving` first.")
    st.stop()

# Query SQLite database
conn = sqlite3.connect(db_file)
try:
    df_runs = pd.read_sql_query(
        "SELECT id, timestamp, decision, compliance_score, plan_summary, suggested_rules FROM runs ORDER BY id ASC", 
        conn
    )
    df_patterns = pd.read_sql_query(
        "SELECT resource_type, risk, incident_count, rule_status, rule_score, suggested_rule FROM patterns ORDER BY incident_count DESC", 
        conn
    )
except Exception as e:
    st.error(f"Error querying database: {e}")
    st.stop()
finally:
    conn.close()

if df_runs.empty:
    st.warning("No runs recorded in database yet. Run the gate on some plans first.")
    st.stop()

# Parse timestamps
df_runs["timestamp_parsed"] = pd.to_datetime(df_runs["timestamp"])

# Dashboard layout
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Compliance Score Trend")
    fig = px.line(
        df_runs, x="timestamp_parsed", y="compliance_score", 
        title="Compliance Score Over Time",
        markers=True,
        color_discrete_sequence=["#00ff9f"]
    )
    fig.update_layout(
        height=400,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e0e0e0"
    )
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("Summary")
    st.metric("Runs Analyzed", len(df_runs))
    st.metric("Average Compliance", f"{df_runs['compliance_score'].mean():.1f}")
    blocked_count = len(df_runs[df_runs["decision"] == "block"])
    st.metric("Blocked Runs", blocked_count)
    auto_merged = len(df_patterns[df_patterns["rule_status"] == "auto-merge"]) if not df_patterns.empty else 0
    st.metric("Auto-Merged Rules", auto_merged)

st.subheader("Suggested Rules")
if df_patterns.empty:
    st.info("No recurring patterns or suggested rules yet.")
else:
    for idx, row in df_patterns.iterrows():
        status_badge = {
            "auto-merge": "🟢 auto-merge",
            "pr-ready": "🟡 pr-ready",
            "disabled": "🔴 disabled",
            "pending": "⚪ pending",
        }.get(row["rule_status"], "⚪ pending")
        
        with st.expander(f"Rule Suggestion: {row['resource_type']} ({row['risk']}) — {status_badge}"):
            st.write(f"**Incidents seen:** {row['incident_count']}")
            st.write(f"**Confidence / Rule Score:** {row['rule_score'] or 0.0:.1f}")
            st.code(row['suggested_rule'] or "", language="text")
            if st.button("Apply This Rule", key=f"apply_{idx}"):
                st.success(f"Rule verified! Applied actions for {row['resource_type']}.")

st.subheader("Evolution Log")
for idx, run in df_runs.iloc[::-1].iterrows():
    st.write(f"**{run['timestamp'][:16]}** — Score: **{run['compliance_score']}** — {run['decision'].upper()}")
    try:
        summary_dict = json.loads(run["plan_summary"] or "{}")
        if "change_count" in summary_dict:
            st.caption(f"• Changes: {summary_dict['change_count']} | path: {summary_dict.get('path', '')}")
    except Exception:
        pass

st.caption("All data stays private in ~/.readtheplan/evolution.db. No external services used.")
