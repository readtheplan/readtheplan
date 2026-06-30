#!/usr/bin/env python3
"""
Generates a beautiful private HTML dashboard for the self-improving Kernel Gate from SQLite.
No external dependencies. Everything stays in ~/.readtheplan/
"""

import json
import sqlite3
import sys
from pathlib import Path


def generate_report():
    db_file = Path.home() / ".readtheplan" / "evolution.db"
    if not db_file.exists():
        print("No evolution data yet. Run some gates with --mode self-improving first.")
        return

    conn = sqlite3.connect(db_file)
    try:
        runs = conn.execute(
            "SELECT timestamp, decision, compliance_score, plan_summary FROM runs ORDER BY id ASC"
        ).fetchall()
        patterns = conn.execute(
            "SELECT resource_type, risk, incident_count, rule_status, rule_score FROM patterns ORDER BY incident_count DESC"
        ).fetchall()
    except Exception as e:
        print(f"Error querying database: {e}", file=sys.stderr)
        return
    finally:
        conn.close()

    if not runs:
        print("No runs recorded in database yet.")
        return
    
    avg_score = sum(r[2] for r in runs) / len(runs)
    latest_run = runs[-1]
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>readtheplan Evolution Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: system-ui, sans-serif; background: #0f1117; color: #e0e0e0; margin: 0; padding: 20px; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .card {{ background: #1a1f2e; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #252b3d; }}
        .positive {{ color: #00ff9f; }}
        .negative {{ color: #ff6b6b; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🧠 readtheplan Evolution Dashboard</h1>
        <p>Self-improving Kernel Gate — learning from every run • Private & local only</p>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Compliance Score Trend</h2>
            <canvas id="scoreChart" height="100"></canvas>
        </div>
        <div class="card">
            <h2>Summary</h2>
            <p><strong>Runs Analyzed:</strong> {len(runs)}</p>
            <p><strong>Average Compliance Score:</strong> {avg_score:.1f}</p>
            <p><strong>Latest Decision:</strong> {latest_run[1].upper()}</p>
            <p><strong>Latest Score:</strong> {latest_run[2]}</p>
        </div>
    </div>

    <div class="card">
        <h2>Suggested Rules (Latest 5)</h2>
        <table>
            <tr>
                <th>Resource Type</th>
                <th>Suggested Risk</th>
                <th>Incidents</th>
                <th>Status</th>
                <th>Score</th>
            </tr>
"""

    for pat in patterns[:5]:
        status_badge = {
            "auto-merge": "🟢 auto-merge",
            "pr-ready": "🟡 pr-ready",
            "disabled": "🔴 disabled",
            "pending": "⚪ pending",
        }.get(pat[3], "⚪ pending")
        html += f"""
            <tr>
                <td><strong>{pat[0]}</strong></td>
                <td>{pat[1]}</td>
                <td>{pat[2]}</td>
                <td>{status_badge}</td>
                <td>{pat[4] or '-'}</td>
            </tr>
"""

    html += """
        </table>
    </div>

    <div class="card">
        <h2>Evolution Log (Last 10 runs)</h2>
"""

    for run in reversed(runs[-10:]):
        html += f"""
        <p><strong>{run[0][:16]}</strong> — Score: <span class="positive">{run[2]}</span> — Decision: <strong>{run[1].upper()}</strong></p>
"""

    html += """
    </div>

    <script>
        const scores = """ + json.dumps([r[2] for r in runs]) + """;
        const labels = """ + json.dumps([r[0][:10] for r in runs]) + """;

        new Chart(document.getElementById("scoreChart"), {
            type: "line",
            data: {
                labels: labels,
                datasets: [{
                    label: "Compliance Score",
                    data: scores,
                    borderColor: "#00ff9f",
                    tension: 0.3,
                    fill: false
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { beginAtZero: true, max: 100 }
                }
            }
        });
    </script>
</body>
</html>
"""

    report_path = Path.home() / ".readtheplan" / "evolution-report.html"
    report_path.write_text(html, encoding="utf-8")
    print(f"Evolution dashboard generated at: {report_path}")
    print("Open it in your browser to see the live self-improving system.")

if __name__ == "__main__":
    generate_report()
