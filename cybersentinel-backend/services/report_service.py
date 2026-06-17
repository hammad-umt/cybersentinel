"""
services/report_service.py

Text/table PDF summary reports for SOC administrators.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from core.severity import translate_firewall_severity
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import FirewallAlert, ResponseAction
from services.dashboard_service import DashboardService
from services.threat_scoring_service import ThreatScoringService


class ReportService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def summary_pdf(self) -> bytes:
        dashboard = await DashboardService(self.db).summary()
        top_threats = await ThreatScoringService(self.db).top(limit=10)

        recent_alerts = (await self.db.execute(
            select(FirewallAlert)
            .order_by(FirewallAlert.timestamp.desc())
            .limit(20)
        )).scalars().all()

        response_actions = (await self.db.execute(
            select(ResponseAction)
            .order_by(ResponseAction.timestamp.desc())
            .limit(20)
        )).scalars().all()

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
        styles = getSampleStyleSheet()
        story = []

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        story.append(Paragraph("CyberSentinel SOC Summary Report", styles["Title"]))
        story.append(Paragraph(f"Generated: {generated_at}", styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Dashboard Counters", styles["Heading2"]))
        counter_rows = [
            ["Metric", "Value"],
            ["Packet events", str(dashboard.packet_events)],
            ["Firewall alerts", str(dashboard.firewall_alerts)],
            ["Unacknowledged alerts", str(dashboard.unacknowledged_alerts)],
            ["Critical alerts", str(dashboard.critical_alerts)],
            ["Response actions", str(dashboard.response_actions)],
            ["Avg packet threat score", f"{dashboard.avg_packet_threat_score:.2f}"],
            ["Max firewall threat score", f"{dashboard.max_firewall_threat_score:.2f}"],
        ]
        story.append(_styled_table(counter_rows))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Top Scored IPs", styles["Heading2"]))
        top_rows = [["IP", "Final Score", "Severity", "Packet", "Anomaly", "Intel"]]
        for item in top_threats.results:
            top_rows.append([
                item.ip,
                f"{item.final_score:.1f}",
                item.severity,
                f"{item.packet_score:.1f}",
                f"{item.anomaly_score:.1f}",
                f"{item.intel_score:.1f}",
            ])
        if len(top_rows) == 1:
            top_rows.append(["—", "—", "—", "—", "—", "—"])
        story.append(_styled_table(top_rows))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Recent Firewall Alerts", styles["Heading2"]))
        alert_rows = [["Timestamp", "Source IP", "Severity", "Score", "Ack"]]
        for alert in recent_alerts:
            alert_rows.append([
                alert.timestamp,
                alert.src_ip,
                translate_firewall_severity(alert.severity),
                f"{alert.threat_score:.1f}",
                "Yes" if alert.acknowledged else "No",
            ])
        if len(alert_rows) == 1:
            alert_rows.append(["—", "—", "—", "—", "—"])
        story.append(_styled_table(alert_rows))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Response Action Audit Log", styles["Heading2"]))
        action_rows = [["Timestamp", "Target IP", "Action", "Status", "Executed"]]
        for action in response_actions:
            action_rows.append([
                action.timestamp,
                action.target_ip,
                action.action,
                action.status,
                "Yes" if action.executed else "No",
            ])
        if len(action_rows) == 1:
            action_rows.append(["—", "—", "—", "—", "—"])
        story.append(_styled_table(action_rows))

        doc.build(story)
        return buffer.getvalue()


def _styled_table(rows: list[list[str]]) -> Table:
    table = Table(rows, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table
