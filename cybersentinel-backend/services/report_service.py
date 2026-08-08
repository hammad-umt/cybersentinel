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
    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id

    async def summary_pdf(self) -> bytes:
        dashboard = await DashboardService(self.db, self.user_id).summary()
        top_threats = await ThreatScoringService(self.db, self.user_id).top(limit=10)

        recent_alerts = (await self.db.execute(
            select(FirewallAlert)
            .where(FirewallAlert.user_id == self.user_id)
            .order_by(FirewallAlert.timestamp.desc())
            .limit(20)
        )).scalars().all()

        response_actions = (await self.db.execute(
            select(ResponseAction)
            .where(ResponseAction.user_id == self.user_id)
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

    async def incident_pdf(self, incident_id: str) -> bytes | None:
        from services.incident_service import IncidentService

        incident = await IncidentService(self.db, self.user_id).get(incident_id)
        if incident is None:
            return None

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("CyberSentinel Incident Forensic Report", styles["Title"]))
        story.append(Paragraph(f"Incident ID: {incident.id}", styles["Normal"]))
        story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        rows = [
            ["Field", "Value"],
            ["Attack Type", incident.attack_type],
            ["Severity", incident.severity],
            ["Status", incident.status],
            ["Source IP", incident.source_ip or "—"],
            ["Destination IP", incident.destination_ip or "—"],
            ["Threat Score", f"{incident.threat_score:.1f}"],
            ["MITRE ID", incident.mitre_id or "—"],
            ["MITRE Technique", incident.mitre_technique or "—"],
            ["MITRE Tactic", incident.mitre_tactic or "—"],
            ["Created", incident.timestamp],
        ]
        story.append(_styled_table(rows))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Recommended Response", styles["Heading2"]))
        recommendations = _incident_recommendations(incident.severity, incident.attack_type)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Evidence", styles["Heading2"]))
        evidence = incident.evidence or {}
        for key, value in list(evidence.items())[:20]:
            story.append(Paragraph(f"{key}: {value}", styles["Normal"]))

        doc.build(story)
        return buffer.getvalue()

    async def incident_csv(self, incident_id: str) -> str | None:
        from services.incident_service import IncidentService
        import csv

        incident = await IncidentService(self.db, self.user_id).get(incident_id)
        if incident is None:
            return None
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["field", "value"])
        for field, value in incident.model_dump().items():
            if field != "evidence":
                writer.writerow([field, value])
        for key, value in (incident.evidence or {}).items():
            writer.writerow([f"evidence.{key}", value])
        return output.getvalue()


def _incident_recommendations(severity: str, attack_type: str) -> list[str]:
    recs = []
    if severity in {"Critical", "High"}:
        recs.append("Block or quarantine the source IP via Threat Response Center.")
        recs.append("Enrich IP reputation and review firewall alerts for the same host.")
    if attack_type in {"DDoS", "DoS", "SYN Flood"}:
        recs.append("Apply rate limiting and verify upstream DDoS mitigation.")
    if attack_type in {"Brute Force", "PortScan", "Port Scan"}:
        recs.append("Review authentication logs and restrict exposed services.")
    if not recs:
        recs.append("Continue monitoring and document findings in the incident notes.")
    return recs


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
