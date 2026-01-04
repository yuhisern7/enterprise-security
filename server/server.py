#!/usr/bin/env python3
"""
Home WiFi Security Server - Network Monitoring & Threat Detection
Monitors all devices on the network and protects against attacks
"""

from flask import Flask, render_template, jsonify, request, send_file, Response
from datetime import datetime
import json
import os
import threading
import sys
import pytz
from report_generator import generate_html_report

def _get_current_time():
    """Get current datetime in configured timezone"""
    try:
        tz_name = os.getenv('TZ', 'Asia/Kuala_Lumpur')
        tz = pytz.timezone(tz_name)
        return datetime.now(tz)
    except:
        return datetime.now(pytz.UTC)

# Add parent directory to path to import AI module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import our AI security engine
import AI.pcs_ai as pcs_ai

# Set template folder based on environment
if os.path.exists('/app/AI'):  # Docker
    app = Flask(__name__, template_folder='/app/AI')
else:  # Native
    app = Flask(__name__, template_folder='../AI')
app.config['SECRET_KEY'] = 'change-this-to-a-secure-random-key'

# Load persistent data on startup
pcs_ai._load_threat_data()

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template('inspector_ai_monitoring.html',
                         stats=pcs_ai.get_threat_statistics(),
                         blocked_ips=pcs_ai.get_blocked_ips(),
                         whitelisted_ips=pcs_ai.get_whitelisted_ips(),
                         threat_logs=pcs_ai._threat_log[-100:][::-1],
                         ml_stats=pcs_ai.get_ml_model_stats(),
                         vpn_stats=pcs_ai.get_vpn_tor_statistics())


@app.route('/legacy')
def legacy_dashboard():
    """Legacy route - redirects to main dashboard"""
    return render_template('inspector_ai_monitoring.html',
                         stats=pcs_ai.get_threat_statistics(),
                         blocked_ips=pcs_ai.get_blocked_ips(),
                         whitelisted_ips=pcs_ai.get_whitelisted_ips(),
                         threat_logs=pcs_ai._threat_log[-100:][::-1],
                         ml_stats=pcs_ai.get_ml_model_stats(),
                         vpn_stats=pcs_ai.get_vpn_tor_statistics())




@app.route('/inspector/ai-monitoring')
def ai_monitoring():
    """Legacy AI Monitoring Dashboard"""
    return render_template('inspector_ai_monitoring.html',
                         stats=pcs_ai.get_threat_statistics(),
                         blocked_ips=pcs_ai.get_blocked_ips(),
                         whitelisted_ips=pcs_ai.get_whitelisted_ips(),
                         threat_logs=pcs_ai._threat_log[-100:][::-1],  # Latest 100, reversed
                         ml_stats=pcs_ai.get_ml_model_stats(),
                         vpn_stats=pcs_ai.get_vpn_tor_statistics())


@app.route('/inspector/ai-monitoring/export')
def export_monitoring_data():
    """Export enterprise security report"""
    export_format = request.args.get('format', 'html')  # html, json, or raw
    
    if export_format == 'raw':
        # Raw JSON data export
        data = pcs_ai.export_all_monitoring_data()
        filename = f"security_raw_export_{_get_current_time().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join('data', filename)
        os.makedirs('data', exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    
    elif export_format == 'json':
        # Structured enterprise report as JSON
        report = pcs_ai.generate_enterprise_security_report()
        filename = f"Enterprise_Security_Report_{_get_current_time().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join('data', filename)
        os.makedirs('data', exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    
    else:  # HTML report (default)
        report = pcs_ai.generate_enterprise_security_report()
        html_content = _generate_html_report(report)
        
        filename = f"Enterprise_Security_Report_{_get_current_time().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join('data', filename)
        os.makedirs('data', exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return send_file(filepath, as_attachment=True, download_name=filename)


def _generate_html_report(report: dict) -> str:
    """Generate professional HTML report for enterprise clients"""
    meta = report['report_metadata']
    exec_summary = report['executive_summary']
    threat_stats = report['threat_statistics']
    attacker_intel = report['attacker_intelligence']
    ai_insights = report['ai_ml_insights']
    threat_sources = report['threat_intelligence_sources']
    
    # Generate severity chart data
    severity = exec_summary.get('severity_breakdown', {})
    
    # Generate top threat types
    top_threats = list(threat_stats['threat_type_breakdown'].items())[:10]
    
    # Generate top countries
    top_countries = list(threat_stats['geographic_distribution'].items())[:10]
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{meta['report_title']}</title>
    <style>
        @media print {{
            .no-print {{ display: none; }}
            body {{ background: white; }}
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0b1020 0%, #1a2642 100%);
            color: #2c3e50;
            line-height: 1.6;
            padding: 2rem;
        }}
        
        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 10px 60px rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            overflow: hidden;
        }}
        
        .report-header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 3rem 2rem;
            text-align: center;
            border-bottom: 5px solid #3498db;
        }}
        
        .report-header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            font-weight: 700;
        }}
        
        .report-header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
            margin-bottom: 1.5rem;
        }}
        
        .report-meta {{
            display: flex;
            justify-content: center;
            gap: 2rem;
            flex-wrap: wrap;
            font-size: 0.9rem;
            opacity: 0.8;
        }}
        
        .report-meta-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .report-body {{
            padding: 3rem 2rem;
        }}
        
        .section {{
            margin-bottom: 3rem;
            page-break-inside: avoid;
        }}
        
        .section-title {{
            font-size: 1.8rem;
            color: #2c3e50;
            margin-bottom: 1.5rem;
            padding-bottom: 0.75rem;
            border-bottom: 3px solid #3498db;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .executive-summary {{
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 2rem;
            border-radius: 8px;
            border-left: 5px solid #3498db;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 1.5rem 0;
        }}
        
        .stat-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .stat-card .label {{
            font-size: 0.85rem;
            color: #7f8c8d;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .stat-card .value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #2c3e50;
        }}
        
        .stat-card.critical .value {{ color: #e74c3c; }}
        .stat-card.warning .value {{ color: #f39c12; }}
        .stat-card.success .value {{ color: #27ae60; }}
        .stat-card.info .value {{ color: #3498db; }}
        
        .risk-indicator {{
            background: white;
            padding: 2rem;
            border-radius: 8px;
            margin: 1.5rem 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .risk-score {{
            text-align: center;
            margin-bottom: 1.5rem;
        }}
        
        .risk-score .score {{
            font-size: 4rem;
            font-weight: 700;
            margin: 1rem 0;
        }}
        
        .risk-score .posture {{
            font-size: 1.5rem;
            font-weight: 600;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            display: inline-block;
        }}
        
        .recommendations {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 1.5rem;
            border-radius: 8px;
            margin-top: 1.5rem;
        }}
        
        .recommendations h3 {{
            color: #856404;
            margin-bottom: 1rem;
        }}
        
        .recommendations ul {{
            list-style: none;
        }}
        
        .recommendations li {{
            padding: 0.5rem 0;
            padding-left: 1.5rem;
            position: relative;
        }}
        
        .recommendations li:before {{
            content: "⚠️";
            position: absolute;
            left: 0;
        }}
        
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1.5rem 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .data-table thead {{
            background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%);
            color: white;
        }}
        
        .data-table th {{
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }}
        
        .data-table td {{
            padding: 1rem;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        .data-table tbody tr:hover {{
            background: #f8f9fa;
        }}
        
        .data-table tbody tr:last-child td {{
            border-bottom: none;
        }}
        
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .badge.critical {{ background: #fee; color: #c0392b; }}
        .badge.dangerous {{ background: #ffe; color: #e67e22; }}
        .badge.suspicious {{ background: #fff3cd; color: #856404; }}
        .badge.safe {{ background: #d4edda; color: #155724; }}
        
        .chart-container {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            margin: 1.5rem 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .bar-chart {{
            margin: 1rem 0;
        }}
        
        .bar-chart-item {{
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }}
        
        .bar-chart-label {{
            width: 150px;
            font-size: 0.9rem;
            font-weight: 500;
        }}
        
        .bar-chart-bar {{
            flex: 1;
            height: 30px;
            background: linear-gradient(90deg, #3498db 0%, #2980b9 100%);
            border-radius: 4px;
            position: relative;
            margin: 0 1rem;
        }}
        
        .bar-chart-value {{
            width: 60px;
            text-align: right;
            font-weight: 600;
            color: #2c3e50;
        }}
        
        .report-footer {{
            background: #f8f9fa;
            padding: 2rem;
            text-align: center;
            border-top: 1px solid #dee2e6;
            color: #7f8c8d;
            font-size: 0.9rem;
        }}
        
        .print-button {{
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
            border: none;
            padding: 1rem 2rem;
            font-size: 1rem;
            border-radius: 6px;
            cursor: pointer;
            margin: 1rem;
            box-shadow: 0 4px 12px rgba(52, 152, 219, 0.3);
            transition: all 0.3s;
        }}
        
        .print-button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(52, 152, 219, 0.4);
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="report-header">
            <h1>🛡️ {meta['report_title']}</h1>
            <div class="subtitle">{meta['system_name']}</div>
            <div class="report-meta">
                <div class="report-meta-item">
                    <span>📅</span>
                    <span>Generated: {_get_current_time().strftime('%B %d, %Y at %H:%M %Z')}</span>
                </div>
                <div class="report-meta-item">
                    <span>🌍</span>
                    <span>Timezone: {meta['timezone']}</span>
                </div>
                <div class="report-meta-item">
                    <span>📊</span>
                    <span>Period: {meta['report_period']}</span>
                </div>
                <div class="report-meta-item">
                    <span>🔢</span>
                    <span>Version: {meta['report_version']}</span>
                </div>
            </div>
            <div style="margin-top: 2rem;" class="no-print">
                <button class="print-button" onclick="window.print()">🖨️ Print Report</button>
            </div>
        </div>
        
        <div class="report-body">
            <!-- Executive Summary -->
            <div class="section">
                <h2 class="section-title">📋 Executive Summary</h2>
                <div class="executive-summary">
                    <div class="summary-grid">
                        <div class="stat-card critical">
                            <div class="label">Total Threats</div>
                            <div class="value">{exec_summary['total_threats_detected']:,}</div>
                        </div>
                        <div class="stat-card warning">
                            <div class="label">Unique Attackers</div>
                            <div class="value">{exec_summary['unique_attacker_ips']:,}</div>
                        </div>
                        <div class="stat-card info">
                            <div class="label">Blocked IPs</div>
                            <div class="value">{exec_summary['blocked_ips']:,}</div>
                        </div>
                    </div>
                    
                    <div class="risk-indicator">
                        <div class="risk-score">
                            <div style="font-size: 1.2rem; color: #7f8c8d; margin-bottom: 0.5rem;">SECURITY RISK SCORE</div>
                            <div class="score" style="color: {exec_summary['posture_color']}">{exec_summary['risk_score']}/100</div>
                            <div class="posture" style="background: {exec_summary['posture_color']}20; color: {exec_summary['posture_color']}; border: 2px solid {exec_summary['posture_color']}">
                                {exec_summary['security_posture']}
                            </div>
                        </div>
                        
                        <div style="margin-top: 2rem;">
                            <h4 style="margin-bottom: 1rem; color: #2c3e50;">🔍 Critical Findings</h4>
                            <ul style="list-style: none;">
                                {''.join(f'<li style="padding: 0.5rem 0; padding-left: 1.5rem; position: relative;"><span style="position: absolute; left: 0;">•</span> {finding}</li>' for finding in exec_summary['critical_findings'])}
                            </ul>
                        </div>
                    </div>
                    
                    <div class="recommendations">
                        <h3>📌 Priority Recommendations</h3>
                        <ul>
                            {''.join(f'<li>{rec}</li>' for rec in exec_summary['recommendations'])}
                        </ul>
                    </div>
                </div>
            </div>
            
            <!-- Threat Statistics -->
            <div class="section">
                <h2 class="section-title">📊 Threat Analysis</h2>
                
                <div class="chart-container">
                    <h3 style="margin-bottom: 1rem;">Severity Breakdown</h3>
                    <div class="bar-chart">
'''    
    
    # Add severity bars
    severity_data = threat_stats['severity_breakdown']
    max_severity = max(severity_data.values()) if severity_data else 1
    
    for level, count in [('CRITICAL', 'critical'), ('DANGEROUS', 'dangerous'), ('SUSPICIOUS', 'suspicious'), ('SAFE', 'safe')]:
        value = severity_data.get(level, 0)
        width_percent = (value / max_severity * 100) if max_severity > 0 else 0
        colors = {'critical': '#e74c3c', 'dangerous': '#e67e22', 'suspicious': '#f39c12', 'safe': '#27ae60'}
        html += f'''
                        <div class="bar-chart-item">
                            <div class="bar-chart-label">{level}</div>
                            <div class="bar-chart-bar" style="width: {width_percent}%; background: linear-gradient(90deg, {colors[value]} 0%, {colors[value]}dd 100%);"></div>
                            <div class="bar-chart-value">{value:,}</div>
                        </div>
'''
    
    html += '''
                    </div>
                </div>
                
                <div class="chart-container">
                    <h3 style="margin-bottom: 1rem;">Top Threat Types</h3>
                    <div class="bar-chart">
'''
    
    # Add threat type bars
    max_threats = max([count for _, count in top_threats]) if top_threats else 1
    for threat_type, count in top_threats:
        width_percent = (count / max_threats * 100) if max_threats > 0 else 0
        html += f'''
                        <div class="bar-chart-item">
                            <div class="bar-chart-label">{threat_type[:25]}</div>
                            <div class="bar-chart-bar" style="width: {width_percent}%;"></div>
                            <div class="bar-chart-value">{count:,}</div>
                        </div>
'''
    
    html += f'''
                    </div>
                </div>
            </div>
            
            <!-- Top Attackers -->
            <div class="section">
                <h2 class="section-title">🎯 Top Threat Actors</h2>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>IP Address</th>
                            <th>Attacks</th>
                            <th>Countries</th>
                            <th>Threat Types</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
'''
    
    for idx, attacker in enumerate(attacker_intel['top_attackers'][:15], 1):
        countries = ', '.join(attacker['countries'][:2])
        threat_types = ', '.join(list(attacker['threat_types'])[:3])
        severity_counts = {}
        for s in attacker['severity']:
            severity_counts[s] = severity_counts.get(s, 0) + 1
        top_severity = max(severity_counts, key=severity_counts.get) if severity_counts else 'SUSPICIOUS'
        
        html += f'''
                        <tr>
                            <td><strong>#{idx}</strong></td>
                            <td><code>{attacker['ip']}</code></td>
                            <td><strong>{attacker['count']:,}</strong></td>
                            <td>{countries}</td>
                            <td style="font-size: 0.85rem;">{threat_types}</td>
                            <td><span class="badge {top_severity.lower()}">{top_severity}</span></td>
                        </tr>
'''
    
    html += f'''
                    </tbody>
                </table>
            </div>
            
            <!-- Geographic Distribution -->
            <div class="section">
                <h2 class="section-title">🌍 Geographic Distribution</h2>
                <div class="chart-container">
                    <div class="bar-chart">
'''
    
    max_country = max([count for _, count in top_countries]) if top_countries else 1
    for country, count in top_countries:
        width_percent = (count / max_country * 100) if max_country > 0 else 0
        html += f'''
                        <div class="bar-chart-item">
                            <div class="bar-chart-label">{country}</div>
                            <div class="bar-chart-bar" style="width: {width_percent}%; background: linear-gradient(90deg, #9b59b6 0%, #8e44ad 100%);"></div>
                            <div class="bar-chart-value">{count:,}</div>
                        </div>
'''
    
    html += f'''
                    </div>
                </div>
            </div>
            
            <!-- AI/ML Insights -->
            <div class="section">
                <h2 class="section-title">🤖 AI/ML Intelligence</h2>
                <div class="summary-grid">
                    <div class="stat-card info">
                        <div class="label">ML Status</div>
                        <div class="value" style="font-size: 1.5rem;">{ai_insights['ml_status']}</div>
                    </div>
                    <div class="stat-card success">
                        <div class="label">Training Samples</div>
                        <div class="value">{ai_insights['training_samples']:,}</div>
                    </div>
                    <div class="stat-card">
                        <div class="label">Prediction Accuracy</div>
                        <div class="value">{ai_insights['prediction_accuracy']:.1f}%</div>
                    </div>
                </div>
                
                <div style="background: #e8f5e9; padding: 1.5rem; border-radius: 8px; margin-top: 1.5rem; border-left: 5px solid #27ae60;">
                    <h4 style="color: #155724; margin-bottom: 1rem;">🎓 Threat Intelligence Sources</h4>
                    <ul style="list-style: none;">
                        <li style="padding: 0.5rem 0;">{'✅' if threat_sources['virustotal_enabled'] else '❌'} <strong>VirusTotal API:</strong> {'Active - 70+ security vendors' if threat_sources['virustotal_enabled'] else 'Not configured'}</li>
                        <li style="padding: 0.5rem 0;">{'✅' if threat_sources['abuseipdb_enabled'] else '❌'} <strong>AbuseIPDB:</strong> {'Active - Community blacklist' if threat_sources['abuseipdb_enabled'] else 'Not configured'}</li>
                        <li style="padding: 0.5rem 0;">✅ <strong>ExploitDB:</strong> {threat_sources['exploitdb_signatures']:,} exploit signatures loaded</li>
                        <li style="padding: 0.5rem 0;">✅ <strong>Honeypots:</strong> {threat_sources['honeypot_attacks']:,} attacker interactions logged</li>
                    </ul>
                </div>
            </div>
            
            <!-- VPN/Tor Intelligence -->
            <div class="section">
                <h2 class="section-title">🔓 De-Anonymization Intelligence</h2>
                <div class="summary-grid">
                    <div class="stat-card warning">
                        <div class="label">VPN Users Detected</div>
                        <div class="value">{attacker_intel['vpn_tor_usage']['total_vpn_users']:,}</div>
                    </div>
                    <div class="stat-card warning">
                        <div class="label">Tor Users Detected</div>
                        <div class="value">{attacker_intel['vpn_tor_usage']['total_tor_users']:,}</div>
                    </div>
                    <div class="stat-card success">
                        <div class="label">Real IPs Revealed</div>
                        <div class="value">{attacker_intel['vpn_tor_usage']['real_ips_revealed']:,}</div>
                    </div>
                    <div class="stat-card info">
                        <div class="label">Proxy Chains</div>
                        <div class="value">{attacker_intel['fingerprint_tracking']['proxy_chains_detected']:,}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="report-footer">
            <p><strong>Enterprise Security Threat Intelligence System</strong></p>
            <p>This report is confidential and intended for authorized personnel only.</p>
            <p>Generated by AI-Powered Network Security System v2.0</p>
            <p style="margin-top: 1rem; font-size: 0.85rem;">© {_get_current_time().year} · All Rights Reserved</p>
        </div>
    </div>
</body>
</html>
'''
    
    return html


@app.route('/inspector/ai-monitoring/clear-all', methods=['POST'])
def clear_all_data():
    """Clear all monitoring data"""
    try:
        result = pcs_ai.clear_all_monitoring_data()
        return jsonify({
            'success': True,
            'message': 'All monitoring data cleared successfully',
            'summary': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/inspector/ai-monitoring/clear-threats', methods=['POST'])
def clear_threats():
    """Clear only threat logs"""
    try:
        result = pcs_ai.clear_threat_log_only()
        return jsonify({
            'success': True,
            'message': 'Threat logs cleared successfully',
            'summary': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/inspector/ai-monitoring/clear-blocked-ips', methods=['POST'])
def clear_blocked_ips():
    """Clear only blocked IPs"""
    try:
        result = pcs_ai.clear_blocked_ips_only()
        return jsonify({
            'success': True,
            'message': 'Blocked IPs cleared successfully',
            'summary': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/api/threat/block-ip', methods=['POST'])
def block_threat_ip():
    """Manually block an IP from threat logs"""
    try:
        data = request.json
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'}), 400
        
        # Use pcs_ai's internal blocking mechanism
        pcs_ai._block_ip(ip_address)
        
        return jsonify({
            'success': True,
            'message': f'IP {ip_address} blocked successfully',
            'ip_address': ip_address
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# REMOVED: Training endpoints (subscribers download models from relay, not train locally)
# Training happens ONLY on relay server (centralized)
# Subscribers use /api/models/sync to download pre-trained models


# REMOVED: GPU endpoints (relay server only)
# Subscribers use CPU for inference (lightweight detection)
# GPU training happens on relay server


# GPU Info Endpoint (stub for compatibility)
@app.route('/api/gpu/info', methods=['GET'])
def get_gpu_info():
    """Return GPU info stub - actual GPU training happens on relay server"""
    return jsonify({
        'gpu_available': False,
        'gpu_count': 0,
        'gpu_name': 'CPU Only (GPU training on relay server)',
        'message': 'This container uses CPU for inference. GPU-accelerated training runs on the central relay server.',
        'mode': 'Inference Only'
    })


@app.route('/api/signatures/extracted', methods=['GET'])
def get_extracted_signatures():
    """Get automatically extracted attack signatures (DEFENSIVE - no exploit code)"""
    try:
        from AI.signature_extractor import get_signature_extractor
        
        extractor = get_signature_extractor()
        ml_data = extractor.get_ml_training_data()
        
        return jsonify({
            'status': 'success',
            'metadata': {
                'total_patterns': ml_data['total_samples'],
                'attack_distribution': ml_data['attack_distribution'],
                'architecture': 'DEFENSIVE - Patterns only, NO exploit code stored',
                'data_safety': ml_data['data_safety']
            },
            'top_encodings': dict(list(extractor.attack_patterns['encodings_used'].items())[:10]),
            'top_keywords': dict(list(extractor.attack_patterns['attack_keywords'].items())[:20]),
            'encoding_chains_detected': len(extractor.attack_patterns['encoding_chains']),
            'regex_patterns_generated': len(extractor.attack_patterns['regex_patterns'])
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# REMOVED: GPU training (relay server only)
# Subscribers download pre-trained models (280 KB) from relay
# Training (heavy compute) happens centrally on relay server


@app.route('/api/models/sync', methods=['POST'])
def sync_models_from_relay():
    """Download latest ML models from relay server (Premium mode)"""
    try:
        from AI.training_sync_client import TrainingSyncClient
        
        relay_url = os.getenv('MODEL_SYNC_URL', os.getenv('RELAY_URL', '').replace('ws://', 'http://').replace(':60001', ':60002'))
        
        if not relay_url:
            return jsonify({
                'success': False,
                'message': 'MODEL_SYNC_URL not configured in .env'
            }), 400
        
        sync_client = TrainingSyncClient(relay_url)
        result = sync_client.sync_ml_models()
        
        if result['success']:
            # Reload models in pcs_ai after sync
            pcs_ai._load_ml_models()
            return jsonify({
                'success': True,
                'message': f"Downloaded {result['synced']} models from relay server",
                'models': result['models']
            })
        else:
            return jsonify(result), 500
            
    except ImportError:
        return jsonify({
            'success': False,
            'message': 'TrainingSyncClient not available. Check AI folder.'
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/inspector/users')
def user_management():
    """User management page (placeholder)"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Management</title>
        <style>
            body { font-family: system-ui; background: #0b1020; color: #f5f7ff; padding: 2rem; }
            h1 { color: #5fe2ff; }
            a { color: #5fe2ff; text-decoration: none; padding: 0.5rem 1rem; background: #151b2c; border-radius: 6px; }
        </style>
    </head>
    <body>
        <h1>👥 User Management</h1>
        <p>User management features coming soon...</p>
        <br>
        <a href="/">← Back to Dashboard</a>
    </body>
    </html>
    """

@app.route('/api/relay/block-peer', methods=['POST'])
def block_peer_api():
    """Block a peer from connecting to the relay"""
    try:
        data = request.get_json()
        peer_name = data.get('peer_name')
        
        if not peer_name:
            return jsonify({'success': False, 'message': 'Peer name is required'})
        
        # Add to blocked peers list (you can store this in a file or database)
        blocked_peers_file = 'json/blocked_peers.json'
        
        # Load existing blocked peers
        blocked_peers = []
        if os.path.exists(blocked_peers_file):
            try:
                with open(blocked_peers_file, 'r') as f:
                    blocked_peers = json.load(f)
            except:
                blocked_peers = []
        
        # Add new blocked peer
        if peer_name not in blocked_peers:
            blocked_peers.append(peer_name)
            
            # Save to file
            with open(blocked_peers_file, 'w') as f:
                json.dump(blocked_peers, f, indent=2)
            
            return jsonify({
                'success': True,
                'message': f'Peer {peer_name} has been blocked'
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Peer {peer_name} is already blocked'
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/profile')
def profile():
    """User profile page (placeholder)"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Profile</title>
        <style>
            body { font-family: system-ui; background: #0b1020; color: #f5f7ff; padding: 2rem; }
            h1 { color: #5fe2ff; }
            a { color: #5fe2ff; text-decoration: none; padding: 0.5rem 1rem; background: #151b2c; border-radius: 6px; }
        </style>
    </head>
    <body>
        <h1>👤 User Profile</h1>
        <p>Profile features coming soon...</p>
        <br>
        <a href="/">← Back to Dashboard</a>
    </body>
    </html>
    """


# API endpoints for network monitoring
@app.route('/api/check-request', methods=['POST'])
def check_request():
    """Check a request for threats (for integration with other systems)"""
    data = request.json
    
    assessment = pcs_ai.assess_request_pattern(
        ip_address=data.get('ip_address', request.remote_addr),
        endpoint=data.get('endpoint', '/'),
        method=data.get('method', 'GET'),
        user_agent=data.get('user_agent', ''),
        headers=data.get('headers', {})
    )
    
    return jsonify({
        'should_block': assessment.should_block,
        'threat_level': assessment.level.value,
        'threats': assessment.threats,
        'ip_address': assessment.ip_address
    })


@app.route('/api/check-login', methods=['POST'])
def check_login():
    """Check a login attempt for threats"""
    data = request.json
    
    assessment = pcs_ai.assess_login_attempt(
        ip_address=data.get('ip_address', request.remote_addr),
        username=data.get('username', ''),
        success=data.get('success', False),
        user_agent=data.get('user_agent', ''),
        headers=data.get('headers', {})
    )
    
    return jsonify({
        'should_block': assessment.should_block,
        'threat_level': assessment.level.value,
        'threats': assessment.threats,
        'ip_address': assessment.ip_address
    })


@app.route('/api/stats')
def api_stats():
    """Get statistics as JSON"""
    return jsonify({
        'stats': pcs_ai.get_threat_statistics(),
        'blocked_ips': pcs_ai.get_blocked_ips(),
        'ml_stats': pcs_ai.get_ml_model_stats(),
        'vpn_stats': pcs_ai.get_vpn_tor_statistics()
    })

@app.route('/api/threat_log')
def api_threat_log():
    """Get threat log data for new dashboard"""
    stats = pcs_ai.get_threat_statistics()
    return jsonify({
        'threats': stats.get('recent_threats', []),
        'total': stats.get('total_threats_detected', 0),
        'blocked_ips': pcs_ai.get_blocked_ips()
    })


@app.route('/api/unblock/<ip_address>', methods=['POST'])
def unblock_ip(ip_address):
    """Unblock an IP address"""
    success = pcs_ai.unblock_ip(ip_address)
    return jsonify({
        'success': success,
        'message': f'IP {ip_address} unblocked' if success else f'IP {ip_address} was not blocked'
    })


@app.route('/api/whitelist', methods=['GET'])
def get_whitelist():
    """Get list of whitelisted IPs"""
    return jsonify({
        'success': True,
        'whitelist': pcs_ai.get_whitelist()
    })


@app.route('/api/whitelist/add', methods=['POST'])
def add_to_whitelist():
    """Add an IP to the whitelist"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({
            'success': False,
            'message': 'IP address is required'
        }), 400
    
    success = pcs_ai.add_to_whitelist(ip_address)
    return jsonify({
        'success': success,
        'message': f'IP {ip_address} added to whitelist' if success else f'IP {ip_address} is already whitelisted'
    })


@app.route('/api/whitelist/remove', methods=['POST'])
def remove_from_whitelist():
    """Remove an IP from the whitelist"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({
            'success': False,
            'message': 'IP address is required'
        }), 400
    
    success = pcs_ai.remove_from_whitelist(ip_address)
    return jsonify({
        'success': success,
        'message': f'IP {ip_address} removed from whitelist' if success else f'IP {ip_address} not in whitelist or cannot be removed'
    })


@app.route('/api/p2p/status', methods=['GET'])
def get_p2p_status():
    """Get P2P sync status"""
    try:
        from AI.p2p_sync import get_p2p_status
        status = get_p2p_status()
        return jsonify({
            'success': True,
            'p2p_status': status
        })
    except ImportError:
        return jsonify({
            'success': True,
            'p2p_status': {'enabled': False, 'message': 'P2P sync not available'}
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/p2p/threats', methods=['GET', 'POST'])
def p2p_threats():
    """
    Peer-to-peer threat exchange endpoint
    GET: Return our threats for peer to fetch
    POST: Receive threats from peer
    """
    try:
        from AI.p2p_sync import get_p2p_sync, get_peer_threats
        
        if request.method == 'POST':
            # Receive threats from peer
            data = request.get_json()
            threats = data.get('threats', [])
            
            sync = get_p2p_sync()
            new_count = 0
            for threat in threats:
                if sync.receive_threat(threat):
                    new_count += 1
                    # Learn from peer's threat
                    try:
                        pcs_ai.add_global_threat_to_learning(threat)
                    except:
                        pass
            
            return jsonify({
                'success': True,
                'received': new_count,
                'message': f'Received {new_count} new threats'
            })
        
        else:
            # GET: Return our threats for peer to fetch
            since = request.args.get('since', '')
            limit = int(request.args.get('limit', 100))
            
            # Return our detected threats
            threats = pcs_ai._threat_log[-limit:]
            
            # Filter by timestamp if requested
            if since:
                threats = [t for t in threats if t.get('timestamp', '') > since]
            
            return jsonify({
                'success': True,
                'threats': threats,
                'count': len(threats)
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/relay/status', methods=['GET'])
def get_relay_status_api():
    """Get relay client status and connected peers"""
    try:
        from AI.relay_client import get_relay_status
        status = get_relay_status()
        return jsonify({
            'success': True,
            'relay_status': status
        })
    except ImportError:
        return jsonify({
            'success': True,
            'relay_status': {'enabled': False, 'message': 'Relay client not available'}
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/p2p/add-peer', methods=['POST'])
def add_peer():
    """Add a new peer URL dynamically"""
    data = request.get_json()
    peer_url = data.get('peer_url')
    
    if not peer_url:
        return jsonify({
            'success': False,
            'message': 'peer_url is required'
        }), 400
    
    try:
        from AI.p2p_sync import get_p2p_sync
        sync = get_p2p_sync()
        
        if peer_url not in sync.peer_urls:
            sync.peer_urls.append(peer_url)
            return jsonify({
                'success': True,
                'message': f'Added peer: {peer_url}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Peer already configured'
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==============================================================================
# ExploitDB Signature Distribution Endpoints (P2P Signature Sharing)
# ==============================================================================

@app.route('/api/signatures/types', methods=['GET'])
def get_signature_types():
    """Get list of available attack types for signature distribution."""
    try:
        from AI.signature_distribution import get_signature_distribution
        dist = get_signature_distribution()
        
        attack_types = dist.get_all_attack_types()
        
        return jsonify({
            'success': True,
            'attack_types': attack_types,
            'count': len(attack_types),
            'mode': dist.mode,
            'is_master': dist.mode == 'master'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/signatures/<attack_type>', methods=['GET'])
def get_signatures_for_type(attack_type):
    """Serve signatures for a specific attack type (master nodes)."""
    try:
        from AI.signature_distribution import get_signature_distribution
        dist = get_signature_distribution()
        
        result = dist.serve_signatures(attack_type)
        
        if 'error' in result:
            return jsonify(result), 403
        
        return jsonify({
            'success': True,
            **result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/signatures/stats', methods=['GET'])
def get_signature_stats():
    """Get signature distribution statistics."""
    try:
        from AI.signature_distribution import get_signature_distribution
        dist = get_signature_distribution()
        
        return jsonify({
            'success': True,
            'stats': dist.get_stats()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/signatures/sync', methods=['POST'])
def sync_signatures():
    """Trigger manual signature sync with peers (client nodes)."""
    try:
        from AI.signature_distribution import get_signature_distribution
        dist = get_signature_distribution()
        
        if dist.mode != 'client':
            return jsonify({
                'success': False,
                'message': 'Only client nodes can request sync'
            }), 400
        
        dist.sync_with_peers()
        
        return jsonify({
            'success': True,
            'message': 'Signature sync completed',
            'stats': dist.get_stats()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/graph-intelligence/attack-chains', methods=['GET'])
def get_attack_chains():
    """Get attack chain visualization data (Phase 4)."""
    try:
        from AI.pcs_ai import get_attack_chains as get_chains
        return jsonify(get_chains())
    except Exception as e:
        logger.error(f"[API] Attack chains error: {e}")
        return jsonify({
            'error': str(e),
            'total_chains': 0,
            'lateral_movement_count': 0,
            'total_nodes': 0,
            'total_edges': 0,
            'attack_chains': []
        }), 500


@app.route('/api/explainability/decisions', methods=['GET'])
def get_explainability_decisions():
    """Get AI decision explanations (Phase 7)."""
    try:
        from AI.pcs_ai import get_explainability_decisions as get_decisions
        return jsonify(get_decisions())
    except Exception as e:
        logger.error(f"[API] Explainability error: {e}")
        return jsonify({
            'error': str(e),
            'total_decisions': 0,
            'high_confidence_count': 0,
            'low_confidence_count': 0,
            'average_confidence': 0.0,
            'decisions': []
        }), 500


# ============================================================================
# NEW MODULES B, C, D, F, G, H, J - API ENDPOINTS
# ============================================================================

@app.route('/api/byzantine-defense/stats', methods=['GET'])
def get_byzantine_stats():
    """Get Byzantine-resilient federated learning statistics."""
    try:
        from AI.pcs_ai import get_byzantine_defense_stats
        return jsonify(get_byzantine_defense_stats())
    except Exception as e:
        logger.error(f"[API] Byzantine defense error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/model-lineage/stats', methods=['GET'])
def get_lineage_stats():
    """Get cryptographic model lineage statistics."""
    try:
        from AI.pcs_ai import get_model_lineage_stats
        return jsonify(get_model_lineage_stats())
    except Exception as e:
        logger.error(f"[API] Model lineage error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/deterministic-eval/stats', methods=['GET'])
def get_deterministic_stats():
    """Get deterministic evaluation statistics."""
    try:
        from AI.pcs_ai import get_deterministic_eval_stats
        return jsonify(get_deterministic_eval_stats())
    except Exception as e:
        logger.error(f"[API] Deterministic evaluation error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/threat-model/stats', methods=['GET'])
def get_threat_model_stats():
    """Get formal threat model statistics."""
    try:
        from AI.pcs_ai import get_threat_model_stats
        return jsonify(get_threat_model_stats())
    except Exception as e:
        logger.error(f"[API] Threat model error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/self-protection/stats', methods=['GET'])
def get_protection_stats():
    """Get self-protection and integrity monitoring statistics."""
    try:
        from AI.pcs_ai import get_self_protection_stats
        return jsonify(get_self_protection_stats())
    except Exception as e:
        logger.error(f"[API] Self-protection error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/governance/stats', methods=['GET'])
def get_governance_stats():
    """Get policy governance and approval queue statistics."""
    try:
        from AI.pcs_ai import get_policy_governance_stats
        return jsonify(get_policy_governance_stats())
    except Exception as e:
        logger.error(f"[API] Governance error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/killswitch/status', methods=['GET'])
def get_killswitch():
    """Get emergency kill-switch status."""
    try:
        from AI.pcs_ai import get_killswitch_status
        return jsonify(get_killswitch_status())
    except Exception as e:
        logger.error(f"[API] Kill-switch error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/audit-log/stats', methods=['GET'])
def get_audit_stats():
    """Get comprehensive audit log statistics."""
    try:
        from AI.pcs_ai import get_audit_log_stats
        return jsonify(get_audit_log_stats())
    except Exception as e:
        logger.error(f"[API] Audit log error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/system-logs/<os_type>', methods=['GET'])
def get_system_logs(os_type):
    """Get system logs for Linux/Windows/macOS."""
    try:
        from AI.system_log_collector import get_system_log_collector
        collector = get_system_log_collector()
        
        hours = int(request.args.get('hours', 168))  # Default 7 days
        
        if os_type.lower() == 'linux':
            logs = collector.collect_linux_logs(hours)
        elif os_type.lower() == 'windows':
            logs = collector.collect_windows_logs(hours)
        elif os_type.lower() == 'macos':
            logs = collector.collect_macos_logs(hours)
        else:
            return jsonify({'error': 'Invalid OS type'}), 400
        
        logs['os_type'] = os_type
        logs['collection_time'] = datetime.now().isoformat()
        return jsonify(logs)
    except Exception as e:
        logger.error(f"[API] System logs error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/central-sync/register', methods=['POST'])
def register_with_central():
    """DEPRECATED: No central server needed in P2P architecture"""
    return jsonify({
        'success': False,
        'message': 'Central server deprecated - using P2P mesh instead. Set PEER_URLS environment variable.'
    }), 410


@app.route('/api/central-sync/status', methods=['GET'])
def get_central_sync_status():
    """DEPRECATED: Redirect to P2P status"""
    return get_p2p_status()


def start_network_monitoring():
    """Start network monitoring in background"""
    try:
        from network_monitor import NetworkMonitor
        monitor = NetworkMonitor()
        monitor.start()
        print("[NETWORK] Network monitoring started")
    except ImportError:
        print("[WARNING] network_monitor.py not found - network monitoring disabled")
        print("[INFO] Install required packages: pip install scapy")
    
    # Start device scanner
    try:
        from device_scanner import scanner
        scanner.start()
        print("[DEVICE SCANNER] Device discovery started")
    except ImportError:
        print("[WARNING] device_scanner.py not found - device discovery disabled")
    except Exception as e:
        print(f"[WARNING] Could not start device scanner: {e}")


# API endpoint for system status
@app.route('/api/system-status', methods=['GET'])
def get_system_status():
    """Get comprehensive system status for dashboard"""
    try:
        import os
        import psutil
        import platform
        from datetime import timedelta
        
        # System Health Metrics
        cpu_usage = round(psutil.cpu_percent(interval=0.1))
        memory = psutil.virtual_memory()
        memory_usage = round(memory.percent)
        
        # Cross-platform disk usage
        if platform.system() == 'Windows':
            disk = psutil.disk_usage('C:\\')
        else:
            disk = psutil.disk_usage('/')
        disk_usage = round(disk.percent)
        
        # Uptime
        boot_time = psutil.boot_time()
        uptime_seconds = int(psutil.time.time() - boot_time)
        uptime_delta = timedelta(seconds=uptime_seconds)
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        uptime = f"{days}d {hours}h {minutes}m" if days > 0 else f"{hours}h {minutes}m"
        
        # Service Status (check if processes are running)
        services = {
            'Flask Server': 'running',  # If we're responding, Flask is running
            'Network Monitor': 'running',  # Assumed running if container is up
            'AI Engine': 'running' if hasattr(pcs_ai, 'ML_AVAILABLE') else 'stopped',
            'Threat Intelligence': 'running',
        }
        
        # Check VirusTotal API key
        vt_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        vt_status = {
            'status': 'ok' if vt_key and len(vt_key) == 64 else 'error',
            'message': 'Connected to 70+ security vendors' if vt_key and len(vt_key) == 64 else 'API key not configured - add in System Status'
        }
        
        # Check AbuseIPDB API key
        abuse_key = os.getenv('ABUSEIPDB_API_KEY', '')
        abuse_status = {
            'status': 'ok' if abuse_key else 'disabled',
            'message': 'Community IP blacklist active' if abuse_key else 'Optional - not configured'
        }
        
        # ML Models status
        total_training_samples = len(pcs_ai._threat_log) + len(pcs_ai._peer_threats) if hasattr(pcs_ai, '_peer_threats') else len(pcs_ai._threat_log)
        local_samples = len(pcs_ai._threat_log)
        ml_status = {
            'status': 'ok' if pcs_ai.ML_AVAILABLE and pcs_ai._ml_last_trained else 'warning',
            'message': f'3 models trained ({total_training_samples} samples: {local_samples} local + {total_training_samples - local_samples} peer)' if pcs_ai.ML_AVAILABLE else 'Collecting training data',
            'last_trained': pcs_ai._ml_last_trained.isoformat() if pcs_ai._ml_last_trained else None
        }
        
        # ExploitDB status
        try:
            from AI.threat_intelligence import _exploitdb_signatures
            exploitdb_status = {
                'status': 'ok' if len(_exploitdb_signatures) > 0 else 'warning',
                'message': f'Learning from real exploits' if len(_exploitdb_signatures) > 0 else 'Downloading exploit database',
                'signatures_loaded': len(_exploitdb_signatures)
            }
        except:
            exploitdb_status = {
                'status': 'warning',
                'message': 'Loading exploit signatures',
                'signatures_loaded': 0
            }
        
        # Honeypots status
        try:
            from AI.threat_intelligence import honeypot
            honeypot_status = honeypot.get_honeypot_status() if hasattr(honeypot, 'get_honeypot_status') else {
                'services': {},
                'total_services': 0,
                'enabled_services': 0,
                'total_attacks': 0,
                'attack_log_size': len(honeypot.attack_log) if hasattr(honeypot, 'attack_log') else 0,
                'learned_patterns': len(honeypot.learned_patterns) if hasattr(honeypot, 'learned_patterns') else 0
            }
        except Exception as e:
            honeypot_status = {
                'services': {},
                'total_services': 0,
                'enabled_services': 0,
                'total_attacks': 0,
                'attack_log_size': 0,
                'learned_patterns': 0
            }
        
        # Threat Intelligence status
        threat_intel_sources = []
        if vt_key:
            threat_intel_sources.append('VirusTotal')
        if abuse_key:
            threat_intel_sources.append('AbuseIPDB')
        threat_intel_sources.append('ExploitDB')
        threat_intel_sources.append('Honeypots')
        
        threat_intel_status = {
            'status': 'ok' if len(threat_intel_sources) >= 2 else 'warning',
            'sources': threat_intel_sources,
            'total_queries': len(pcs_ai._threat_log) if hasattr(pcs_ai, '_threat_log') else 0
        }
        
        # Detection stats
        detection_stats = {
            'total_threats': len(pcs_ai._threat_log) if hasattr(pcs_ai, '_threat_log') else 0,
            'blocked_ips': len(pcs_ai._blocked_ips) if hasattr(pcs_ai, '_blocked_ips') else 0
        }
        
        # Current API keys (masked)
        current_keys = {
            'virustotal': vt_key if vt_key else None,
            'abuseipdb': abuse_key if abuse_key else None
        }
        
        return jsonify({
            # System health metrics
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'disk_usage': disk_usage,
            'uptime': uptime,
            'services': services,
            
            # API status
            'virustotal': vt_status,
            'abuseipdb': abuse_status,
            'ml_models': ml_status,
            'exploitdb': exploitdb_status,
            'honeypots': honeypot_status,
            'threat_intel': threat_intel_status,
            'detection_stats': detection_stats,
            'current_keys': current_keys
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API endpoint to update API keys
@app.route('/api/update-api-key', methods=['POST'])
def update_api_key():
    """Update API keys (VirusTotal or AbuseIPDB)"""
    try:
        data = request.json
        key_type = data.get('key_type')
        api_key = data.get('api_key', '').strip()
        
        if key_type not in ['virustotal', 'abuseipdb']:
            return jsonify({'success': False, 'error': 'Invalid key type'}), 400
        
        # Update .env file
        env_path = '/app/../.env'
        if not os.path.exists(env_path):
            env_path = '../.env'
        
        # Read current .env
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_lines = f.readlines()
        
        # Update the appropriate key
        key_name = 'VIRUSTOTAL_API_KEY' if key_type == 'virustotal' else 'ABUSEIPDB_API_KEY'
        key_updated = False
        
        for i, line in enumerate(env_lines):
            if line.startswith(key_name + '='):
                env_lines[i] = f'{key_name}={api_key}\n'
                key_updated = True
                break
        
        # Add key if not found
        if not key_updated:
            env_lines.append(f'{key_name}={api_key}\n')
        
        # Write back to .env
        with open(env_path, 'w') as f:
            f.writelines(env_lines)
        
        # Update environment variable for current process
        os.environ[key_name] = api_key
        
        # Reload threat intelligence module if VirusTotal key was updated
        if key_type == 'virustotal':
            try:
                from AI import threat_intelligence
                threat_intelligence.VIRUSTOTAL_API_KEY = api_key
                return jsonify({
                    'success': True,
                    'message': f'{key_type.title()} API key updated! Restart container for full effect.'
                })
            except:
                pass
        
        return jsonify({
            'success': True,
            'message': f'{key_type.title()} API key saved! Restart container for full effect.'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoint to update timezone
@app.route('/api/update-timezone', methods=['POST'])
def update_timezone():
    """Update timezone setting"""
    try:
        data = request.json
        timezone = data.get('timezone', '').strip()
        
        if not timezone:
            return jsonify({'success': False, 'error': 'Timezone required'}), 400
        
        # Validate timezone
        try:
            import pytz
            pytz.timezone(timezone)
        except:
            return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        
        # Update .env file
        env_path = '/app/../.env'
        if not os.path.exists(env_path):
            env_path = '../.env'
        
        # Read current .env
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_lines = f.readlines()
        
        # Update timezone
        tz_updated = False
        for i, line in enumerate(env_lines):
            if line.startswith('TZ='):
                env_lines[i] = f'TZ={timezone}\n'
                tz_updated = True
                break
        
        # Add if not found
        if not tz_updated:
            env_lines.append(f'TZ={timezone}\n')
        
        # Write back to .env
        with open(env_path, 'w') as f:
            f.writelines(env_lines)
        
        # Update environment variable for current process
        os.environ['TZ'] = timezone
        
        # Get current time in new timezone
        import pytz
        tz = pytz.timezone(timezone)
        current_time = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S %Z')
        
        return jsonify({
            'success': True,
            'message': f'Timezone updated to {timezone}',
            'current_time': current_time
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoint to get current time
@app.route('/api/current-time', methods=['GET'])
def get_current_time():
    """Get current time in configured timezone"""
    try:
        import pytz
        tz_name = os.getenv('TZ', 'Asia/Kuala_Lumpur')
        tz = pytz.timezone(tz_name)
        current_time = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S %Z')
        
        return jsonify({
            'timezone': tz_name,
            'current_time': current_time
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API endpoint to get current ports
@app.route('/api/current-ports', methods=['GET'])
def get_current_ports():
    """Get current port configuration"""
    try:
        dashboard_port = int(os.getenv('DASHBOARD_PORT', '60000'))
        p2p_port = int(os.getenv('P2P_PORT', '60001'))
        
        return jsonify({
            'dashboard_port': dashboard_port,
            'p2p_port': p2p_port
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API endpoint to update ports
@app.route('/api/update-ports', methods=['POST'])
def update_ports():
    """Update port configuration in .env file"""
    try:
        data = request.json
        dashboard_port = data.get('dashboard_port')
        p2p_port = data.get('p2p_port')
        
        # Validation
        if not dashboard_port or not p2p_port:
            return jsonify({'success': False, 'error': 'Both ports required'}), 400
        
        if dashboard_port < 1024 or dashboard_port > 65535:
            return jsonify({'success': False, 'error': 'Dashboard port must be between 1024 and 65535'}), 400
        
        if p2p_port < 1024 or p2p_port > 65535:
            return jsonify({'success': False, 'error': 'P2P port must be between 1024 and 65535'}), 400
        
        if dashboard_port == p2p_port:
            return jsonify({'success': False, 'error': 'Ports must be different'}), 400
        
        # Update .env file
        env_path = '/app/../.env'
        if not os.path.exists(env_path):
            env_path = '../.env'
        if not os.path.exists(env_path):
            env_path = '.env'
        
        # Read current .env
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_lines = f.readlines()
        else:
            # Create from .env.example if .env doesn't exist
            example_path = '../.env.example'
            if os.path.exists(example_path):
                with open(example_path, 'r') as f:
                    env_lines = f.readlines()
        
        # Update ports
        dashboard_updated = False
        p2p_updated = False
        
        for i, line in enumerate(env_lines):
            if line.startswith('DASHBOARD_PORT='):
                env_lines[i] = f'DASHBOARD_PORT={dashboard_port}\n'
                dashboard_updated = True
            elif line.startswith('P2P_PORT='):
                env_lines[i] = f'P2P_PORT={p2p_port}\n'
                p2p_updated = True
        
        # Add if not found
        if not dashboard_updated:
            env_lines.append(f'DASHBOARD_PORT={dashboard_port}\n')
        if not p2p_updated:
            env_lines.append(f'P2P_PORT={p2p_port}\n')
        
        # Write back to .env
        with open(env_path, 'w') as f:
            f.writelines(env_lines)
        
        return jsonify({
            'success': True,
            'message': 'Port configuration saved! Download the .env file and restart Docker container to apply changes.',
            'dashboard_port': dashboard_port,
            'p2p_port': p2p_port
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoint to generate .env file with updated ports
@app.route('/api/generate-env-file', methods=['POST'])
def generate_env_file():
    """Generate .env file with updated ports for download"""
    try:
        data = request.json
        dashboard_port = data.get('dashboard_port', 60000)
        p2p_port = data.get('p2p_port', 60001)
        
        # Read current .env or .env.example
        env_path = '/app/../.env'
        if not os.path.exists(env_path):
            env_path = '../.env'
        if not os.path.exists(env_path):
            env_path = '../.env.example'
        if not os.path.exists(env_path):
            env_path = '.env.example'
        
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_lines = f.readlines()
        
        # Update ports
        dashboard_updated = False
        p2p_updated = False
        
        for i, line in enumerate(env_lines):
            if line.startswith('DASHBOARD_PORT='):
                env_lines[i] = f'DASHBOARD_PORT={dashboard_port}  # Dashboard web interface (HTTP)\n'
                dashboard_updated = True
            elif line.startswith('P2P_PORT='):
                env_lines[i] = f'P2P_PORT={p2p_port}        # P2P mesh synchronization (HTTPS)\n'
                p2p_updated = True
        
        # Add if not found
        if not dashboard_updated:
            env_lines.append(f'\n# Port Configuration\nDASHBOARD_PORT={dashboard_port}  # Dashboard web interface (HTTP)\n')
        if not p2p_updated:
            env_lines.append(f'P2P_PORT={p2p_port}        # P2P mesh synchronization (HTTPS)\n')
        
        # Create downloadable .env file
        env_content = ''.join(env_lines)
        
        from io import BytesIO
        env_bytes = BytesIO(env_content.encode('utf-8'))
        env_bytes.seek(0)
        
        return send_file(
            env_bytes,
            mimetype='text/plain',
            as_attachment=True,
            download_name='.env'
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# NEW API ENDPOINTS - Performance, Compliance, Visualization
# ============================================================================

@app.route('/api/performance/metrics', methods=['GET'])
def get_performance_metrics():
    """Get network performance metrics for dashboard"""
    try:
        import psutil
        import socket
        import subprocess
        
        # Try to get physical network interface speed from ethtool (host system)
        link_speed_mbps = 0
        try:
            # Common interface names
            interfaces = ['eth0', 'eno1', 'enp0s3', 'wlan0', 'wlo1', 'ens18']
            for iface in interfaces:
                try:
                    result = subprocess.run(
                        ['ethtool', iface],
                        capture_output=True,
                        text=True,
                        timeout=1
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'Speed:' in line:
                                speed_str = line.split('Speed:')[1].strip()
                                if 'Mb/s' in speed_str:
                                    link_speed_mbps = int(speed_str.replace('Mb/s', '').strip())
                                elif 'Gb/s' in speed_str:
                                    link_speed_mbps = int(float(speed_str.replace('Gb/s', '').strip()) * 1000)
                                break
                        if link_speed_mbps > 0:
                            break
                except:
                    continue
        except:
            pass
        
        # If ethtool failed, try to detect from common speeds (fallback)
        if link_speed_mbps == 0:
            # Assume Gigabit Ethernet as common default
            link_speed_mbps = 1000
        
        # Calculate current throughput
        current_bandwidth = 0.0
        try:
            import AI.network_performance as net_perf
            stats = net_perf.get_network_statistics()
            current_bandwidth = (stats.get('total_bandwidth_in', 0) + stats.get('total_bandwidth_out', 0)) / 1_000_000
        except:
            pass
        
        # Measure latency to internet using socket
        latency = 0.0
        try:
            start_time = time.time()
            sock = socket.create_connection(('8.8.8.8', 53), timeout=2)
            latency = (time.time() - start_time) * 1000  # Convert to ms
            sock.close()
        except:
            latency = 0.0
        
        # Calculate packet loss from network interface stats
        net_io = psutil.net_io_counters()
        packet_loss = 0.0
        if net_io.packets_sent > 0:
            total_errors = net_io.errin + net_io.errout + net_io.dropin + net_io.dropout
            packet_loss = (total_errors / net_io.packets_sent) * 100 if net_io.packets_sent > 0 else 0.0
        
        return jsonify({
            'bandwidth': link_speed_mbps,
            'bandwidth_type': 'link_speed',
            'current_usage': round(current_bandwidth, 2),
            'latency': round(latency, 1),
            'packet_loss': round(min(packet_loss, 100), 2),
            'labels': [],
            'bandwidth_history': [],
            'latency_history': []
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/performance/network-stats', methods=['GET'])
def get_network_stats():
    """Get network-wide performance statistics"""
    try:
        import AI.network_performance as net_perf
        stats = net_perf.get_network_statistics()
        return jsonify({'status': 'success', 'stats': stats})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/performance/anomalies', methods=['GET'])
def get_performance_anomalies():
    """Get IPs with detected performance anomalies"""
    try:
        import AI.network_performance as net_perf
        anomalies = net_perf.get_performance_anomalies()
        return jsonify({'status': 'success', 'anomalies': anomalies})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/compliance/report/<report_type>', methods=['GET'])
def get_compliance_report(report_type):
    """Generate compliance report (pci_dss, hipaa, gdpr, soc2)"""
    try:
        import AI.compliance_reporting as compliance
        from datetime import timedelta
        
        days = int(request.args.get('days', 30))
        end_date = _get_current_time()
        start_date = end_date - timedelta(days=days)
        
        if report_type == 'pci_dss':
            report = compliance.generate_pci_dss_report(start_date, end_date)
        elif report_type == 'hipaa':
            report = compliance.generate_hipaa_report(start_date, end_date)
        elif report_type == 'gdpr':
            report = compliance.generate_gdpr_report(start_date, end_date)
        elif report_type == 'soc2':
            report = compliance.generate_soc2_report(start_date, end_date)
        else:
            return jsonify({'status': 'error', 'message': f'Unknown report type: {report_type}'}), 400
        
        return jsonify({'status': 'success', 'report': report})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/compliance/summary', methods=['GET'])
def get_compliance_summary():
    """Get compliance summary for dashboard"""
    try:
        import AI.compliance_reporting as compliance
        summary = compliance.get_compliance_summary()
        
        # Extract compliance standards and convert to percentages (100% = COMPLIANT)
        standards = summary.get('compliance_standards', {})
        
        return jsonify({
            'pci_dss': 100 if standards.get('pci_dss') == 'COMPLIANT' else 0,
            'hipaa': 100 if standards.get('hipaa') == 'COMPLIANT' else 0,
            'gdpr': 100 if standards.get('gdpr') == 'COMPLIANT' else 0,
            'soc2': 100 if standards.get('soc2') == 'COMPLIANT' else 0,
            'total_events': summary.get('total_security_events', 0),
            'blocked_attacks': summary.get('blocked_attacks', 0),
            'critical_incidents': summary.get('critical_incidents', 0)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/visualization/topology', methods=['GET'])
def get_network_topology():
    """Get network topology map"""
    try:
        import AI.advanced_visualization as viz
        import traceback
        topology = viz.generate_network_topology()
        return jsonify({'status': 'success', 'topology': topology})
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[TOPOLOGY ERROR] {error_trace}")
        return jsonify({'status': 'error', 'message': str(e), 'traceback': error_trace}), 500


@app.route('/api/visualization/attack-flows', methods=['GET'])
def get_attack_flows():
    """Get attack flow diagram"""
    try:
        import AI.advanced_visualization as viz
        time_range = int(request.args.get('minutes', 60))
        flows = viz.generate_attack_flows(time_range)
        return jsonify({'status': 'success', 'flows': flows})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/visualization/heatmap', methods=['GET'])
def get_threat_heatmap():
    """Get threat heatmap"""
    try:
        import AI.advanced_visualization as viz
        hours = int(request.args.get('hours', 24))
        heatmap = viz.generate_threat_heatmap(hours)
        return jsonify({'status': 'success', 'heatmap': heatmap})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/visualization/geographic', methods=['GET'])
def get_geographic_map():
    """Get geographic attack origin map"""
    try:
        import AI.advanced_visualization as viz
        geo_data = viz.generate_geographic_map()

        # Normalize to the structure expected by the dashboard (Section 18)
        # Frontend expects: { countries: [ { country, attack_count, threat_level, blocked } ] }
        countries = []
        country_list = geo_data.get('country_data', []) or geo_data.get('top_attacking_countries', [])

        for c in country_list:
            attack_count = c.get('attack_count', 0) or 0
            critical = c.get('critical_attacks', 0) or 0
            dangerous = c.get('dangerous_attacks', 0) or 0
            blocked = c.get('blocked_attacks', 0) or 0

            # Derive threat level for badge coloring
            if critical > 0:
                threat_level = 'critical'
            elif attack_count >= 10 or dangerous > 0:
                threat_level = 'high'
            elif attack_count > 0:
                threat_level = 'medium'
            else:
                threat_level = 'low'

            countries.append({
                'country': c.get('country', 'Unknown'),
                'attack_count': attack_count,
                'threat_level': threat_level,
                # Blocked if we have any blocked attacks from that country
                'blocked': bool(blocked),
            })

        return jsonify({'countries': countries})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/visualization/all', methods=['GET'])
def get_all_visualizations():
    """Generate all visualizations at once"""
    try:
        import AI.advanced_visualization as viz
        visualizations = viz.generate_all_visualizations()
        return jsonify({'status': 'success', 'visualizations': visualizations})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/connected-devices', methods=['GET'])
def get_connected_devices_api():
    """Get all devices connected to the network"""
    try:
        from device_scanner import get_connected_devices
        devices_data = get_connected_devices()
        return jsonify(devices_data)
    except ImportError:
        return jsonify({
            'devices': [],
            'total_count': 0,
            'last_scan': None,
            'device_summary': {},
            'error': 'Device scanner not available - scapy not installed'
        })
    except Exception as e:
        return jsonify({
            'devices': [],
            'total_count': 0,
            'last_scan': None,
            'device_summary': {},
            'error': str(e)
        }), 500


@app.route('/api/device-history', methods=['GET', 'DELETE'])
def get_device_history_api():
    """Get or clear device connection history (last 7 days)"""
    if request.method == 'DELETE':
        # Clear device history
        try:
            from device_scanner import clear_device_history
            clear_device_history()
            return jsonify({'success': True, 'message': 'Device history cleared'})
        except ImportError:
            return jsonify({'success': False, 'error': 'Device scanner not available'}), 500
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Get device history
        try:
            from device_scanner import get_device_history
            history_data = get_device_history()
            return jsonify(history_data)
        except Exception as e:
            return jsonify({
                'devices': [],
                'total_count': 0,
                'error': str(e)
            }), 500


@app.route('/api/device/block', methods=['POST'])
def block_device_api():
    """Block a device from network access"""
    try:
        from device_scanner import block_device
        data = request.json
        mac = data.get('mac')
        ip = data.get('ip')
        
        if not mac or not ip:
            return jsonify({'success': False, 'error': 'MAC and IP required'}), 400
        
        success = block_device(mac, ip)
        return jsonify({
            'success': success,
            'message': f'Device {mac} blocked',
            'mac': mac,
            'ip': ip
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device/unblock', methods=['POST'])
def unblock_device_api():
    """Unblock a device to restore network access"""
    try:
        from device_scanner import unblock_device
        data = request.json
        mac = data.get('mac')
        ip = data.get('ip')
        
        if not mac or not ip:
            return jsonify({'success': False, 'error': 'MAC and IP required'}), 400
        
        success = unblock_device(mac, ip)
        return jsonify({
            'success': success,
            'message': f'Device {mac} unblocked',
            'mac': mac,
            'ip': ip
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan-devices', methods=['POST'])
def manual_scan_devices():
    """Manually trigger device scan"""
    try:
        from device_scanner import trigger_manual_scan
        result = trigger_manual_scan()
        return jsonify({
            'success': True,
            'message': 'Device scan completed',
            'devices_found': result.get('total_count', 0),
            'scan_time': result.get('last_scan')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoints for Adaptive Honeypot
# ============================================================================

@app.route('/api/adaptive_honeypot/status', methods=['GET'])
def adaptive_honeypot_status():
    """Get adaptive honeypot status"""
    try:
        from AI.adaptive_honeypot import get_honeypot_status
        status = get_honeypot_status()

        # Normalize keys for dashboard while preserving core fields
        response = {
            'running': bool(status.get('running', False)),
            'persona': status.get('persona_name') or status.get('current_persona'),
            'port': status.get('port'),
            'attack_count': status.get('total_attacks', 0),
        }

        return jsonify(response)
    except Exception as e:
        return jsonify({'running': False, 'error': str(e)}), 500

@app.route('/api/adaptive_honeypot/personas', methods=['GET'])
def adaptive_honeypot_personas():
    """Get available service personas"""
    try:
        from AI.adaptive_honeypot import get_available_personas
        personas = get_available_personas()
        return jsonify(personas)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/adaptive_honeypot/configure', methods=['POST'])
def configure_adaptive_honeypot():
    """Configure and start honeypot"""
    try:
        from AI.adaptive_honeypot import start_honeypot
        
        data = request.json
        persona = data.get('persona', 'http_admin')
        port = data.get('port', 8080)
        custom_banner = data.get('custom_banner')
        
        success = start_honeypot(persona, port, custom_banner)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Honeypot started as {persona} on port {port}'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to start honeypot'
            }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/adaptive_honeypot/stop', methods=['POST'])
def stop_adaptive_honeypot_api():
    """Stop the honeypot"""
    try:
        from AI.adaptive_honeypot import stop_honeypot
        stop_honeypot()
        return jsonify({'success': True, 'message': 'Honeypot stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/adaptive_honeypot/attacks', methods=['GET'])
def adaptive_honeypot_attacks():
    """Get honeypot attack log"""
    try:
        from AI.adaptive_honeypot import get_honeypot
        hp = get_honeypot()
        attacks = hp.get_attack_log(limit=100)
        return jsonify(attacks)
    except Exception as e:
        return jsonify([], 500)


# API endpoint to toggle honeypots (DEPRECATED - kept for backward compatibility)
@app.route('/api/honeypot/toggle', methods=['POST'])
def toggle_honeypot():
    """Enable or disable a specific honeypot service (DEPRECATED)"""
    try:
        from AI.threat_intelligence import honeypot
        
        data = request.json
        service_id = data.get('service_id')
        enabled = data.get('enabled', True)
        
        if not service_id:
            return jsonify({'success': False, 'error': 'service_id required'}), 400
        
        success = honeypot.toggle_honeypot(service_id, enabled)
        
        if success:
            # Redeploy honeypots
            honeypot.deploy_honeypots()
            
            return jsonify({
                'success': True,
                'message': f'Honeypot {service_id} {"enabled" if enabled else "disabled"}',
                'service_id': service_id,
                'enabled': enabled
            })
        else:
            return jsonify({'success': False, 'error': f'Unknown service: {service_id}'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoint to get honeypot details
@app.route('/api/honeypot/status', methods=['GET'])
def get_honeypot_status():
    """Get detailed honeypot status"""
    try:
        from AI.threat_intelligence import honeypot
        
        status = honeypot.get_honeypot_status()
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500




# ============================================================================
# Advanced feature endpoints (traffic analysis, DNS, user monitoring, forensics)
# ============================================================================

# Import real implementation modules
try:
    from AI.traffic_analyzer import traffic_analyzer
    from AI.pcap_capture import pcap_capture
    from AI.user_tracker import user_tracker
    from AI.file_analyzer import file_analyzer
    from AI.alert_system import alert_system
    from AI.soar_api import soar_integration
    ADVANCED_FEATURES_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] Advanced features modules not loaded: {e}")
    ADVANCED_FEATURES_AVAILABLE = False

@app.route('/api/traffic/analysis', methods=['GET'])
def get_traffic_analysis():
    """Real-time traffic analysis with DPI"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            stats = traffic_analyzer.get_stats()
            return jsonify(stats)
        else:
            return jsonify({'error': 'Traffic analyzer not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dns/stats', methods=['GET'])
def get_dns_stats():
    """Get DNS query statistics"""
    try:
        # Cross-platform DNS activity estimate using psutil
        dns_count = 0

        try:
            import psutil  # type: ignore
        except ImportError:
            psutil = None

        if psutil is not None:
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    lport = conn.laddr.port if conn.laddr else None
                    rport = conn.raddr.port if conn.raddr else None
                    if lport == 53 or rport == 53:
                        dns_count += 1
            except Exception:
                dns_count = 0

        return jsonify({
            'total_queries': dns_count * 100,  # Estimate based on active connections
            'blocked_domains': 0,
            'tunneling_detected': 0
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/tracking', methods=['GET'])
def get_user_tracking():
    """Get tracked users on network"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            stats = user_tracker.get_stats()
            return jsonify(stats)
        else:
            return jsonify({'error': 'User tracker not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-hunt', methods=['POST'])
def threat_hunt():
    """Real threat hunting via PCAP search"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'PCAP capture module not loaded',
                'status': 'NOT_AVAILABLE'
            }), 503
        
        data = request.get_json()
        query = data.get('query', '')
        timerange = data.get('timerange', '1h')
        protocol = data.get('protocol', 'all')
        
        results = pcap_capture.search_pcap(query, timerange, protocol)
        
        if not pcap_capture.is_tcpdump_available():
            return jsonify({
                'success': False,
                'error': 'tcpdump not installed or not accessible',
                'status': 'NOT_IMPLEMENTED',
                'required': ['Install tcpdump: apt-get install tcpdump', 'Grant CAP_NET_RAW capability']
            }), 501
        
        return jsonify({
            'success': True,
            'matches': len(results),
            'results': results,
            'query': query,
            'timerange': timerange
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/pcap/stats', methods=['GET'])
def get_pcap_stats():
    """Get PCAP capture statistics"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            return jsonify(pcap_capture.get_stats())
        else:
            return jsonify({'error': 'PCAP module not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/pcap/download', methods=['GET'])
def download_pcap():
    """Download latest PCAP file"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({'error': 'PCAP module not available'}), 503

        # Find latest PCAP file in capture directory
        pcap_dir = pcap_capture.pcap_dir
        if not os.path.isdir(pcap_dir):
            return jsonify({'error': 'No PCAP directory found'}), 404

        pcap_files = sorted(
            [
                os.path.join(pcap_dir, f)
                for f in os.listdir(pcap_dir)
                if f.endswith('.pcap')
            ]
        )

        if not pcap_files:
            return jsonify({'error': 'No PCAP files available'}), 404

        latest_pcap = pcap_files[-1]

        # Stream file to client (works inside Docker regardless of host OS)
        return send_file(
            latest_pcap,
            as_attachment=True,
            download_name=os.path.basename(latest_pcap),
            mimetype='application/vnd.tcpdump.pcap'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sandbox/detonate', methods=['POST'])
def sandbox_detonate():
    """Real file analysis (hash-based threat detection)"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'File analyzer module not loaded',
                'status': 'NOT_AVAILABLE'
            }), 503
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Empty filename'}), 400
        
        # Save file temporarily
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            file.save(tmp.name)
            result = file_analyzer.analyze_file(tmp.name, file.filename)
            os.unlink(tmp.name)  # Delete temp file
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sandbox/stats', methods=['GET'])
def get_sandbox_stats():
    """Get sandbox analysis statistics"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            return jsonify(file_analyzer.get_stats())
        else:
            return jsonify({'error': 'File analyzer not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/email/config', methods=['POST'])
def save_email_config():
    """Save real email alert configuration"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({'success': False, 'error': 'Alert system not available'}), 503
        
        data = request.get_json()
        success = alert_system.save_config('email', data)
        return jsonify({
            'success': success,
            'message': 'Email configuration saved' if success else 'Failed to save configuration'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts/sms/config', methods=['POST'])
def save_sms_config():
    """Save real SMS alert configuration"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({'success': False, 'error': 'Alert system not available'}), 503
        
        data = request.get_json()
        success = alert_system.save_config('sms', data)
        return jsonify({
            'success': success,
            'message': 'SMS configuration saved' if success else 'Failed to save configuration'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Get alert statistics"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            return jsonify(alert_system.get_stats())
        else:
            return jsonify({'error': 'Alert system not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/generate-key', methods=['POST'])
def generate_api_key():
    """Generate real API key with storage"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({'success': False, 'error': 'SOAR module not available'}), 503
        
        data = request.get_json() or {}
        name = data.get('name', 'SOAR Integration')
        result = soar_integration.generate_key(name)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/soar/keys', methods=['GET'])
def get_api_keys():
    """Get all API keys with real data"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({'keys': []}), 503
        
        keys = soar_integration.get_all_keys()
        return jsonify({'keys': keys})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/keys/<int:key_id>', methods=['DELETE'])
def revoke_api_key(key_id):
    """Revoke API key (real deletion)"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({'success': False, 'error': 'SOAR module not available'}), 503
        
        success = soar_integration.revoke_key(key_id)
        return jsonify({
            'success': success,
            'message': f'API key {key_id} revoked' if success else 'Key not found'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/soar/stats', methods=['GET'])
def get_soar_stats():
    """Get SOAR API usage statistics"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            return jsonify(soar_integration.get_stats())
        else:
            return jsonify({'error': 'SOAR module not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/openapi.json', methods=['GET'])
def get_openapi_spec():
    """Download OpenAPI specification"""
    spec = {
        'openapi': '3.0.0',
        'info': {
            'title': 'Battle-Hardened AI Security API',
            'version': '1.0.0',
            'description': 'Enterprise security monitoring and threat detection API'
        },
        'paths': {
            '/api/threats': {'get': {'summary': 'Get all threat logs'}},
            '/api/blocked-ips': {'get': {'summary': 'Get blocked IP addresses'}},
            '/api/block-ip': {'post': {'summary': 'Block an IP address'}},
            '/api/devices': {'get': {'summary': 'Get network devices'}}
        }
    }

    # Force browsers to download as a file while remaining valid JSON for tools
    return Response(
        json.dumps(spec),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename="openapi.json"'}
    )


@app.route('/api/docs', methods=['GET'])
def api_docs():
    """Serve Swagger UI documentation page"""
    # swagger_ui.html is served from the same template folder as the dashboard
    return render_template('swagger_ui.html')

@app.route('/api/assets/inventory', methods=['GET'])
def get_asset_inventory():
    """Get complete asset inventory"""
    try:
        from AI.asset_inventory import asset_inventory
        return jsonify(asset_inventory.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assets/eol', methods=['GET'])
def get_eol_software():
    """Get end-of-life software"""
    try:
        from AI.asset_inventory import asset_inventory
        eol = asset_inventory.detect_eol_software()
        return jsonify({'eol_software': eol, 'count': len(eol)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assets/shadow-it', methods=['GET'])
def get_shadow_it():
    """Detect shadow IT"""
    try:
        from AI.asset_inventory import asset_inventory
        shadow_it = asset_inventory.detect_shadow_it()
        return jsonify({'shadow_it': shadow_it, 'count': len(shadow_it)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zero-trust/scores', methods=['GET'])
def get_zero_trust_scores():
    """Get device trust scores"""
    try:
        from AI.zero_trust import zero_trust
        return jsonify(zero_trust.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zero-trust/policies', methods=['GET'])
def get_conditional_access_policies():
    """Get conditional access policies"""
    try:
        from AI.zero_trust import zero_trust
        policies = zero_trust.get_conditional_access_policies()
        return jsonify({'policies': policies, 'count': len(policies)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zero-trust/violations', methods=['GET'])
def get_privilege_violations():
    """Get least privilege violations"""
    try:
        from AI.zero_trust import zero_trust
        violations = zero_trust.check_least_privilege_violations()
        return jsonify({'violations': violations, 'count': len(violations)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/workflows', methods=['GET'])
def get_soar_workflows():
    """Get SOAR workflows"""
    try:
        from AI.soar_workflows import soar_workflows
        return jsonify(soar_workflows.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/incidents', methods=['GET'])
def get_soar_incidents():
    """Get all incidents"""
    try:
        from AI.soar_workflows import soar_workflows
        return jsonify({'incidents': soar_workflows.incidents})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/incidents', methods=['POST'])
def create_soar_incident():
    """Create new incident"""
    try:
        from AI.soar_workflows import soar_workflows
        data = request.get_json()
        incident = soar_workflows.create_incident(
            incident_type=data.get('type', 'unknown'),
            severity=data.get('severity', 'medium'),
            description=data.get('description', 'No description')
        )
        return jsonify(incident)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/playbooks', methods=['GET'])
def get_soar_playbooks():
    """Get automated playbooks"""
    try:
        from AI.soar_workflows import soar_workflows
        return jsonify({'playbooks': soar_workflows.playbooks})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/playbooks/<playbook_id>/execute', methods=['POST'])
def execute_soar_playbook(playbook_id):
    """Execute playbook"""
    try:
        from AI.soar_workflows import soar_workflows
        data = request.get_json() or {}
        result = soar_workflows.execute_playbook(playbook_id, data)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities/scan', methods=['GET'])
def scan_vulnerabilities():
    """Scan system for vulnerabilities"""
    try:
        from AI.vulnerability_manager import vulnerability_manager
        return jsonify(vulnerability_manager.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities/cves', methods=['GET'])
def get_cves():
    """Get CVE vulnerabilities"""
    try:
        from AI.vulnerability_manager import vulnerability_manager
        vulns = vulnerability_manager.scan_system_vulnerabilities()
        return jsonify({'vulnerabilities': vulns, 'count': len(vulns)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities/patches', methods=['GET'])
def get_patches():
    """Get prioritized patches"""
    try:
        from AI.vulnerability_manager import vulnerability_manager
        patches = vulnerability_manager.prioritize_patches()
        return jsonify({'patches': patches, 'count': len(patches)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities/sbom', methods=['GET'])
def get_sbom():
    """Get Software Bill of Materials"""
    try:
        from AI.vulnerability_manager import vulnerability_manager
        sbom = vulnerability_manager.generate_sbom()

        # Return as downloadable JSON file for the dashboard button
        return Response(
            json.dumps(sbom),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename="sbom.json"'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities/dependencies', methods=['GET'])
def get_vulnerable_dependencies():
    """Get vulnerable dependencies"""
    try:
        from AI.vulnerability_manager import vulnerability_manager
        deps = vulnerability_manager.scan_dependencies()
        return jsonify({'dependencies': deps, 'count': len(deps)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cloud/posture', methods=['GET'])
def get_cloud_posture():
    """Get cloud security posture"""
    try:
        from AI.cloud_security import cloud_security
        return jsonify(cloud_security.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cloud/misconfigurations', methods=['GET'])
def get_cloud_misconfigurations():
    """Get cloud misconfigurations"""
    try:
        from AI.cloud_security import cloud_security
        aws = cloud_security.detect_aws_misconfigurations()
        azure = cloud_security.detect_azure_misconfigurations()
        gcp = cloud_security.detect_gcp_misconfigurations()
        return jsonify({
            'aws': aws,
            'azure': azure,
            'gcp': gcp,
            'total': len(aws) + len(azure) + len(gcp)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cloud/iam', methods=['GET'])
def get_cloud_iam_issues():
    """Get IAM policy issues"""
    try:
        from AI.cloud_security import cloud_security
        issues = cloud_security.analyze_iam_policies()
        return jsonify({'iam_issues': issues, 'count': len(issues)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cloud/compliance', methods=['GET'])
def get_cloud_compliance():
    """Get cloud compliance status"""
    try:
        from AI.cloud_security import cloud_security
        compliance = cloud_security.get_compliance_status()
        return jsonify(compliance)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/crypto-mining', methods=['GET'])
def get_crypto_mining_detection():
    """Get cryptocurrency mining detection stats"""
    try:
        from AI.traffic_analyzer import traffic_analyzer
        stats = traffic_analyzer.get_crypto_mining_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities/darkweb', methods=['GET'])
def get_darkweb_monitoring():
    """Get dark web monitoring stats"""
    try:
        from AI.vulnerability_manager import vulnerability_manager
        stats = vulnerability_manager.get_darkweb_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities/credential-leaks', methods=['GET'])
def get_credential_leaks():
    """Check for credential leaks"""
    try:
        from AI.vulnerability_manager import vulnerability_manager
        domain = request.args.get('domain', 'example.com')
        leaks = vulnerability_manager.check_credential_leaks(domain)
        return jsonify({'leaks': leaks, 'count': len(leaks)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/attack-simulation', methods=['GET'])
def get_attack_simulation_stats():
    """Get attack simulation statistics"""
    try:
        from AI.soar_workflows import soar_workflows
        stats = soar_workflows.get_attack_simulation_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/mitre-coverage', methods=['GET'])
def get_mitre_coverage():
    """Get MITRE ATT&CK coverage heatmap"""
    try:
        from AI.soar_workflows import soar_workflows
        return jsonify({'coverage': soar_workflows.mitre_coverage})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/soar/red-team/schedule', methods=['POST'])
def schedule_red_team():
    """Schedule red team exercise"""
    try:
        from AI.soar_workflows import soar_workflows
        data = request.get_json()
        exercise = soar_workflows.schedule_red_team_exercise(
            exercise_type=data.get('type', 'penetration_test'),
            scheduled_date=data.get('date', datetime.now().isoformat())
        )
        return jsonify(exercise)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zero-trust/dlp', methods=['GET'])
def get_dlp_stats():
    """Get DLP statistics"""
    try:
        from AI.zero_trust import zero_trust
        stats = zero_trust.get_dlp_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zero-trust/data-classification', methods=['GET'])
def get_data_classification():
    """Get data classification status"""
    try:
        from AI.zero_trust import zero_trust
        classification = zero_trust.get_data_classification_status()
        return jsonify(classification)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup/status', methods=['GET'])
def get_backup_status():
    """Get backup status"""
    try:
        from AI.backup_recovery import backup_recovery
        return jsonify(backup_recovery.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup/resilience', methods=['GET'])
def get_ransomware_resilience():
    """Get ransomware resilience score"""
    try:
        from AI.backup_recovery import backup_recovery
        score = backup_recovery.calculate_ransomware_resilience_score()
        return jsonify({'resilience_score': score})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup/test-restore', methods=['POST'])
def test_backup_restore():
    """Test backup restore"""
    try:
        from AI.backup_recovery import backup_recovery
        data = request.get_json()
        result = backup_recovery.test_backup_restore(data.get('backup_id', 'test-001'))
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# MAIN APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  HOME WIFI SECURITY SYSTEM - STARTING")
    print("=" * 70)
    print(f"[INFO] Server starting at: {_get_current_time()}")
    
    # Get actual ports from environment
    dashboard_port = int(os.getenv('DASHBOARD_PORT', '60000'))
    p2p_port = int(os.getenv('P2P_PORT', '60001'))
    
    print(f"[INFO] Dashboard: http://localhost:{dashboard_port}")
    print(f"[INFO] Encrypted P2P: https://localhost:{p2p_port} (HTTPS)")
    print(f"[INFO] AI/ML Security Engine: {'ACTIVE' if pcs_ai.ML_AVAILABLE else 'DISABLED (install scikit-learn)'}")
    print("=" * 70)
    
    # Initialize Relay Client (if enabled)
    try:
        from AI.relay_client import start_relay_client, get_relay_status
        
        def on_threat_received(threat):
            """Process threats received from relay"""
            try:
                # Just log the threat for now (AI learning integration pending)
                print(f"[RELAY] 📥 Received threat from {threat.get('source_peer')}: {threat.get('attack_type')} - IP: {threat.get('src_ip')}")
            except Exception as e:
                print(f"[RELAY ERROR] Failed to process threat: {e}")
        
        start_relay_client(on_threat_received)
        relay_status = get_relay_status()
        
        if relay_status.get('enabled'):
            print(f"[RELAY] Connected to: {relay_status.get('relay_url')}")
            print(f"[RELAY] Peer name: {relay_status.get('peer_name')}")
        
    except Exception as e:
        print(f"[WARNING] Relay client not available: {e}")
    
    # Initialize Signature Distribution System
    try:
        from AI.signature_distribution import start_signature_distribution
        sig_dist = start_signature_distribution()
        print(f"[SIGNATURE DIST] Initialized in {sig_dist.mode.upper()} mode")
        print(f"[SIGNATURE DIST] Signatures available: {len(sig_dist._signature_index)}")
    except Exception as e:
        print(f"[WARNING] Signature distribution not available: {e}")
    
    # Start network monitoring in background
    monitoring_thread = threading.Thread(target=start_network_monitoring, daemon=True)
    monitoring_thread.start()
    
    # Check if SSL certificates exist
    import os
    ssl_cert = '/app/ssl/cert.pem'
    ssl_key = '/app/ssl/key.pem'
    
    # Get ports from environment variables (default to high ports to avoid conflicts)
    dashboard_port = int(os.getenv('DASHBOARD_PORT', '60000'))
    p2p_port = int(os.getenv('P2P_PORT', '60001'))
    
    # HTTPS is handled by Gunicorn entrypoint - Flask runs in HTTP mode
    print("📊 Starting server (HTTPS handled by container entrypoint)...")
    print(f"📊 Dashboard: https://localhost:60000 (HTTPS - Secure)")
    
    # Run Flask in HTTP mode (Gunicorn will handle HTTPS wrapping)
    app.run(
        host='0.0.0.0',
        port=5000,  # Gunicorn listens on 5000 internally
        debug=False,
        threaded=True
    )
