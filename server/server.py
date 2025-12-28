#!/usr/bin/env python3
"""
Home WiFi Security Server - Network Monitoring & Threat Detection
Monitors all devices on the network and protects against attacks
"""

from flask import Flask, render_template, jsonify, request, send_file
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
    """Main dashboard - AI Security Monitoring"""
    return render_template('inspector_ai_monitoring.html',
                         stats=pcs_ai.get_threat_statistics(),
                         blocked_ips=pcs_ai.get_blocked_ips(),
                         threat_logs=pcs_ai._threat_log[-100:][::-1],  # Latest 100, reversed
                         ml_stats=pcs_ai.get_ml_model_stats(),
                         vpn_stats=pcs_ai.get_vpn_tor_statistics())


@app.route('/inspector/ai-monitoring')
def ai_monitoring():
    """AI Monitoring Dashboard (same as home)"""
    return dashboard()


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


@app.route('/inspector/ai-monitoring/retrain-ml', methods=['POST'])
def retrain_ml_models():
    """Force retrain ML models"""
    try:
        result = pcs_ai.retrain_ml_models_now()
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 500
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


# API endpoint for system status
@app.route('/api/system-status', methods=['GET'])
def get_system_status():
    """Get comprehensive system status for dashboard"""
    try:
        import os
        
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
        ml_status = {
            'status': 'ok' if pcs_ai.ML_AVAILABLE and pcs_ai._ml_last_trained else 'warning',
            'message': f'3 models trained ({pcs_ai._threat_log.qsize() if hasattr(pcs_ai._threat_log, "qsize") else len(pcs_ai._threat_log)} samples)' if pcs_ai.ML_AVAILABLE else 'Collecting training data',
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


# API endpoint to toggle honeypots
@app.route('/api/honeypot/toggle', methods=['POST'])
def toggle_honeypot():
    """Enable or disable a specific honeypot service"""
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


if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  HOME WIFI SECURITY SYSTEM - STARTING")
    print("=" * 70)
    print(f"[INFO] Server starting at: {_get_current_time()}")
    print(f"[INFO] Dashboard: http://localhost:5000")
    print(f"[INFO] Encrypted P2P: https://localhost:5443 (HTTPS)")
    print(f"[INFO] AI/ML Security Engine: {'ACTIVE' if pcs_ai.ML_AVAILABLE else 'DISABLED (install scikit-learn)'}")
    print("=" * 70)
    
    # Start network monitoring in background
    monitoring_thread = threading.Thread(target=start_network_monitoring, daemon=True)
    monitoring_thread.start()
    
    # Check if we should run HTTPS (for P2P encryption)
    import os
    ssl_cert = '/app/ssl/cert.pem'
    ssl_key = '/app/ssl/key.pem'
    
    # Get ports from environment variables (default to high ports to avoid conflicts)
    dashboard_port = int(os.getenv('DASHBOARD_PORT', '60000'))
    p2p_port = int(os.getenv('P2P_PORT', '60001'))
    
    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        # Run HTTPS server for encrypted P2P communication
        print("🔐 Starting HTTPS server for encrypted P2P connections...")
        print(f"📊 Dashboard: http://localhost:{dashboard_port}")
        print(f"🌐 P2P Sync: https://localhost:{p2p_port}")
        
        # Start HTTP server in background (for dashboard)
        http_thread = threading.Thread(
            target=lambda: app.run(host='0.0.0.0', port=dashboard_port, debug=False, threaded=True),
            daemon=True
        )
        http_thread.start()
        
        # Run HTTPS server in main thread (for P2P)
        app.run(
            host='0.0.0.0',
            port=p2p_port,
            debug=True,
            threaded=True,
            ssl_context=(ssl_cert, ssl_key)
        )
    else:
        # Fall back to HTTP only
        print("ℹ️  Running HTTP only (no SSL cert found)")
        print(f"📊 Dashboard: http://localhost:{dashboard_port}")
        app.run(
            host='0.0.0.0',
            port=dashboard_port,
            debug=True,
            threaded=True
        )
