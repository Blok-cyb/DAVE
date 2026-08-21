from flask import Blueprint, request, jsonify, send_file
import os
import sqlite3
import csv
from datetime import datetime
from file_monitor import ActivityMonitor

activity = Blueprint('activity', __name__)
BASE = os.path.dirname(os.path.dirname(__file__))
DATABASE = os.path.join(BASE, 'database.db')
monitor = ActivityMonitor(DATABASE)

def default_folder():
    home = os.path.expanduser('~')
    docs = os.path.join(home, 'Documents')
    return docs if os.path.isdir(docs) else home

@activity.get('/activity/status')
def status(): return jsonify(success=True, **monitor.snapshot())

@activity.post('/activity/start')
def start():
    data = request.get_json(silent=True) or {}
    folder = data.get('folder') or default_folder()
    try:
        monitor.start(folder)
        return jsonify(success=True, message='Real-time file activity monitoring started.', **monitor.snapshot())
    except ValueError as e: return jsonify(success=False, message=str(e)), 400
    except Exception as e: return jsonify(success=False, message=f'Unable to start monitor: {e}'), 500

@activity.post('/activity/stop')
def stop():
    monitor.stop(); return jsonify(success=True, message='File activity monitoring stopped.', **monitor.snapshot())

@activity.post('/activity/clear')
def clear():
    monitor.clear_live()
    return jsonify(success=True, message='Live activity view cleared.', **monitor.snapshot())

@activity.get('/activity/events')
def events(): return jsonify(success=True, **monitor.snapshot())

@activity.get('/activity/export.csv')
def export_csv():
    """Export the CURRENT live monitoring session, never stale database demo rows."""
    out = os.path.join(BASE, 'uploads', 'file_activity_live.csv')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    snap = monitor.snapshot()
    with open(out, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow(['Time','Activity','Filename','Extension','Process','Path','Old Path','Status','Score','Reasons'])
        for e in snap['events']:
            w.writerow([e.get('time',''), e.get('activity',''), e.get('filename',''), e.get('extension',''),
                        e.get('process',''), e.get('path',''), e.get('old_path',''), e.get('status',''),
                        e.get('score',0), '; '.join(e.get('reasons',[]))])
    return send_file(out, as_attachment=True, download_name='file_activity_live.csv', mimetype='text/csv')

@activity.get('/activity/export.pdf')
def export_pdf():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        return jsonify(success=False, message='reportlab is not installed. Run: python -m pip install reportlab'), 500

    snap = monitor.snapshot()
    out = os.path.join(BASE, 'uploads', 'file_activity_live_report.pdf')
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=32, leftMargin=32, topMargin=32, bottomMargin=32)
    styles = getSampleStyleSheet(); story = []
    story += [Paragraph('Real-Time File Activity Monitoring Report', styles['Title']),
              Paragraph('Malware Detection Using File Activity', styles['Heading2']), Spacer(1, 10)]
    f = snap['features']
    rows = [
        ['Monitoring folder', snap['folder'] or 'Not selected'],
        ['Session started', snap.get('session_started') or 'Not started'],
        ['Monitoring status', 'ACTIVE' if snap['running'] else 'STOPPED'],
        ['Events in 10-second window', f['total_events']],
        ['Write count', f['write_count']], ['Delete count', f['delete_count']],
        ['Create count', f['create_count']], ['Rename count', f['rename_count']],
        ['Write entropy', f['write_entropy']], ['Extension diversity', f['ext_diversity']],
        ['Sensitive path access', f['sensitive_path_access']],
        ['Read/write ratio', f['read_write_ratio']],
        ['Ratio note', f.get('read_write_ratio_note','')],
        ['Behaviour score', f['score']], ['Assessment', f['status']],
        ['Reasons', '; '.join(f['reasons'])]
    ]
    t = Table([['Metric','Result']] + rows, colWidths=[190,330])
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#163b6d')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
                           ('GRID',(0,0),(-1,-1),0.5,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('PADDING',(0,0),(-1,-1),6)]))
    story += [t, Spacer(1,16), Paragraph('Recent Live Events', styles['Heading2'])]
    er = [['Time','Activity','Filename','Process','Status','Score']] + [[e.get('time',''),e.get('activity',''),e.get('filename',''),e.get('process',''),e.get('status',''),e.get('score',0)] for e in snap['events'][:80]]
    if len(er) == 1:
        er.append(['-','No events','-','-','-','-'])
    et = Table(er, repeatRows=1, colWidths=[78,62,120,90,62,42])
    et.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#163b6d')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
                             ('GRID',(0,0),(-1,-1),0.3,colors.grey),('FONTSIZE',(0,0),(-1,-1),7),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story += [et, Spacer(1,12), Paragraph('Generated: '+datetime.now().strftime('%Y-%m-%d %H:%M:%S'), styles['BodyText']),
              Paragraph('Note: Watchdog reports file-system changes, not ordinary file reads. Suspicious/Warning is a behavioural indicator, not proof that a file is malware.', styles['BodyText'])]
    doc.build(story)
    return send_file(out, as_attachment=True, download_name='file_activity_live_report.pdf', mimetype='application/pdf')
