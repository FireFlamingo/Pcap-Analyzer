"""
PCAP Analyzer — Flask Web Server
"""

import os
import uuid
import json
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from analyzer import analyze_pcap

app = Flask(__name__, static_folder='static')
CORS(app)

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
CARVED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'carved')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CARVED_DIR, exist_ok=True)

# In-memory store for analysis results
_analyses = {}


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)


@app.route('/api/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Empty filename'}), 400

    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ('.pcap', '.pcapng', '.cap'):
        return jsonify({'error': 'Invalid file type. Upload .pcap, .pcapng, or .cap files.'}), 400

    analysis_id = str(uuid.uuid4())[:8]
    save_path = os.path.join(UPLOAD_DIR, f'{analysis_id}{ext}')
    f.save(save_path)

    # Run analysis
    carved_output = os.path.join(CARVED_DIR, analysis_id)
    os.makedirs(carved_output, exist_ok=True)

    try:
        results = analyze_pcap(save_path, carved_output)
        results['id'] = analysis_id
        results['filename'] = f.filename
        _analyses[analysis_id] = results
        return jsonify({'id': analysis_id, 'status': 'complete', 'results': results})
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/api/results/<analysis_id>')
def get_results(analysis_id):
    if analysis_id not in _analyses:
        return jsonify({'error': 'Analysis not found'}), 404
    return jsonify(_analyses[analysis_id])


@app.route('/api/files/<analysis_id>/<filename>')
def download_carved(analysis_id, filename):
    carved_path = os.path.join(CARVED_DIR, analysis_id)
    filepath = os.path.join(carved_path, filename)
    if not os.path.isfile(filepath):
        return jsonify({'error': 'File not found'}), 404
    return send_file(filepath, as_attachment=True, download_name=filename)


if __name__ == '__main__':
    print("\n  ╔══════════════════════════════════════════╗")
    print("  ║   PCAP Analyzer for CTF Challenges       ║")
    print("  ║   http://localhost:5001                 ║")
    print("  ╚══════════════════════════════════════════╝\n")
    app.run(host='0.0.0.0', port=5001, debug=True)
