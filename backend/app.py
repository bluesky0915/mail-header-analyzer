"""
발신정보 분석기 - Flask API 서버
"""

import os
import json
import csv
import time
import traceback
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from email_parser import parse_header_text, parse_eml_bytes
from dns_analyzer import analyze_all_dns
from analyzer import perform_full_analysis

app = Flask(__name__, static_folder='../frontend/public', static_url_path='')
CORS(app)

UPLOAD_MAX_SIZE = 1 * 1024 * 1024  # 1MB

# 사용자 정보 저장 경로
USER_LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'users.csv')
os.makedirs(os.path.dirname(USER_LOG_PATH), exist_ok=True)


def save_user_info(user_data: dict):
    """사용자 정보를 CSV에 저장"""
    fieldnames = ['timestamp', 'name', 'company', 'email', 'phone', 'agree_marketing', 'ip']
    file_exists = os.path.isfile(USER_LOG_PATH)
    try:
        with open(USER_LOG_PATH, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow({
                'timestamp':       datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'name':            user_data.get('name', ''),
                'company':         user_data.get('company', ''),
                'email':           user_data.get('email', ''),
                'phone':           user_data.get('phone', ''),
                'agree_marketing': str(user_data.get('agreeMarketing', False)),
                'ip':              request.remote_addr or ''
            })
    except Exception as e:
        print(f"[사용자 저장 오류] {e}")


@app.route('/')
def index():
    return send_from_directory('../frontend/public', 'index.html')


@app.route('/api/user', methods=['POST'])
def save_user():
    """사용자 정보 저장 API"""
    try:
        data = request.get_json(force=True) or {}
        if not data.get('name') or not data.get('email'):
            return jsonify({'error': '필수 항목 누락'}), 400
        save_user_info(data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """
    이메일 분석 API
    - multipart/form-data: file (EML 파일) 또는 text (헤더 텍스트)
    """
    start_time = time.time()
    
    try:
        email_data = None
        input_type = None
        
        # EML 파일 업로드
        if 'file' in request.files:
            f = request.files['file']
            if not f or f.filename == '':
                return jsonify({'error': '파일이 없습니다.'}), 400
            
            filename = f.filename.lower()
            if not (filename.endswith('.eml') or filename.endswith('.txt') or filename.endswith('.msg')):
                return jsonify({'error': '.eml, .txt, .msg 파일만 지원합니다.'}), 400
            
            file_bytes = f.read()
            if len(file_bytes) > UPLOAD_MAX_SIZE:
                return jsonify({'error': '파일 크기가 너무 큽니다. (최대 1MB)'}), 400
            
            email_data = parse_eml_bytes(file_bytes)
            input_type = 'eml_file'
        
        # 텍스트 헤더 입력
        elif 'text' in request.form:
            header_text = request.form['text']
            if not header_text or not header_text.strip():
                return jsonify({'error': '헤더 텍스트가 없습니다.'}), 400
            
            email_data = parse_header_text(header_text)
            input_type = 'header_text'
        
        # JSON body
        elif request.is_json:
            body = request.get_json()
            header_text = body.get('text', '')
            if not header_text:
                return jsonify({'error': '헤더 텍스트가 없습니다.'}), 400
            email_data = parse_header_text(header_text)
            input_type = 'header_text'
        
        else:
            return jsonify({'error': '파일 또는 텍스트를 제공해 주세요.'}), 400
        
        if not email_data:
            return jsonify({'error': '이메일 파싱 실패'}), 500
        
        # DNS 분석
        dns_results = analyze_all_dns(email_data)
        
        # 종합 분석
        analysis = perform_full_analysis(email_data, dns_results)
        
        elapsed = round(time.time() - start_time, 2)
        
        return jsonify({
            'success': True,
            'input_type': input_type,
            'elapsed_seconds': elapsed,
            'email_data': email_data,
            'dns_results': dns_results,
            'analysis': analysis
        })
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'error': f'분석 중 오류 발생: {str(e)}',
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': '발신정보 분석기'})


@app.route('/api/sample', methods=['GET'])
def get_sample():
    """샘플 이메일 헤더 반환"""
    sample = """From: "홍길동" <info@legitimate-company.com>
To: recipient@example.com
Subject: 중요 공지사항
Date: Tue, 25 Feb 2025 10:30:00 +0900
Message-ID: <20250225103000.12345@legitimate-company.com>
Return-Path: <info@legitimate-company.com>
Received: from mail.legitimate-company.com (mail.legitimate-company.com [203.0.113.10])
        by mx.recipient.com with ESMTPS id abc123
        for <recipient@example.com>; Tue, 25 Feb 2025 10:30:00 +0900
Received: from localhost (localhost [127.0.0.1])
        by mail.legitimate-company.com with ESMTP id def456
        Tue, 25 Feb 2025 10:29:58 +0900
Received-SPF: pass (mx.recipient.com: domain of info@legitimate-company.com designates 203.0.113.10 as permitted sender) client-ip=203.0.113.10; envelope-from="info@legitimate-company.com"; helo=mail.legitimate-company.com;
Authentication-Results: mx.recipient.com;
       dkim=pass header.i=@legitimate-company.com header.s=mail header.b=AbCdEfGh;
       spf=pass (mx.recipient.com: domain of info@legitimate-company.com designates 203.0.113.10 as permitted sender) smtp.mailfrom=info@legitimate-company.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=legitimate-company.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=legitimate-company.com; s=mail;
        h=from:to:subject:date:message-id;
        bh=abc123==;
        b=AbCdEfGhIjKlMnOpQrStUvWxYz==
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
X-Mailer: Microsoft Outlook 16.0"""
    return jsonify({'sample': sample})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"발신정보 분석기 서버 시작 - http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
