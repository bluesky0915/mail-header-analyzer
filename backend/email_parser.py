"""
이메일 헤더/EML 파일 파싱 엔진
- EML 파일 및 텍스트 헤더 모두 지원
- 발신측 도메인, IP, 계정 등 모든 발신 정보 추출
"""

import email
import email.policy
import re
import chardet
from email import message_from_bytes, message_from_string
from email.header import decode_header, make_header
from datetime import datetime
from dateutil import parser as date_parser


def decode_mime_words(s):
    """MIME 인코딩된 헤더 문자열 디코딩"""
    if not s:
        return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def extract_email_address(value):
    """이메일 주소 추출"""
    if not value:
        return None
    pattern = r'[\w\.\+\-]+@[\w\.\-]+'
    matches = re.findall(pattern, value)
    return matches[0] if matches else None


def extract_domain_from_email(email_addr):
    """이메일 주소에서 도메인 추출"""
    if not email_addr:
        return None
    if '@' in email_addr:
        return email_addr.split('@')[-1].strip().lower().rstrip('>')
    return None


def extract_ips_from_received(received_value):
    """Received 헤더에서 IP 주소 추출"""
    ips = []
    # IPv4 패턴
    ipv4_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    # IPv6 패턴
    ipv6_pattern = r'\[([0-9a-fA-F:]+)\]'
    
    ipv4_matches = re.findall(ipv4_pattern, received_value)
    ipv6_matches = re.findall(ipv6_pattern, received_value)
    
    for ip in ipv4_matches:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            ips.append(ip)
    
    for ip in ipv6_matches:
        if ':' in ip and ip not in ips:
            ips.append(ip)
    
    return list(dict.fromkeys(ips))  # 중복 제거


def is_private_ip(ip):
    """사설/로컬 IP 여부 확인"""
    private_ranges = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^::1$',
        r'^fc00:',
        r'^fe80:',
        r'^0\.0\.0\.0$',
    ]
    for pattern in private_ranges:
        if re.match(pattern, ip):
            return True
    return False


def extract_domain_from_received(received_value):
    """Received 헤더에서 도메인명 추출"""
    domains = []
    
    # from 절에서 도메인 추출
    from_match = re.search(r'from\s+([\w\.\-]+)', received_value, re.IGNORECASE)
    if from_match:
        host = from_match.group(1)
        if '.' in host and not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            domains.append(host.lower())
    
    # by 절에서 도메인 추출
    by_match = re.search(r'by\s+([\w\.\-]+)', received_value, re.IGNORECASE)
    if by_match:
        host = by_match.group(1)
        if '.' in host and not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            domains.append(host.lower())
    
    return domains


def extract_domains_from_text(text):
    """텍스트에서 도메인 추출 (일반적인 패턴)"""
    domain_pattern = r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    matches = re.findall(domain_pattern, text)
    
    # 이메일 도메인이나 특정 패턴에서만 추출
    email_domain_pattern = r'@([\w\.\-]+\.[a-zA-Z]{2,})'
    email_domains = re.findall(email_domain_pattern, text)
    
    return list(set(email_domains))


def parse_authentication_results(auth_header):
    """Authentication-Results 헤더 파싱"""
    result = {
        'spf': None,
        'dkim': None,
        'dmarc': None,
        'raw': auth_header
    }
    
    if not auth_header:
        return result
    
    # SPF 결과
    spf_match = re.search(r'spf=(\w+)', auth_header, re.IGNORECASE)
    if spf_match:
        result['spf'] = spf_match.group(1).lower()
    
    # DKIM 결과
    dkim_match = re.search(r'dkim=(\w+)', auth_header, re.IGNORECASE)
    if dkim_match:
        result['dkim'] = dkim_match.group(1).lower()
    
    # DMARC 결과
    dmarc_match = re.search(r'dmarc=(\w+)', auth_header, re.IGNORECASE)
    if dmarc_match:
        result['dmarc'] = dmarc_match.group(1).lower()
    
    return result


def parse_received_spf(spf_header):
    """Received-SPF 헤더 파싱"""
    if not spf_header:
        return None
    
    result = {'raw': spf_header, 'result': None, 'domain': None, 'ip': None}
    
    # 결과값 추출
    result_match = re.match(r'^\s*(\w+)', spf_header)
    if result_match:
        result['result'] = result_match.group(1).lower()
    
    # 도메인 추출
    domain_match = re.search(r'domain(?:\s+of)?\s+([\w\.\-]+)', spf_header, re.IGNORECASE)
    if domain_match:
        result['domain'] = domain_match.group(1).lower()
    
    # IP 추출
    ip_match = re.search(r'client-ip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', spf_header)
    if ip_match:
        result['ip'] = ip_match.group(1)
    
    return result


def parse_dkim_signature(dkim_header):
    """DKIM-Signature 헤더 파싱"""
    if not dkim_header:
        return None
    
    result = {'raw': dkim_header, 'domain': None, 'selector': None, 'algorithm': None}
    
    # 도메인 추출 (d= 태그)
    d_match = re.search(r'\bd=([\w\.\-]+)', dkim_header)
    if d_match:
        result['domain'] = d_match.group(1).lower()
    
    # 셀렉터 추출 (s= 태그)
    s_match = re.search(r'\bs=([\w\.\-]+)', dkim_header)
    if s_match:
        result['selector'] = s_match.group(1)
    
    # 알고리즘 추출 (a= 태그)
    a_match = re.search(r'\ba=([\w\-]+)', dkim_header)
    if a_match:
        result['algorithm'] = a_match.group(1)
    
    return result


def parse_email_content(content, is_eml=False):
    """
    이메일 내용 파싱 메인 함수
    - content: 파일 바이너리 또는 텍스트 문자열
    - is_eml: EML 파일 여부
    """
    
    parsed = {
        # 기본 헤더 정보
        'from': None,
        'from_domain': None,
        'from_email': None,
        'to': None,
        'cc': None,
        'reply_to': None,
        'reply_to_domain': None,
        'subject': None,
        'date': None,
        'message_id': None,
        'message_id_domain': None,
        
        # 발신 서버 정보
        'received_headers': [],       # 모든 Received 헤더
        'sender_ips': [],             # 발신 측 IP 목록
        'relay_ips': [],              # 중계 서버 IP 목록
        'sender_domains': [],         # 발신 측 도메인 목록
        'relay_domains': [],          # 중계 도메인 목록
        
        # 인증 헤더
        'authentication_results': [],
        'received_spf': None,
        'dkim_signatures': [],
        
        # 기타 발신 관련 헤더
        'x_originating_ip': None,
        'x_mailer': None,
        'x_sender': None,
        'return_path': None,
        'return_path_domain': None,
        'mime_version': None,
        'content_type': None,
        
        # 추출된 모든 도메인 목록 (중복 제거)
        'all_sender_domains': [],
        'all_ips': [],
        
        # 원본 헤더 (텍스트)
        'raw_headers': '',
        
        # 파싱 오류
        'parse_errors': []
    }
    
    try:
        # EML 파일이거나 바이너리인 경우
        if is_eml or isinstance(content, bytes):
            if isinstance(content, bytes):
                # 인코딩 감지
                detected = chardet.detect(content)
                encoding = detected.get('encoding', 'utf-8') or 'utf-8'
                try:
                    text_content = content.decode(encoding)
                except Exception:
                    text_content = content.decode('latin-1')
                msg = message_from_string(text_content)
            else:
                msg = message_from_string(content)
        else:
            # 텍스트 헤더인 경우
            # 헤더만 있는 경우와 전체 메일인 경우 모두 처리
            msg = message_from_string(content)
        
        # 원본 헤더 저장
        parsed['raw_headers'] = str(msg)
        
        # === 기본 헤더 파싱 ===
        
        # From
        from_raw = msg.get('From', '')
        parsed['from'] = decode_mime_words(from_raw)
        parsed['from_email'] = extract_email_address(from_raw)
        parsed['from_domain'] = extract_domain_from_email(parsed['from_email'])
        
        # To
        parsed['to'] = decode_mime_words(msg.get('To', ''))
        
        # CC
        parsed['cc'] = decode_mime_words(msg.get('CC', '') or msg.get('Cc', ''))
        
        # Reply-To
        reply_to_raw = msg.get('Reply-To', '')
        parsed['reply_to'] = decode_mime_words(reply_to_raw)
        reply_to_email = extract_email_address(reply_to_raw)
        parsed['reply_to_domain'] = extract_domain_from_email(reply_to_email)
        
        # Subject
        parsed['subject'] = decode_mime_words(msg.get('Subject', ''))
        
        # Date
        date_raw = msg.get('Date', '')
        parsed['date'] = date_raw
        try:
            if date_raw:
                parsed['date_parsed'] = date_parser.parse(date_raw).isoformat()
        except Exception:
            parsed['date_parsed'] = None
        
        # Message-ID
        msg_id = msg.get('Message-ID', '') or msg.get('Message-Id', '')
        parsed['message_id'] = msg_id
        # Message-ID 도메인 추출
        mid_domain_match = re.search(r'@([\w\.\-]+)>', msg_id)
        if mid_domain_match:
            parsed['message_id_domain'] = mid_domain_match.group(1).lower()
        
        # Return-Path
        return_path_raw = msg.get('Return-Path', '')
        parsed['return_path'] = return_path_raw
        rp_email = extract_email_address(return_path_raw)
        parsed['return_path_domain'] = extract_domain_from_email(rp_email)
        
        # X-Originating-IP
        parsed['x_originating_ip'] = msg.get('X-Originating-IP', '') or msg.get('X-Original-IP', '')
        
        # X-Mailer
        parsed['x_mailer'] = msg.get('X-Mailer', '')
        
        # X-Sender
        parsed['x_sender'] = msg.get('X-Sender', '') or msg.get('Sender', '')
        
        # MIME-Version
        parsed['mime_version'] = msg.get('MIME-Version', '')
        
        # Content-Type
        parsed['content_type'] = msg.get('Content-Type', '')
        
        # === Received 헤더 파싱 (발신 경로 추적) ===
        received_list = msg.get_all('Received') or []
        
        all_sender_ips = []
        all_sender_domains = []
        
        for idx, received in enumerate(received_list):
            received_info = {
                'index': idx,
                'raw': received,
                'ips': [],
                'domains': [],
                'from_host': None,
                'by_host': None,
                'timestamp': None,
                'is_first_hop': (idx == len(received_list) - 1)  # 가장 마지막이 첫 번째 수신
            }
            
            # IP 추출
            ips = extract_ips_from_received(received)
            received_info['ips'] = ips
            
            # 도메인 추출
            domains = extract_domain_from_received(received)
            received_info['domains'] = domains
            
            # from 호스트명
            from_match = re.search(r'from\s+([\w\.\-\[\]]+)', received, re.IGNORECASE)
            if from_match:
                received_info['from_host'] = from_match.group(1)
            
            # by 호스트명
            by_match = re.search(r'by\s+([\w\.\-\[\]]+)', received, re.IGNORECASE)
            if by_match:
                received_info['by_host'] = by_match.group(1)
            
            # 타임스탬프
            time_match = re.search(r';\s*(.+)$', received.strip())
            if time_match:
                received_info['timestamp'] = time_match.group(1).strip()
            
            parsed['received_headers'].append(received_info)
            
            # 첫 번째 hop (발신 서버)의 IP를 sender_ips에
            if received_info['is_first_hop']:
                for ip in ips:
                    if not is_private_ip(ip):
                        all_sender_ips.append(ip)
                    else:
                        all_sender_ips.append(ip)
                all_sender_domains.extend(domains)
            else:
                for ip in ips:
                    if ip not in parsed['relay_ips']:
                        parsed['relay_ips'].append(ip)
        
        parsed['sender_ips'] = list(dict.fromkeys(all_sender_ips))
        parsed['sender_domains'] = list(dict.fromkeys(all_sender_domains))
        
        # === Authentication-Results 헤더 (복수 가능) ===
        auth_results_list = msg.get_all('Authentication-Results') or []
        for auth_raw in auth_results_list:
            parsed['authentication_results'].append(
                parse_authentication_results(auth_raw)
            )
        
        # === Received-SPF ===
        spf_raw = msg.get('Received-SPF', '')
        parsed['received_spf'] = parse_received_spf(spf_raw)
        
        # === DKIM-Signature (복수 가능) ===
        dkim_list = msg.get_all('DKIM-Signature') or []
        for dkim_raw in dkim_list:
            sig = parse_dkim_signature(dkim_raw)
            if sig:
                parsed['dkim_signatures'].append(sig)
        
        # === 모든 도메인 통합 수집 ===
        all_domains = set()
        
        # From 도메인
        if parsed['from_domain']:
            all_domains.add(parsed['from_domain'])
        
        # Reply-To 도메인
        if parsed['reply_to_domain']:
            all_domains.add(parsed['reply_to_domain'])
        
        # Return-Path 도메인
        if parsed['return_path_domain']:
            all_domains.add(parsed['return_path_domain'])
        
        # Message-ID 도메인
        if parsed['message_id_domain']:
            all_domains.add(parsed['message_id_domain'])
        
        # Received 헤더의 도메인
        for recv in parsed['received_headers']:
            for d in recv['domains']:
                all_domains.add(d)
        
        # DKIM 도메인
        for dkim in parsed['dkim_signatures']:
            if dkim.get('domain'):
                all_domains.add(dkim['domain'])
        
        # SPF 도메인
        if parsed['received_spf'] and parsed['received_spf'].get('domain'):
            all_domains.add(parsed['received_spf']['domain'])
        
        # X-Sender 도메인
        if parsed['x_sender']:
            x_email = extract_email_address(parsed['x_sender'])
            x_domain = extract_domain_from_email(x_email)
            if x_domain:
                all_domains.add(x_domain)
        
        # X-Originating-IP에서 도메인 (없으면 IP만)
        if parsed['x_originating_ip']:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', parsed['x_originating_ip'])
            if ip_match:
                all_sender_ips.append(ip_match.group(1))
        
        # 유효한 도메인만 필터링 (최소 2개 이상의 레이블, TLD 2글자 이상)
        def is_valid_domain(d):
            if not d or '.' not in d:
                return False
            parts = d.split('.')
            if len(parts) < 2:
                return False
            # TLD가 2자 이상이어야 함
            if len(parts[-1]) < 2:
                return False
            # 숫자로만 이루어진 TLD 제외 (순수 IP 형태)
            if parts[-1].isdigit():
                return False
            return True
        
        parsed['all_sender_domains'] = [d for d in all_domains if is_valid_domain(d)]
        
        # 모든 IP 수집
        all_ips = set()
        for ip in parsed['sender_ips']:
            all_ips.add(ip)
        for recv in parsed['received_headers']:
            for ip in recv['ips']:
                all_ips.add(ip)
        if parsed['x_originating_ip']:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', parsed['x_originating_ip'])
            if ip_match:
                all_ips.add(ip_match.group(1))
        
        parsed['all_ips'] = [ip for ip in all_ips if ip]
        
    except Exception as e:
        parsed['parse_errors'].append(str(e))
    
    return parsed


def parse_header_text(text):
    """순수 텍스트 헤더 파싱 (헤더만 있는 경우)"""
    # 헤더 텍스트가 Body가 없는 경우 처리
    # 빈 줄이 없으면 헤더 전용으로 간주
    if '\n\n' not in text and '\r\n\r\n' not in text:
        text = text + '\n\n'
    return parse_email_content(text, is_eml=False)


def parse_eml_bytes(file_bytes):
    """EML 파일 바이트 파싱"""
    return parse_email_content(file_bytes, is_eml=True)
