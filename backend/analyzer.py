"""
발신정보 신뢰도 분석 및 종합 판정 모듈
- 이메일 헤더 파싱 결과 + DNS 조회 결과를 종합 분석
- 각 발신 도메인/IP/계정 별 개별 분석
- 최종 정상/비정상 판정 및 위험도 점수 산출
"""

import re
import ipaddress


# 신뢰도 점수 가중치
SCORE_WEIGHTS = {
    'spf_pass':           +20,
    'spf_fail':           -30,
    'spf_softfail':       -10,
    'spf_none':           -10,
    'dkim_pass':          +20,
    'dkim_fail':          -25,
    'dkim_none':          -10,
    'dmarc_pass':         +15,
    'dmarc_fail':         -20,
    'dmarc_none':          -5,
    'from_domain_exists': +10,
    'from_domain_no_mx':  -15,
    'from_domain_no_dns': -40,
    'ptr_exists':         +10,
    'ptr_no_exists':      -10,
    'ptr_fcrdns':         +10,
    'reply_to_mismatch':  -20,
    'return_path_mismatch': -15,
    'msgid_domain_mismatch': -10,
    'private_ip_sending': -20,
    'no_received_headers': -15,
    'suspicious_header':  -15,
    'from_display_mismatch': -20,
}

VERDICT_THRESHOLDS = {
    'safe':       60,   # 60점 이상 = 정상
    'warning':    30,   # 30~59점 = 주의
    'suspicious': 0,    # 0~29점 = 의심
    'dangerous':  -999  # 0점 미만 = 위험
}


def calculate_trust_score(analysis_result):
    """신뢰도 점수 계산 (0~100 기준, 초기 50점에서 가감)"""
    score = 50
    reasons = []
    deductions = []
    bonuses = []

    checks = analysis_result.get('checks', {})
    
    for check_key, check_val in checks.items():
        if check_key in SCORE_WEIGHTS:
            delta = SCORE_WEIGHTS[check_key]
            score += delta
            if delta > 0:
                bonuses.append({'key': check_key, 'delta': delta, 'detail': check_val})
            else:
                deductions.append({'key': check_key, 'delta': delta, 'detail': check_val})
    
    # 0~100 범위 클램핑
    score = max(0, min(100, score))
    
    return score, bonuses, deductions


def get_verdict(score):
    """점수 기반 최종 판정"""
    if score >= VERDICT_THRESHOLDS['safe']:
        return {
            'verdict': 'SAFE',
            'label': '정상',
            'color': 'green',
            'icon': '✅',
            'description': '정상적인 메일서버에서 발송된 이메일로 판단됩니다.'
        }
    elif score >= VERDICT_THRESHOLDS['warning']:
        return {
            'verdict': 'WARNING',
            'label': '주의',
            'color': 'yellow',
            'icon': '⚠️',
            'description': '일부 발신 정보가 불확실합니다. 주의가 필요합니다.'
        }
    elif score >= VERDICT_THRESHOLDS['suspicious']:
        return {
            'verdict': 'SUSPICIOUS',
            'label': '의심',
            'color': 'orange',
            'icon': '🔶',
            'description': '발신 정보에 여러 이상 징후가 발견됩니다. 발신자를 신뢰하기 어렵습니다.'
        }
    else:
        return {
            'verdict': 'DANGEROUS',
            'label': '위험',
            'color': 'red',
            'icon': '🚨',
            'description': '비정상적인 발신 정보가 다수 감지됩니다. 스팸 또는 피싱 이메일일 가능성이 높습니다.'
        }


def analyze_domain_consistency(email_data, dns_results):
    """
    From, Reply-To, Return-Path, Message-ID, DKIM 도메인 일관성 분석
    """
    from_domain = email_data.get('from_domain', '')
    reply_to_domain = email_data.get('reply_to_domain', '')
    return_path_domain = email_data.get('return_path_domain', '')
    msgid_domain = email_data.get('message_id_domain', '')
    
    consistency = {
        'from_domain': from_domain,
        'reply_to_domain': reply_to_domain,
        'return_path_domain': return_path_domain,
        'message_id_domain': msgid_domain,
        'dkim_domains': [d.get('domain') for d in email_data.get('dkim_signatures', [])],
        'issues': [],
        'is_consistent': True
    }
    
    # Reply-To 도메인과 From 도메인 불일치
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        consistency['issues'].append({
            'type': 'reply_to_mismatch',
            'severity': 'high',
            'message': f'From 도메인({from_domain})과 Reply-To 도메인({reply_to_domain})이 다릅니다. 답장 가로채기 의심',
            'from': from_domain,
            'reply_to': reply_to_domain
        })
        consistency['is_consistent'] = False
    
    # Return-Path 도메인과 From 도메인 불일치
    if return_path_domain and from_domain and return_path_domain != from_domain:
        consistency['issues'].append({
            'type': 'return_path_mismatch',
            'severity': 'medium',
            'message': f'From 도메인({from_domain})과 Return-Path 도메인({return_path_domain})이 다릅니다.',
            'from': from_domain,
            'return_path': return_path_domain
        })
        # Return-Path 불일치는 정상인 경우도 있어 is_consistent 변경 안 함
    
    # Message-ID 도메인과 From 도메인 불일치
    if msgid_domain and from_domain and msgid_domain != from_domain:
        consistency['issues'].append({
            'type': 'msgid_domain_mismatch',
            'severity': 'low',
            'message': f'From 도메인({from_domain})과 Message-ID 도메인({msgid_domain})이 다릅니다.',
            'from': from_domain,
            'message_id': msgid_domain
        })
    
    return consistency


def analyze_sender_ip(ip, ip_dns_info, from_domain, domain_dns_info):
    """
    발신 IP 분석
    - PTR 레코드 확인
    - PTR 도메인이 From 도메인과 관련 있는지 확인
    - 사설/공인 IP 여부
    """
    result = {
        'ip': ip,
        'is_private': False,
        'is_public': False,
        'has_ptr': False,
        'ptr_hostname': None,
        'ptr_matches_from_domain': False,
        'ptr_fcrdns': False,
        'is_in_spf': False,
        'issues': [],
        'notes': []
    }
    
    if not ip_dns_info:
        return result
    
    result['is_private'] = ip_dns_info.get('is_private', False)
    result['is_public'] = ip_dns_info.get('is_public', False)
    
    if result['is_private']:
        result['issues'].append({
            'type': 'private_ip',
            'severity': 'high',
            'message': f'사설 IP({ip})에서 발송됨 - 내부망 또는 위조된 Received 헤더일 수 있음'
        })
    
    ptr_info = ip_dns_info.get('ptr_records', {})
    if ptr_info and ptr_info.get('records'):
        result['has_ptr'] = True
        result['ptr_hostname'] = ptr_info['records'][0]
        
        # PTR 호스트명과 From 도메인 연관성 확인
        if from_domain and result['ptr_hostname']:
            if from_domain in result['ptr_hostname'] or result['ptr_hostname'].endswith('.' + from_domain):
                result['ptr_matches_from_domain'] = True
                result['notes'].append(f'PTR 레코드({result["ptr_hostname"]})가 발신 도메인({from_domain})과 일치')
        
        # FCrDNS (Forward Confirmed rDNS)
        result['ptr_fcrdns'] = ip_dns_info.get('summary', {}).get('ptr_matches_forward', False)
        if result['ptr_fcrdns']:
            result['notes'].append('FCrDNS 검증 통과 (PTR ↔ A 레코드 일치)')
    else:
        if result['is_public']:
            result['issues'].append({
                'type': 'no_ptr',
                'severity': 'medium',
                'message': f'IP({ip})에 PTR 레코드 없음 - 정식 메일서버 미등록 가능성'
            })
    
    # SPF에 포함 여부 확인
    if domain_dns_info and domain_dns_info.get('spf_record'):
        spf_parsed = domain_dns_info['spf_record'].get('parsed', {})
        if spf_parsed:
            for ip4_range in spf_parsed.get('ip4_ranges', []):
                try:
                    network = ipaddress.ip_network(ip4_range, strict=False)
                    if ipaddress.ip_address(ip) in network:
                        result['is_in_spf'] = True
                        result['notes'].append(f'SPF ip4:{ip4_range} 범위에 포함됨')
                        break
                except Exception:
                    if ip == ip4_range:
                        result['is_in_spf'] = True
                        break
    
    return result


def analyze_authentication(email_data, dns_results):
    """
    이메일 인증 헤더(SPF/DKIM/DMARC) 분석
    헤더에 명시된 인증 결과 + DNS 조회 결과 교차 검증
    """
    auth_analysis = {
        'spf': {
            'status': 'none',
            'detail': 'SPF 정보 없음',
            'from_header': None,
            'dns_record': None,
            'ip_authorized': None
        },
        'dkim': {
            'status': 'none',
            'detail': 'DKIM 정보 없음',
            'signatures': [],
            'dns_records': []
        },
        'dmarc': {
            'status': 'none',
            'detail': 'DMARC 정보 없음',
            'from_header': None,
            'dns_record': None
        }
    }
    
    from_domain = email_data.get('from_domain', '')
    
    # === SPF 분석 ===
    # 헤더의 Received-SPF
    received_spf = email_data.get('received_spf', {})
    if received_spf and received_spf.get('result'):
        auth_analysis['spf']['from_header'] = received_spf
        spf_result = received_spf.get('result', '').lower()
        
        status_map = {
            'pass': 'pass',
            'fail': 'fail',
            'softfail': 'softfail',
            'neutral': 'neutral',
            'none': 'none',
            'permerror': 'error',
            'temperror': 'error'
        }
        auth_analysis['spf']['status'] = status_map.get(spf_result, spf_result)
        
        detail_map = {
            'pass': '✅ SPF 인증 통과 - 허가된 서버에서 발송',
            'fail': '❌ SPF 인증 실패 - 허가되지 않은 서버에서 발송',
            'softfail': '⚠️ SPF 소프트 실패 - 발송 서버가 SPF에 완전히 포함되지 않음',
            'neutral': '❓ SPF 중립 - 정책 없음',
            'none': '❓ SPF 없음 - SPF 레코드 없거나 확인 불가',
            'error': '⚠️ SPF 처리 오류'
        }
        auth_analysis['spf']['detail'] = detail_map.get(
            auth_analysis['spf']['status'], f'SPF: {spf_result}'
        )
    
    # Authentication-Results 헤더의 SPF
    for auth_res in email_data.get('authentication_results', []):
        if auth_res.get('spf') and auth_analysis['spf']['status'] == 'none':
            spf_val = auth_res['spf'].lower()
            auth_analysis['spf']['status'] = spf_val
            auth_analysis['spf']['from_header'] = auth_res
    
    # DNS의 SPF 레코드
    if from_domain and from_domain in dns_results.get('domains', {}):
        domain_dns = dns_results['domains'][from_domain]
        if domain_dns.get('spf_record'):
            auth_analysis['spf']['dns_record'] = domain_dns['spf_record']
            if auth_analysis['spf']['status'] == 'none':
                auth_analysis['spf']['status'] = 'dns_only'
                auth_analysis['spf']['detail'] = '📋 DNS에 SPF 레코드 존재 (헤더 검증 결과 없음)'
        else:
            if auth_analysis['spf']['status'] == 'none':
                auth_analysis['spf']['detail'] = '❌ DNS에 SPF 레코드 없음'
    
    # === DKIM 분석 ===
    dkim_sigs = email_data.get('dkim_signatures', [])
    auth_analysis['dkim']['signatures'] = dkim_sigs
    
    if dkim_sigs:
        for sig in dkim_sigs:
            domain = sig.get('domain')
            selector = sig.get('selector')
            dkim_key = f'{selector}._domainkey.{domain}' if selector and domain else None
            
            dkim_check = {
                'domain': domain,
                'selector': selector,
                'has_dns_key': False,
                'dns_info': None
            }
            
            if dkim_key and dkim_key in dns_results.get('dkim_checks', {}):
                dns_dkim = dns_results['dkim_checks'][dkim_key]
                dkim_check['has_dns_key'] = dns_dkim.get('exists', False)
                dkim_check['dns_info'] = dns_dkim
            
            auth_analysis['dkim']['dns_records'].append(dkim_check)
        
        # Authentication-Results에서 DKIM 결과
        for auth_res in email_data.get('authentication_results', []):
            if auth_res.get('dkim'):
                dkim_val = auth_res['dkim'].lower()
                status_map = {'pass': 'pass', 'fail': 'fail', 'none': 'none', 'error': 'error', 'permerror': 'error', 'temperror': 'error'}
                auth_analysis['dkim']['status'] = status_map.get(dkim_val, dkim_val)
                
                detail_map = {
                    'pass': '✅ DKIM 서명 검증 통과',
                    'fail': '❌ DKIM 서명 검증 실패',
                    'none': '❓ DKIM 서명 없음',
                    'error': '⚠️ DKIM 처리 오류'
                }
                auth_analysis['dkim']['detail'] = detail_map.get(
                    auth_analysis['dkim']['status'], f'DKIM: {dkim_val}'
                )
                break
        
        if auth_analysis['dkim']['status'] == 'none':
            # DKIM 서명은 있으나 검증 결과 헤더 없는 경우
            has_dns_keys = any(d.get('has_dns_key') for d in auth_analysis['dkim']['dns_records'])
            if has_dns_keys:
                auth_analysis['dkim']['status'] = 'dns_key_exists'
                auth_analysis['dkim']['detail'] = '📋 DKIM 서명 존재 + DNS 공개키 확인됨'
            else:
                auth_analysis['dkim']['status'] = 'no_dns_key'
                auth_analysis['dkim']['detail'] = '⚠️ DKIM 서명 존재하나 DNS 공개키 없음'
    else:
        auth_analysis['dkim']['detail'] = '❓ DKIM 서명 없음'
    
    # === DMARC 분석 ===
    for auth_res in email_data.get('authentication_results', []):
        if auth_res.get('dmarc'):
            dmarc_val = auth_res['dmarc'].lower()
            status_map = {'pass': 'pass', 'fail': 'fail', 'none': 'none'}
            auth_analysis['dmarc']['status'] = status_map.get(dmarc_val, dmarc_val)
            auth_analysis['dmarc']['from_header'] = auth_res
            
            detail_map = {
                'pass': '✅ DMARC 정책 통과',
                'fail': '❌ DMARC 정책 실패',
                'none': '❓ DMARC 정책 없음'
            }
            auth_analysis['dmarc']['detail'] = detail_map.get(
                auth_analysis['dmarc']['status'], f'DMARC: {dmarc_val}'
            )
            break
    
    # DNS의 DMARC 레코드
    if from_domain and from_domain in dns_results.get('domains', {}):
        domain_dns = dns_results['domains'][from_domain]
        if domain_dns.get('dmarc_record'):
            auth_analysis['dmarc']['dns_record'] = domain_dns['dmarc_record']
            if auth_analysis['dmarc']['status'] == 'none':
                auth_analysis['dmarc']['status'] = 'dns_only'
                auth_analysis['dmarc']['detail'] = '📋 DNS에 DMARC 레코드 존재 (헤더 검증 결과 없음)'
        else:
            if auth_analysis['dmarc']['status'] == 'none':
                auth_analysis['dmarc']['detail'] = '❌ DNS에 DMARC 레코드 없음'
    
    return auth_analysis


def perform_full_analysis(email_data, dns_results):
    """
    전체 발신정보 종합 분석
    """
    analysis = {
        'summary': {},
        'from_info': {},
        'domain_analysis': {},
        'ip_analysis': {},
        'authentication': {},
        'consistency': {},
        'routing': {},
        'checks': {},
        'score': 50,
        'verdict': {},
        'risk_factors': [],
        'trust_factors': []
    }
    
    from_domain = email_data.get('from_domain', '')
    
    # === 1. From 정보 분석 ===
    analysis['from_info'] = {
        'display_name': email_data.get('from', ''),
        'email': email_data.get('from_email', ''),
        'domain': from_domain,
        'reply_to': email_data.get('reply_to', ''),
        'return_path': email_data.get('return_path', ''),
        'x_originating_ip': email_data.get('x_originating_ip', ''),
        'x_mailer': email_data.get('x_mailer', ''),
    }
    
    # === 2. 도메인별 DNS 분석 ===
    domain_analyses = {}
    for domain, dns_info in dns_results.get('domains', {}).items():
        da = {
            'domain': domain,
            'role': [],
            'dns_exists': dns_info.get('exists', False),
            'has_a': dns_info['summary'].get('has_a', False),
            'has_mx': dns_info['summary'].get('has_mx', False),
            'has_spf': dns_info['summary'].get('has_spf', False),
            'has_dmarc': dns_info['summary'].get('has_dmarc', False),
            'is_mail_domain': dns_info['summary'].get('is_mail_domain', False),
            'a_records': dns_info.get('a_records', {}).get('records', []),
            'mx_records': dns_info.get('mx_records', {}).get('records', []),
            'spf_record': dns_info.get('spf_record'),
            'dmarc_record': dns_info.get('dmarc_record'),
            'txt_records': dns_info.get('txt_records', {}).get('records', []),
            'ns_records': dns_info.get('ns_records', {}).get('records', []),
            'issues': [],
            'notes': []
        }
        
        # 역할 판별
        if domain == from_domain:
            da['role'].append('발신 도메인 (From)')
        if domain == email_data.get('reply_to_domain'):
            da['role'].append('Reply-To 도메인')
        if domain == email_data.get('return_path_domain'):
            da['role'].append('Return-Path 도메인')
        if domain == email_data.get('message_id_domain'):
            da['role'].append('Message-ID 도메인')
        for dkim_sig in email_data.get('dkim_signatures', []):
            if dkim_sig.get('domain') == domain:
                da['role'].append('DKIM 서명 도메인')
        if not da['role']:
            da['role'].append('경유 서버 도메인')
        
        # 문제점 분석
        if not da['dns_exists']:
            da['issues'].append({
                'severity': 'critical',
                'message': '⛔ DNS 레코드 전혀 없음 - 허위/사설 도메인 강력 의심'
            })
        elif not da['has_mx'] and '발신 도메인 (From)' in da['role']:
            da['issues'].append({
                'severity': 'high',
                'message': '⚠️ MX 레코드 없음 - 메일 발신 전용 도메인이 아닐 수 있음'
            })
        
        if not da['has_spf'] and '발신 도메인 (From)' in da['role']:
            da['issues'].append({
                'severity': 'medium',
                'message': '⚠️ SPF 레코드 없음 - 이메일 인증 정책 미설정'
            })
        
        if not da['has_dmarc'] and '발신 도메인 (From)' in da['role']:
            da['issues'].append({
                'severity': 'low',
                'message': 'ℹ️ DMARC 레코드 없음 - 이메일 인증 정책 미설정'
            })
        
        if da['has_mx']:
            da['notes'].append('✅ MX 레코드 확인 - 정식 메일 도메인')
        if da['has_spf']:
            da['notes'].append('✅ SPF 레코드 확인')
        if da['has_dmarc']:
            da['notes'].append('✅ DMARC 레코드 확인')
        
        domain_analyses[domain] = da
    
    analysis['domain_analysis'] = domain_analyses
    
    # === 3. IP별 분석 ===
    ip_analyses = {}
    for ip, ip_dns_info in dns_results.get('ips', {}).items():
        from_domain_dns = dns_results.get('domains', {}).get(from_domain)
        ip_analysis = analyze_sender_ip(ip, ip_dns_info, from_domain, from_domain_dns)
        
        # 어느 Received 헤더에서 나왔는지 확인
        ip_role = []
        for recv in email_data.get('received_headers', []):
            if ip in recv.get('ips', []):
                if recv.get('is_first_hop'):
                    ip_role.append('최초 발신 서버 IP')
                else:
                    ip_role.append('경유 서버 IP')
        if email_data.get('x_originating_ip') and ip in email_data.get('x_originating_ip', ''):
            ip_role.append('X-Originating-IP')
        ip_analysis['role'] = ip_role if ip_role else ['발신 경로 IP']
        
        ip_analyses[ip] = ip_analysis
    
    analysis['ip_analysis'] = ip_analyses
    
    # === 4. 인증 분석 ===
    analysis['authentication'] = analyze_authentication(email_data, dns_results)
    
    # === 5. 도메인 일관성 분석 ===
    analysis['consistency'] = analyze_domain_consistency(email_data, dns_results)
    
    # === 6. 발신 경로(Routing) 분석 ===
    received_headers = email_data.get('received_headers', [])
    analysis['routing'] = {
        'hop_count': len(received_headers),
        'hops': received_headers,
        'first_sender': received_headers[-1] if received_headers else None,
        'issues': []
    }
    
    if not received_headers:
        analysis['routing']['issues'].append({
            'severity': 'high',
            'message': 'Received 헤더 없음 - 발신 경로 추적 불가'
        })
    
    # === 7. 종합 체크 항목 및 점수 계산 ===
    checks = {}
    
    # SPF 체크
    spf_status = analysis['authentication']['spf']['status']
    if spf_status == 'pass':
        checks['spf_pass'] = 'SPF 인증 통과'
    elif spf_status == 'fail':
        checks['spf_fail'] = 'SPF 인증 실패'
    elif spf_status in ('softfail',):
        checks['spf_softfail'] = 'SPF 소프트 실패'
    elif spf_status in ('none', ''):
        checks['spf_none'] = 'SPF 없음'
    
    # DKIM 체크
    dkim_status = analysis['authentication']['dkim']['status']
    if dkim_status == 'pass':
        checks['dkim_pass'] = 'DKIM 검증 통과'
    elif dkim_status == 'fail':
        checks['dkim_fail'] = 'DKIM 검증 실패'
    elif dkim_status in ('none',):
        checks['dkim_none'] = 'DKIM 서명 없음'
    
    # DMARC 체크
    dmarc_status = analysis['authentication']['dmarc']['status']
    if dmarc_status == 'pass':
        checks['dmarc_pass'] = 'DMARC 통과'
    elif dmarc_status == 'fail':
        checks['dmarc_fail'] = 'DMARC 실패'
    elif dmarc_status in ('none',):
        checks['dmarc_none'] = 'DMARC 없음'
    
    # From 도메인 DNS 체크
    if from_domain:
        from_dns = domain_analyses.get(from_domain, {})
        if from_dns.get('dns_exists'):
            checks['from_domain_exists'] = f'{from_domain} DNS 확인됨'
            if not from_dns.get('has_mx'):
                checks['from_domain_no_mx'] = f'{from_domain} MX 레코드 없음'
        else:
            checks['from_domain_no_dns'] = f'{from_domain} DNS 레코드 전혀 없음'
    
    # IP PTR 체크
    for ip, ip_ana in ip_analyses.items():
        if ip_ana.get('is_public'):
            if ip_ana.get('has_ptr'):
                checks['ptr_exists'] = f'{ip} PTR 레코드 확인'
                if ip_ana.get('ptr_fcrdns'):
                    checks['ptr_fcrdns'] = f'{ip} FCrDNS 검증 통과'
            else:
                checks['ptr_no_exists'] = f'{ip} PTR 레코드 없음'
            if ip_ana.get('is_private'):
                checks['private_ip_sending'] = f'사설 IP({ip}) 발송'
            break  # 첫 번째 공인 IP만 체크
    
    # 도메인 일관성 체크
    for issue in analysis['consistency']['issues']:
        issue_type = issue.get('type')
        if issue_type == 'reply_to_mismatch':
            checks['reply_to_mismatch'] = issue['message']
        elif issue_type == 'return_path_mismatch':
            checks['return_path_mismatch'] = issue['message']
        elif issue_type == 'msgid_domain_mismatch':
            checks['msgid_domain_mismatch'] = issue['message']
    
    # Received 헤더 없음 체크
    if not received_headers:
        checks['no_received_headers'] = 'Received 헤더 없음'
    
    analysis['checks'] = checks
    
    # === 8. 최종 점수 및 판정 ===
    score, bonuses, deductions = calculate_trust_score(analysis)
    analysis['score'] = score
    analysis['score_breakdown'] = {
        'base': 50,
        'bonuses': bonuses,
        'deductions': deductions,
        'final': score
    }
    analysis['verdict'] = get_verdict(score)
    
    # === 9. 위험/신뢰 요인 정리 ===
    for item in deductions:
        analysis['risk_factors'].append({
            'key': item['key'],
            'delta': item['delta'],
            'detail': item['detail']
        })
    
    for item in bonuses:
        analysis['trust_factors'].append({
            'key': item['key'],
            'delta': item['delta'],
            'detail': item['detail']
        })
    
    # === 10. 요약 ===
    analysis['summary'] = {
        'from': email_data.get('from', ''),
        'from_email': email_data.get('from_email', ''),
        'from_domain': from_domain,
        'subject': email_data.get('subject', ''),
        'date': email_data.get('date', ''),
        'total_domains_analyzed': len(domain_analyses),
        'total_ips_analyzed': len(ip_analyses),
        'hop_count': len(received_headers),
        'score': score,
        'verdict': analysis['verdict']['verdict'],
        'verdict_label': analysis['verdict']['label'],
        'has_spf': spf_status == 'pass',
        'has_dkim': dkim_status in ('pass', 'dns_key_exists'),
        'has_dmarc': dmarc_status in ('pass', 'dns_only'),
        'risk_count': len(analysis['risk_factors']),
        'trust_count': len(analysis['trust_factors'])
    }
    
    return analysis
