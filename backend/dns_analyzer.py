"""
DNS 조회 모듈
- Google DNS(8.8.8.8)를 통한 A, MX, TXT, SPF, PTR 레코드 조회
- 도메인 및 IP에 대한 DNS 정보 수집
- 발신 정보와 DNS 정보 비교 분석
"""

import dns.resolver
import dns.reversename
import dns.exception
import re
import socket
import time


# Google Public DNS 사용
DNS_SERVER = '8.8.8.8'

def get_resolver():
    """Google DNS(8.8.8.8)를 사용하는 Resolver 생성"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [DNS_SERVER]
    resolver.timeout = 5
    resolver.lifetime = 10
    return resolver


def query_dns(domain, record_type, resolver=None):
    """
    DNS 레코드 조회
    Returns: {'records': [...], 'error': None or str, 'ttl': int}
    """
    if resolver is None:
        resolver = get_resolver()
    
    result = {
        'type': record_type,
        'domain': domain,
        'records': [],
        'ttl': None,
        'error': None,
        'queried': True
    }
    
    try:
        answers = resolver.resolve(domain, record_type)
        result['ttl'] = answers.rrset.ttl
        
        for rdata in answers:
            if record_type == 'A':
                result['records'].append(str(rdata))
            elif record_type == 'AAAA':
                result['records'].append(str(rdata))
            elif record_type == 'MX':
                result['records'].append({
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange).rstrip('.')
                })
            elif record_type == 'TXT':
                txt_val = b''.join(rdata.strings).decode('utf-8', errors='replace')
                result['records'].append(txt_val)
            elif record_type == 'CNAME':
                result['records'].append(str(rdata.target).rstrip('.'))
            elif record_type == 'NS':
                result['records'].append(str(rdata).rstrip('.'))
            elif record_type == 'SOA':
                result['records'].append({
                    'mname': str(rdata.mname).rstrip('.'),
                    'rname': str(rdata.rname).rstrip('.'),
                    'serial': rdata.serial
                })
            else:
                result['records'].append(str(rdata))
                
    except dns.resolver.NXDOMAIN:
        result['error'] = 'NXDOMAIN - 도메인이 존재하지 않음'
    except dns.resolver.NoAnswer:
        result['error'] = f'NoAnswer - {record_type} 레코드 없음'
    except dns.resolver.NoNameservers:
        result['error'] = 'NoNameservers - 네임서버 응답 없음'
    except dns.exception.Timeout:
        result['error'] = 'Timeout - DNS 조회 시간 초과'
    except Exception as e:
        result['error'] = f'오류: {str(e)}'
    
    return result


def query_ptr(ip):
    """PTR(역방향 DNS) 조회"""
    result = {
        'type': 'PTR',
        'ip': ip,
        'records': [],
        'error': None,
        'queried': True
    }
    
    try:
        resolver = get_resolver()
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, 'PTR')
        for rdata in answers:
            result['records'].append(str(rdata).rstrip('.'))
    except dns.resolver.NXDOMAIN:
        result['error'] = 'NXDOMAIN - PTR 레코드 없음'
    except dns.resolver.NoAnswer:
        result['error'] = 'NoAnswer - PTR 레코드 없음'
    except dns.exception.Timeout:
        result['error'] = 'Timeout - DNS 조회 시간 초과'
    except Exception as e:
        result['error'] = f'오류: {str(e)}'
    
    return result


def parse_spf_record(spf_text):
    """SPF 레코드 파싱 및 분석"""
    if not spf_text or not spf_text.startswith('v=spf1'):
        return None
    
    spf_info = {
        'raw': spf_text,
        'version': 'spf1',
        'mechanisms': [],
        'all_policy': None,
        'includes': [],
        'ip4_ranges': [],
        'ip6_ranges': [],
        'mx_hosts': [],
        'a_hosts': [],
        'redirect': None
    }
    
    parts = spf_text.split()
    
    for part in parts[1:]:  # v=spf1 이후
        part_lower = part.lower()
        
        if part_lower in ['+all', '-all', '~all', '?all', 'all']:
            policy_map = {
                '+all': 'pass', '-all': 'fail',
                '~all': 'softfail', '?all': 'neutral', 'all': 'neutral'
            }
            spf_info['all_policy'] = policy_map.get(part_lower, part_lower)
        
        elif part_lower.startswith('include:'):
            domain = part[8:]
            spf_info['includes'].append(domain)
            spf_info['mechanisms'].append({'type': 'include', 'value': domain})
        
        elif part_lower.startswith('ip4:'):
            ip_range = part[4:]
            spf_info['ip4_ranges'].append(ip_range)
            spf_info['mechanisms'].append({'type': 'ip4', 'value': ip_range})
        
        elif part_lower.startswith('ip6:'):
            ip_range = part[4:]
            spf_info['ip6_ranges'].append(ip_range)
            spf_info['mechanisms'].append({'type': 'ip6', 'value': ip_range})
        
        elif part_lower.startswith('mx'):
            value = part[3:] if ':' in part else ''
            spf_info['mx_hosts'].append(value or '(current domain)')
            spf_info['mechanisms'].append({'type': 'mx', 'value': value})
        
        elif part_lower.startswith('a'):
            value = part[2:] if ':' in part else ''
            spf_info['a_hosts'].append(value or '(current domain)')
            spf_info['mechanisms'].append({'type': 'a', 'value': value})
        
        elif part_lower.startswith('redirect='):
            spf_info['redirect'] = part[9:]
            spf_info['mechanisms'].append({'type': 'redirect', 'value': spf_info['redirect']})
        
        elif part_lower.startswith('exists:'):
            spf_info['mechanisms'].append({'type': 'exists', 'value': part[7:]})
        
        elif part_lower.startswith('ptr'):
            spf_info['mechanisms'].append({'type': 'ptr', 'value': part[4:] if ':' in part else ''})
    
    return spf_info


def check_ip_in_spf(ip, spf_text, depth=0):
    """
    IP가 SPF 레코드에 허용되는지 확인
    재귀적으로 include 처리
    """
    if depth > 5 or not spf_text:
        return False, "최대 재귀 깊이 초과"
    
    spf_info = parse_spf_record(spf_text)
    if not spf_info:
        return False, "SPF 레코드 없음"
    
    resolver = get_resolver()
    
    # ip4 확인
    for ip4_range in spf_info['ip4_ranges']:
        if ip_in_range(ip, ip4_range):
            return True, f"ip4:{ip4_range} 범위에 포함"
    
    # include 확인 (재귀)
    for include_domain in spf_info['includes']:
        try:
            txt_result = query_dns(include_domain, 'TXT', resolver)
            for record in txt_result['records']:
                if record.startswith('v=spf1'):
                    found, reason = check_ip_in_spf(ip, record, depth + 1)
                    if found:
                        return True, f"include:{include_domain} -> {reason}"
        except Exception:
            pass
    
    # mx 확인
    if any(m['type'] == 'mx' for m in spf_info['mechanisms']):
        pass  # MX 레코드 확인은 별도 처리
    
    return False, "SPF에 포함되지 않음"


def ip_in_range(ip, cidr):
    """IP가 CIDR 범위에 속하는지 확인"""
    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(ip) in network
    except Exception:
        return ip == cidr


def get_domain_dns_info(domain):
    """
    특정 도메인의 전체 DNS 정보 조회
    A, AAAA, MX, TXT(SPF 포함), NS, SOA 레코드
    """
    if not domain:
        return None
    
    domain = domain.strip().lower().rstrip('.')
    
    resolver = get_resolver()
    dns_info = {
        'domain': domain,
        'exists': False,
        'a_records': None,
        'aaaa_records': None,
        'mx_records': None,
        'txt_records': None,
        'ns_records': None,
        'soa_record': None,
        'spf_record': None,
        'dmarc_record': None,
        'dkim_records': {},
        'summary': {
            'has_a': False,
            'has_mx': False,
            'has_spf': False,
            'has_dmarc': False,
            'is_mail_domain': False,
            'domain_exists': False
        }
    }
    
    # A 레코드
    dns_info['a_records'] = query_dns(domain, 'A', resolver)
    if dns_info['a_records']['records']:
        dns_info['exists'] = True
        dns_info['summary']['has_a'] = True
        dns_info['summary']['domain_exists'] = True
    
    # AAAA 레코드
    dns_info['aaaa_records'] = query_dns(domain, 'AAAA', resolver)
    
    # MX 레코드
    dns_info['mx_records'] = query_dns(domain, 'MX', resolver)
    if dns_info['mx_records']['records']:
        dns_info['exists'] = True
        dns_info['summary']['has_mx'] = True
        dns_info['summary']['is_mail_domain'] = True
        dns_info['summary']['domain_exists'] = True
    
    # TXT 레코드 (SPF 포함)
    dns_info['txt_records'] = query_dns(domain, 'TXT', resolver)
    if dns_info['txt_records']['records']:
        dns_info['exists'] = True
        dns_info['summary']['domain_exists'] = True
        
        # SPF 레코드 찾기
        for txt in dns_info['txt_records']['records']:
            if txt.startswith('v=spf1'):
                dns_info['spf_record'] = {
                    'raw': txt,
                    'parsed': parse_spf_record(txt)
                }
                dns_info['summary']['has_spf'] = True
                break
    
    # NS 레코드
    dns_info['ns_records'] = query_dns(domain, 'NS', resolver)
    if dns_info['ns_records']['records']:
        dns_info['exists'] = True
        dns_info['summary']['domain_exists'] = True
    
    # SOA 레코드
    dns_info['soa_record'] = query_dns(domain, 'SOA', resolver)
    
    # DMARC 레코드 (_dmarc.domain)
    dmarc_domain = f'_dmarc.{domain}'
    dmarc_result = query_dns(dmarc_domain, 'TXT', resolver)
    if dmarc_result['records']:
        for txt in dmarc_result['records']:
            if txt.startswith('v=DMARC1'):
                dns_info['dmarc_record'] = {
                    'raw': txt,
                    'parsed': parse_dmarc_record(txt)
                }
                dns_info['summary']['has_dmarc'] = True
                break
    
    return dns_info


def get_dkim_dns_info(domain, selector):
    """DKIM DNS 레코드 조회 (selector._domainkey.domain)"""
    if not domain or not selector:
        return None
    
    dkim_domain = f'{selector}._domainkey.{domain}'
    resolver = get_resolver()
    result = query_dns(dkim_domain, 'TXT', resolver)
    
    dkim_info = {
        'domain': domain,
        'selector': selector,
        'dkim_domain': dkim_domain,
        'result': result,
        'exists': bool(result['records']),
        'public_key': None
    }
    
    if result['records']:
        for txt in result['records']:
            if 'v=DKIM1' in txt or 'p=' in txt:
                # 공개키 추출
                p_match = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
                if p_match:
                    dkim_info['public_key'] = p_match.group(1)[:50] + '...' if len(p_match.group(1)) > 50 else p_match.group(1)
                break
    
    return dkim_info


def parse_dmarc_record(dmarc_text):
    """DMARC 레코드 파싱"""
    if not dmarc_text or 'v=DMARC1' not in dmarc_text:
        return None
    
    dmarc_info = {
        'raw': dmarc_text,
        'policy': None,
        'subdomain_policy': None,
        'pct': 100,
        'rua': None,
        'ruf': None,
        'adkim': 'r',
        'aspf': 'r'
    }
    
    parts = dmarc_text.split(';')
    for part in parts:
        part = part.strip()
        if part.startswith('p='):
            dmarc_info['policy'] = part[2:]
        elif part.startswith('sp='):
            dmarc_info['subdomain_policy'] = part[3:]
        elif part.startswith('pct='):
            try:
                dmarc_info['pct'] = int(part[4:])
            except Exception:
                pass
        elif part.startswith('rua='):
            dmarc_info['rua'] = part[4:]
        elif part.startswith('ruf='):
            dmarc_info['ruf'] = part[4:]
        elif part.startswith('adkim='):
            dmarc_info['adkim'] = part[6:]
        elif part.startswith('aspf='):
            dmarc_info['aspf'] = part[5:]
    
    return dmarc_info


def get_ip_dns_info(ip):
    """
    IP 주소에 대한 DNS 정보 조회
    PTR 레코드 및 기본 정보
    """
    if not ip:
        return None
    
    info = {
        'ip': ip,
        'ptr_records': None,
        'hostname': None,
        'is_private': False,
        'is_public': False,
        'summary': {
            'has_ptr': False,
            'ptr_matches_forward': False
        }
    }
    
    # 사설 IP 확인
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        info['is_private'] = ip_obj.is_private
        info['is_public'] = not ip_obj.is_private and not ip_obj.is_loopback
    except Exception:
        pass
    
    if info['is_private']:
        info['ptr_records'] = {'records': [], 'error': '사설 IP - PTR 조회 불필요'}
        return info
    
    # PTR 레코드
    ptr_result = query_ptr(ip)
    info['ptr_records'] = ptr_result
    
    if ptr_result['records']:
        info['hostname'] = ptr_result['records'][0]
        info['summary']['has_ptr'] = True
        
        # PTR 레코드의 호스트명이 실제로 해당 IP를 가리키는지 확인 (Forward Confirmed rDNS)
        if info['hostname']:
            resolver = get_resolver()
            forward_check = query_dns(info['hostname'], 'A', resolver)
            if ip in forward_check.get('records', []):
                info['summary']['ptr_matches_forward'] = True
    
    return info


def analyze_all_dns(email_data):
    """
    파싱된 이메일 데이터의 모든 도메인/IP에 대해 DNS 조회 수행
    Returns: dns_results dict
    """
    dns_results = {
        'domains': {},
        'ips': {},
        'dkim_checks': {},
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    resolver = get_resolver()
    
    # 모든 발신 도메인 DNS 조회
    all_domains = email_data.get('all_sender_domains', [])
    for domain in all_domains:
        if domain and domain not in dns_results['domains']:
            dns_info = get_domain_dns_info(domain)
            if dns_info:
                dns_results['domains'][domain] = dns_info
            time.sleep(0.1)  # DNS 서버 부하 방지
    
    # 모든 IP PTR 조회
    all_ips = email_data.get('all_ips', [])
    for ip in all_ips:
        if ip and ip not in dns_results['ips']:
            ip_info = get_ip_dns_info(ip)
            if ip_info:
                dns_results['ips'][ip] = ip_info
            time.sleep(0.1)
    
    # DKIM 셀렉터 DNS 조회
    for dkim_sig in email_data.get('dkim_signatures', []):
        domain = dkim_sig.get('domain')
        selector = dkim_sig.get('selector')
        if domain and selector:
            key = f'{selector}._domainkey.{domain}'
            if key not in dns_results['dkim_checks']:
                dkim_info = get_dkim_dns_info(domain, selector)
                dns_results['dkim_checks'][key] = dkim_info
            time.sleep(0.1)
    
    return dns_results
