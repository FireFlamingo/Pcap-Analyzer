"""
PCAP Analyzer Engine for CTF Challenges
Extracts flags, credentials, files, DNS/HTTP data, TCP streams, and strings.
Enhanced with: ICMP exfil, DNS exfil reconstruction, ROT13/XOR decoding,
UDP analysis, and printable-only flag filtering.
"""

import re
import os
import base64
import binascii
import hashlib
import struct
import codecs
import string
from collections import Counter, defaultdict
from scapy.all import (
    rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
    Raw, Ether, ARP, conf
)

# Suppress Scapy warnings
conf.verb = 0

# ---------------------------------------------------------------------------
# Flag patterns used across CTF competitions
# ---------------------------------------------------------------------------
# Known CTF flag format patterns (high confidence)
KNOWN_FLAG_PATTERNS = [
    r'flag\{[^\}]+\}',
    r'FLAG\{[^\}]+\}',
    r'ctf\{[^\}]+\}',
    r'CTF\{[^\}]+\}',
    r'picoCTF\{[^\}]+\}',
    r'picoCtf\{[^\}]+\}',
    r'HTB\{[^\}]+\}',
    r'htb\{[^\}]+\}',
    r'THM\{[^\}]+\}',
    r'thm\{[^\}]+\}',
    r'FLAG-[a-fA-F0-9\-]+',
    r'key\{[^\}]+\}',
    r'KEY\{[^\}]+\}',
    r'secret\{[^\}]+\}',
    r'SECRET\{[^\}]+\}',
    r'hack\{[^\}]+\}',
    r'HACK\{[^\}]+\}',
    r'crypto\{[^\}]+\}',
    r'CRYPTO\{[^\}]+\}',
    r'rev\{[^\}]+\}',
    r'forensics\{[^\}]+\}',
    r'misc\{[^\}]+\}',
    r'pwn\{[^\}]+\}',
    r'web\{[^\}]+\}',
    r'stego\{[^\}]+\}',
    r'osint\{[^\}]+\}',
    r'ciph\{[^\}]+\}',
    r'CIPH\{[^\}]+\}',
    r'XPL8\{[^\}]+\}',
    r'xpl8\{[^\}]+\}',
]

# Generic pattern: 3+ alpha-starting chars followed by {...}
# More selective to avoid false positives from binary junk
GENERIC_FLAG_PATTERNS = [
    r'[a-zA-Z][a-zA-Z0-9_]{2,}\{[a-zA-Z0-9_!@#$%^&*()\-+=.,;:\'"/\\?<> ]{4,}\}',
]

FLAG_PATTERNS = KNOWN_FLAG_PATTERNS + GENERIC_FLAG_PATTERNS

# Compile once
_FLAG_RES = [re.compile(p) for p in FLAG_PATTERNS]
_KNOWN_FLAG_RES = [re.compile(p, re.IGNORECASE) for p in KNOWN_FLAG_PATTERNS]

# Printable characters set for filtering
PRINTABLE_SET = set(string.printable)

# File signatures for carving
FILE_SIGNATURES = {
    b'\x89PNG\r\n\x1a\n': ('png', 'image/png'),
    b'\xff\xd8\xff': ('jpg', 'image/jpeg'),
    b'GIF87a': ('gif', 'image/gif'),
    b'GIF89a': ('gif', 'image/gif'),
    b'%PDF': ('pdf', 'application/pdf'),
    b'PK\x03\x04': ('zip', 'application/zip'),
    b'\x1f\x8b': ('gz', 'application/gzip'),
    b'Rar!\x1a\x07': ('rar', 'application/x-rar'),
    b'\x7fELF': ('elf', 'application/x-elf'),
    b'MZ': ('exe', 'application/x-exe'),
    b'BM': ('bmp', 'image/bmp'),
    b'RIFF': ('wav_or_avi', 'application/octet-stream'),
    b'\x00\x00\x01\x00': ('ico', 'image/x-icon'),
    b'OggS': ('ogg', 'audio/ogg'),
    b'fLaC': ('flac', 'audio/flac'),
    b'\x00\x00\x00\x1c\x66\x74\x79\x70': ('mp4', 'video/mp4'),
    b'\x00\x00\x00\x20\x66\x74\x79\x70': ('mp4', 'video/mp4'),
}


def is_printable_flag(flag_str):
    """Check if a flag string contains only printable ASCII characters."""
    return all(c in PRINTABLE_SET for c in flag_str)


def _search_text_for_flags(text, source_label, packet_num, seen, flags_list, known_only=False):
    """Search text for flag patterns, only adding printable results."""
    patterns = _KNOWN_FLAG_RES if known_only else _FLAG_RES
    for regex in patterns:
        for match in regex.finditer(text):
            flag = match.group(0)
            if flag not in seen and len(flag) > 5 and is_printable_flag(flag):
                seen.add(flag)
                flags_list.append({
                    'flag': flag,
                    'packet_num': packet_num,
                    'source': source_label,
                })


def analyze_pcap(filepath, output_dir):
    """Run full analysis on a PCAP file. Returns a dict of all findings."""
    packets = rdpcap(filepath)

    results = {
        'summary': _packet_summary(packets),
        'protocols': _protocol_stats(packets),
        'top_talkers': _top_talkers(packets),
        'flags': _find_flags(packets),
        'credentials': _extract_credentials(packets),
        'dns': _analyze_dns(packets),
        'http': _analyze_http(packets),
        'streams': _reassemble_streams(packets),
        'strings': _extract_strings(packets),
        'files': _carve_files(packets, output_dir),
        'suspicious': _detect_suspicious(packets),
    }
    return results


# ---------------------------------------------------------------------------
# 1. Packet Summary
# ---------------------------------------------------------------------------
def _packet_summary(packets):
    total = len(packets)
    if total == 0:
        return {'total_packets': 0, 'duration': 0, 'start_time': '', 'end_time': ''}

    times = [float(p.time) for p in packets]
    start = min(times)
    end = max(times)
    duration = end - start

    sizes = [len(p) for p in packets]
    return {
        'total_packets': total,
        'duration_seconds': round(duration, 3),
        'avg_packet_size': round(sum(sizes) / total, 1),
        'total_bytes': sum(sizes),
        'smallest_packet': min(sizes),
        'largest_packet': max(sizes),
    }


# ---------------------------------------------------------------------------
# 2. Protocol Statistics
# ---------------------------------------------------------------------------
def _protocol_stats(packets):
    proto_count = Counter()
    port_count = Counter()

    for pkt in packets:
        if pkt.haslayer(TCP):
            proto_count['TCP'] += 1
            port_count[pkt[TCP].dport] += 1
            port_count[pkt[TCP].sport] += 1
        if pkt.haslayer(UDP):
            proto_count['UDP'] += 1
            port_count[pkt[UDP].dport] += 1
            port_count[pkt[UDP].sport] += 1
        if pkt.haslayer(ICMP):
            proto_count['ICMP'] += 1
        if pkt.haslayer(DNS):
            proto_count['DNS'] += 1
        if pkt.haslayer(ARP):
            proto_count['ARP'] += 1
        if pkt.haslayer(IP):
            proto_count['IPv4'] += 1
        if pkt.haslayer(IPv6):
            proto_count['IPv6'] += 1

        # Detect HTTP
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if payload[:4] in (b'GET ', b'POST', b'HTTP', b'PUT ', b'HEAD', b'DELE', b'PATC', b'OPTI'):
                proto_count['HTTP'] += 1

        # Detect FTP
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21):
            proto_count['FTP'] += 1

        # Detect SMTP
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 25 or pkt[TCP].sport == 25 or
                                   pkt[TCP].dport == 587 or pkt[TCP].sport == 587):
            proto_count['SMTP'] += 1

        # Detect Telnet
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
            proto_count['Telnet'] += 1

    protocols = [{'name': k, 'count': v} for k, v in proto_count.most_common()]
    top_ports = [{'port': k, 'count': v} for k, v in port_count.most_common(20)]
    return {'protocols': protocols, 'top_ports': top_ports}


# ---------------------------------------------------------------------------
# 3. Top Talkers
# ---------------------------------------------------------------------------
def _top_talkers(packets):
    src_counter = Counter()
    dst_counter = Counter()
    conversations = Counter()

    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            src_counter[src] += 1
            dst_counter[dst] += 1
            conv = tuple(sorted([src, dst]))
            conversations[conv] += 1

    return {
        'top_sources': [{'ip': k, 'count': v} for k, v in src_counter.most_common(10)],
        'top_destinations': [{'ip': k, 'count': v} for k, v in dst_counter.most_common(10)],
        'top_conversations': [
            {'src': k[0], 'dst': k[1], 'count': v}
            for k, v in conversations.most_common(10)
        ],
    }


# ---------------------------------------------------------------------------
# 4. Flag Finder (Enhanced)
# ---------------------------------------------------------------------------
def _find_flags(packets):
    flags = []
    seen = set()

    # ── A. Search raw payloads per packet ──
    for i, pkt in enumerate(packets):
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)

            try:
                text = payload.decode('utf-8', errors='replace')
            except Exception:
                text = payload.decode('latin-1', errors='replace')

            _search_text_for_flags(text, 'raw_payload', i + 1, seen, flags)

            # Try Base64 decoding chunks
            b64_pattern = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')
            for b64match in b64_pattern.finditer(text):
                try:
                    decoded = base64.b64decode(b64match.group(0)).decode('utf-8', errors='replace')
                    _search_text_for_flags(decoded, 'base64_decoded', i + 1, seen, flags)
                except Exception:
                    pass

            # Try hex decoding
            hex_pattern = re.compile(r'(?:[0-9a-fA-F]{2}){8,}')
            for hexmatch in hex_pattern.finditer(text):
                try:
                    decoded = bytes.fromhex(hexmatch.group(0)).decode('utf-8', errors='replace')
                    _search_text_for_flags(decoded, 'hex_decoded', i + 1, seen, flags)
                except Exception:
                    pass

            # Try ROT13 (known patterns only to avoid false positives)
            try:
                rot13_text = codecs.decode(text, 'rot_13')
                _search_text_for_flags(rot13_text, 'rot13_decoded', i + 1, seen, flags, known_only=True)
            except Exception:
                pass

    # ── B. Search reassembled TCP streams ──
    streams = _get_tcp_streams(packets)
    for stream_key, data in streams.items():
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = data.decode('latin-1', errors='replace')

        _search_text_for_flags(text, f'tcp_stream ({stream_key})', 0, seen, flags)

        # Base64 in streams
        for b64match in re.finditer(r'[A-Za-z0-9+/]{16,}={0,2}', text):
            try:
                decoded = base64.b64decode(b64match.group(0)).decode('utf-8', errors='replace')
                _search_text_for_flags(decoded, f'tcp_stream_base64 ({stream_key})', 0, seen, flags)
            except Exception:
                pass

        # ROT13 in streams (known patterns only to avoid false positives)
        try:
            rot13_text = codecs.decode(text, 'rot_13')
            _search_text_for_flags(rot13_text, f'tcp_stream_rot13 ({stream_key})', 0, seen, flags, known_only=True)
        except Exception:
            pass

        # XOR brute force (single-byte keys 1-255) on first 2KB
        _xor_bruteforce_flags(bytes(data[:2048]), f'tcp_stream_xor ({stream_key})', 0, seen, flags)

    # ── C. Search UDP payloads ──
    udp_data = _get_udp_payloads(packets)
    for i, payload in udp_data:
        try:
            text = payload.decode('utf-8', errors='replace')
        except Exception:
            text = payload.decode('latin-1', errors='replace')

        _search_text_for_flags(text, 'udp_payload', i + 1, seen, flags)

        # Base64 in UDP
        for b64match in re.finditer(r'[A-Za-z0-9+/]{16,}={0,2}', text):
            try:
                decoded = base64.b64decode(b64match.group(0)).decode('utf-8', errors='replace')
                _search_text_for_flags(decoded, 'udp_base64', i + 1, seen, flags)
            except Exception:
                pass

    # ── D. ICMP data exfiltration detection ──
    _find_icmp_exfil_flags(packets, seen, flags)

    # ── E. DNS exfiltration detection ──
    _find_dns_exfil_flags(packets, seen, flags)

    # ── F. Fragmented flag reconstruction from UDP/TCP payloads ──
    _find_fragmented_flags(packets, seen, flags)

    return flags


def _xor_bruteforce_flags(data, source_label, packet_num, seen, flags_list):
    """Try single-byte XOR keys to find flags."""
    # Only try common keys to stay fast
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        try:
            text = decoded.decode('ascii', errors='replace')
        except Exception:
            continue
        # Quick check before regex — use known_only to avoid generic false positives
        if '{' in text:
            _search_text_for_flags(text, f'{source_label} key=0x{key:02x}', packet_num, seen, flags_list, known_only=True)


def _get_udp_payloads(packets):
    """Collect UDP payloads (excluding DNS)."""
    result = []
    for i, pkt in enumerate(packets):
        if pkt.haslayer(UDP) and pkt.haslayer(Raw) and not pkt.haslayer(DNS):
            result.append((i, bytes(pkt[Raw].load)))
    return result


def _find_fragmented_flags(packets, seen, flags_list):
    """
    Detect flags fragmented across multiple packets.
    Collects printable string fragments from UDP and raw payloads,
    then attempts to reconstruct flags by matching partial patterns.
    """
    # Collect all printable fragments from all packet payloads
    fragments = []  # list of (packet_index, printable_string)

    for i, pkt in enumerate(packets):
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            # Extract printable strings
            for match in re.finditer(rb'[\x20-\x7e]{3,}', payload):
                s = match.group(0).decode('ascii')
                fragments.append((i, s))

    if not fragments:
        return

    # Strategy 1: Look for fragments that look like the start, middle, or end of a flag
    # Start: word{ pattern
    # End: } pattern
    # Middle: content between { and }

    starts = []  # Fragments containing a flag start like "ctf{", "flag{", etc.
    middles = []
    ends = []  # Fragments containing "}"

    for idx, (pkt_i, s) in enumerate(fragments):
        if re.search(r'[a-zA-Z0-9_]+\{', s):
            starts.append((idx, pkt_i, s))
        if '}' in s and not '{' in s:
            ends.append((idx, pkt_i, s))

    # Strategy 2: For each start fragment, look for end fragments that come later
    # and try to concatenate fragments between them
    for start_idx, start_pkt, start_str in starts:
        # Extract the part from the flag prefix onward
        start_match = re.search(r'([a-zA-Z0-9_]+\{[^\}]*?)$', start_str)
        if not start_match:
            continue
        flag_start = start_match.group(1)

        # Look for end fragments
        for end_idx, end_pkt, end_str in ends:
            if end_idx <= start_idx:
                continue
            if end_pkt < start_pkt:
                continue

            # Extract the part up to and including }
            end_match = re.search(r'^([^\}]*\})', end_str)
            if not end_match:
                continue
            flag_end = end_match.group(1)

            # Try direct concatenation (start + end) — for 2-piece fragments
            candidate = flag_start + flag_end
            if is_printable_flag(candidate) and len(candidate) > 8:
                if candidate not in seen:
                    seen.add(candidate)
                    flags_list.append({
                        'flag': candidate,
                        'packet_num': start_pkt + 1,
                        'source': 'fragmented_flag_reconstruction',
                    })

            # Try collecting middle fragments (fragments between start and end)
            middle_strs = []
            for mid_idx, (mid_pkt, mid_s) in enumerate(fragments):
                if mid_idx > start_idx and mid_idx < end_idx and mid_pkt >= start_pkt and mid_pkt <= end_pkt:
                    # Only include short fragments that look like flag content
                    if len(mid_s) < 30 and '{' not in mid_s and '}' not in mid_s:
                        middle_strs.append(mid_s)

            # Try concatenating with middles
            if middle_strs and len(middle_strs) < 5:
                for mid in middle_strs:
                    candidate = flag_start + mid + flag_end
                    if is_printable_flag(candidate) and len(candidate) > 10:
                        if candidate not in seen:
                            seen.add(candidate)
                            flags_list.append({
                                'flag': candidate,
                                'packet_num': start_pkt + 1,
                                'source': 'fragmented_flag_reconstruction',
                            })

    # Strategy 3: Concatenate fragments that look like they form a known flag pattern
    # when joined by |-delimiter (seen in some CTF challenges)
    all_strs = [s for _, s in fragments]
    pipe_joined = '|'.join(all_strs)
    pipe_cleaned = pipe_joined.replace('|', '')
    # Search the cleaned concatenation
    _search_text_for_flags(pipe_cleaned, 'fragmented_concat', 0, seen, flags_list, known_only=True)


def _find_icmp_exfil_flags(packets, seen, flags_list):
    """
    Detect flags hidden in ICMP packets via multiple exfiltration techniques:
    - Payload data concatenation
    - Single byte per packet (first byte, or at specific offsets)
    - Payload size as character code
    - Sequence number as character code
    - ID field as character code
    - TTL field encoding
    """
    icmp_packets = []
    for i, pkt in enumerate(packets):
        if pkt.haslayer(ICMP):
            icmp_layer = pkt[ICMP]
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b''
            ip_layer = pkt[IP] if pkt.haslayer(IP) else None
            icmp_packets.append({
                'index': i,
                'type': icmp_layer.type,
                'code': icmp_layer.code,
                'id': getattr(icmp_layer, 'id', 0),
                'seq': getattr(icmp_layer, 'seq', 0),
                'payload': payload,
                'ttl': ip_layer.ttl if ip_layer else 0,
                'pkt_len': len(pkt),
            })

    if len(icmp_packets) < 3:
        return

    payloads = [d['payload'] for d in icmp_packets if d['payload']]

    if payloads:
        # 1. Full payload concatenation
        full_concat = b''.join(payloads)
        text = full_concat.decode('ascii', errors='replace')
        _search_text_for_flags(text, 'icmp_payload_concat', 0, seen, flags_list)

        # 2. Single byte at various offsets
        for offset in [0, 1, 2, 4, 8, 16]:
            chars = bytes(pl[offset] for pl in payloads if len(pl) > offset)
            if len(chars) > 3:
                text = chars.decode('ascii', errors='replace')
                _search_text_for_flags(text, f'icmp_byte_offset_{offset}', 0, seen, flags_list)

        # 3. Last byte of each payload
        last_bytes = bytes(pl[-1] for pl in payloads if len(pl) > 0)
        if len(last_bytes) > 3:
            text = last_bytes.decode('ascii', errors='replace')
            _search_text_for_flags(text, 'icmp_last_byte', 0, seen, flags_list)

        # 4. Payload size as character code
        sizes = [len(pl) for pl in payloads]
        if all(0 < s < 256 for s in sizes):
            text = ''.join(chr(s) for s in sizes if 0 < s < 256)
            _search_text_for_flags(text, 'icmp_size_encoding', 0, seen, flags_list)

        # 5. Try base64 decode of concatenated payload
        try:
            b64_text = full_concat.decode('ascii', errors='ignore')
            decoded = base64.b64decode(b64_text).decode('utf-8', errors='replace')
            _search_text_for_flags(decoded, 'icmp_base64', 0, seen, flags_list)
        except Exception:
            pass

        # 6. Try hex decode of concatenated payload
        try:
            hex_text = full_concat.decode('ascii', errors='ignore')
            decoded = bytes.fromhex(hex_text).decode('utf-8', errors='replace')
            _search_text_for_flags(decoded, 'icmp_hex', 0, seen, flags_list)
        except Exception:
            pass

    # 7. Sequence number as character
    seqs = [d['seq'] for d in icmp_packets]
    if len(seqs) > 3:
        # Direct char mapping
        chars = ''.join(chr(s) for s in seqs if 0 < s < 256)
        _search_text_for_flags(chars, 'icmp_seq_char', 0, seen, flags_list)
        # Also try seq as byte values
        seq_bytes = bytes(s & 0xFF for s in seqs)
        text = seq_bytes.decode('ascii', errors='replace')
        _search_text_for_flags(text, 'icmp_seq_bytes', 0, seen, flags_list)

    # 8. ID field as character
    ids = [d['id'] for d in icmp_packets]
    if len(ids) > 3:
        chars = ''.join(chr(i) for i in ids if 0 < i < 256)
        _search_text_for_flags(chars, 'icmp_id_char', 0, seen, flags_list)

    # 9. TTL field encoding
    ttls = [d['ttl'] for d in icmp_packets]
    if len(ttls) > 3:
        chars = ''.join(chr(t) for t in ttls if 0 < t < 256)
        _search_text_for_flags(chars, 'icmp_ttl_char', 0, seen, flags_list)

    # 10. ICMP type and code based encoding
    type_codes = [d['type'] for d in icmp_packets]
    if any(0 < t < 128 for t in type_codes):
        chars = ''.join(chr(t) for t in type_codes if 0 < t < 256)
        _search_text_for_flags(chars, 'icmp_type_char', 0, seen, flags_list)

    # 11. Try splitting echo request vs reply and analyzing separately
    echo_req_payloads = [d['payload'] for d in icmp_packets if d['type'] == 8 and d['payload']]
    echo_rep_payloads = [d['payload'] for d in icmp_packets if d['type'] == 0 and d['payload']]

    for label, pls in [('icmp_echo_request', echo_req_payloads), ('icmp_echo_reply', echo_rep_payloads)]:
        if len(pls) > 3:
            concat = b''.join(pls)
            text = concat.decode('ascii', errors='replace')
            _search_text_for_flags(text, label, 0, seen, flags_list)
            # Single byte exfil
            for offset in [0, 1]:
                chars = bytes(pl[offset] for pl in pls if len(pl) > offset)
                text = chars.decode('ascii', errors='replace')
                _search_text_for_flags(text, f'{label}_byte_{offset}', 0, seen, flags_list)

    # 12. XOR brute force the ICMP concatenated data (first 2KB)
    if payloads:
        concat_bytes = b''.join(payloads)[:2048]
        _xor_bruteforce_flags(concat_bytes, 'icmp_xor', 0, seen, flags_list)


def _find_dns_exfil_flags(packets, seen, flags_list):
    """
    Detect flags hidden in DNS queries via exfiltration:
    - Subdomain label concatenation (direct, hex, base32, base64)
    - TXT record data
    - DNS response data
    - CNAME chains
    """
    queries = []
    txt_records = []
    cname_records = []
    all_response_data = []

    for i, pkt in enumerate(packets):
        if not pkt.haslayer(DNS):
            continue

        dns = pkt[DNS]

        # Collect queries
        if dns.haslayer(DNSQR):
            try:
                qname = dns[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')
                queries.append(qname)
            except Exception:
                pass

        # Collect response data
        if dns.qr == 1 and dns.ancount and dns.ancount > 0:
            try:
                for j in range(dns.ancount):
                    rr = dns.an[j] if hasattr(dns.an, '__getitem__') else dns.an
                    rtype = getattr(rr, 'type', 0)

                    if hasattr(rr, 'rdata'):
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            all_response_data.append(rdata)
                            if rtype == 16:  # TXT
                                txt_records.append(rdata)
                            elif rtype == 5:  # CNAME
                                cname_records.append(rdata)
                        elif isinstance(rdata, list):
                            for rd in rdata:
                                if isinstance(rd, bytes):
                                    all_response_data.append(rd)
                                    if rtype == 16:
                                        txt_records.append(rd)
                        elif isinstance(rdata, str):
                            all_response_data.append(rdata.encode('utf-8', errors='replace'))
            except Exception:
                pass

    # ── Search TXT records ──
    for txt in txt_records:
        text = txt.decode('utf-8', errors='replace')
        _search_text_for_flags(text, 'dns_txt_record', 0, seen, flags_list)
        # Base64-encoded TXT
        try:
            decoded = base64.b64decode(text).decode('utf-8', errors='replace')
            _search_text_for_flags(decoded, 'dns_txt_base64', 0, seen, flags_list)
        except Exception:
            pass

    # ── Search all response data ──
    for rd in all_response_data:
        if isinstance(rd, bytes):
            text = rd.decode('utf-8', errors='replace')
        else:
            text = str(rd)
        _search_text_for_flags(text, 'dns_response_data', 0, seen, flags_list)

    # ── Subdomain exfiltration reconstruction ──
    if queries:
        # Extract first subdomain label from each query
        labels = []
        for q in queries:
            parts = q.split('.')
            if len(parts) >= 2:
                labels.append(parts[0])

        if labels:
            # 1. Direct concatenation
            combined = ''.join(labels)
            _search_text_for_flags(combined, 'dns_subdomain_concat', 0, seen, flags_list)

            # 2. Hex decode
            try:
                decoded = bytes.fromhex(combined).decode('utf-8', errors='replace')
                _search_text_for_flags(decoded, 'dns_subdomain_hex', 0, seen, flags_list)
            except Exception:
                pass

            # 3. Base32 decode
            try:
                padded = combined.upper()
                pad = (8 - len(padded) % 8) % 8
                padded += '=' * pad
                decoded = base64.b32decode(padded).decode('utf-8', errors='replace')
                _search_text_for_flags(decoded, 'dns_subdomain_base32', 0, seen, flags_list)
            except Exception:
                pass

            # 4. Base64 decode
            try:
                padded = combined
                pad = (4 - len(padded) % 4) % 4
                padded += '=' * pad
                decoded = base64.b64decode(padded).decode('utf-8', errors='replace')
                _search_text_for_flags(decoded, 'dns_subdomain_base64', 0, seen, flags_list)
            except Exception:
                pass

            # 5. Try with ALL subdomain labels (not just first)
            all_labels = []
            for q in queries:
                parts = q.split('.')
                # Get all labels except TLD and SLD
                if len(parts) > 2:
                    for label in parts[:-2]:
                        all_labels.append(label)
            if all_labels:
                combined_all = ''.join(all_labels)
                _search_text_for_flags(combined_all, 'dns_all_labels_concat', 0, seen, flags_list)
                try:
                    decoded = bytes.fromhex(combined_all).decode('utf-8', errors='replace')
                    _search_text_for_flags(decoded, 'dns_all_labels_hex', 0, seen, flags_list)
                except Exception:
                    pass

        # 6. Unique queries only (deduplication)
        unique_labels = []
        seen_labels = set()
        for q in queries:
            parts = q.split('.')
            if len(parts) >= 2:
                label = parts[0]
                if label not in seen_labels:
                    seen_labels.add(label)
                    unique_labels.append(label)
        if unique_labels and unique_labels != labels:
            combined_unique = ''.join(unique_labels)
            _search_text_for_flags(combined_unique, 'dns_unique_labels', 0, seen, flags_list)
            try:
                decoded = bytes.fromhex(combined_unique).decode('utf-8', errors='replace')
                _search_text_for_flags(decoded, 'dns_unique_labels_hex', 0, seen, flags_list)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 5. Credential Extractor
# ---------------------------------------------------------------------------
def _extract_credentials(packets):
    creds = []
    seen = set()

    for i, pkt in enumerate(packets):
        if not pkt.haslayer(Raw):
            continue

        payload = bytes(pkt[Raw].load)
        try:
            text = payload.decode('utf-8', errors='replace')
        except Exception:
            text = payload.decode('latin-1', errors='replace')

        # HTTP Basic Auth
        basic_match = re.search(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', text)
        if basic_match:
            try:
                decoded = base64.b64decode(basic_match.group(1)).decode('utf-8', errors='replace')
                key = f'basic:{decoded}'
                if key not in seen:
                    seen.add(key)
                    creds.append({
                        'type': 'HTTP Basic Auth',
                        'value': decoded,
                        'packet_num': i + 1,
                    })
            except Exception:
                pass

        # HTTP Bearer Token
        bearer_match = re.search(r'Authorization:\s*Bearer\s+(\S+)', text)
        if bearer_match:
            val = bearer_match.group(1).strip()
            key = f'bearer:{val}'
            if key not in seen:
                seen.add(key)
                creds.append({'type': 'Bearer Token', 'value': val, 'packet_num': i + 1})

        # API Keys in headers
        api_key_match = re.search(r'(?:X-API-Key|X-Api-Key|api[_-]?key|apikey):\s*(\S+)', text, re.IGNORECASE)
        if api_key_match:
            val = api_key_match.group(1).strip()
            key = f'apikey:{val}'
            if key not in seen:
                seen.add(key)
                creds.append({'type': 'API Key', 'value': val, 'packet_num': i + 1})

        # FTP USER/PASS
        ftp_user = re.search(r'^USER\s+(.+)', text, re.MULTILINE)
        ftp_pass = re.search(r'^PASS\s+(.+)', text, re.MULTILINE)
        if ftp_user:
            val = ftp_user.group(1).strip()
            key = f'ftp_user:{val}'
            if key not in seen:
                seen.add(key)
                creds.append({'type': 'FTP Username', 'value': val, 'packet_num': i + 1})
        if ftp_pass:
            val = ftp_pass.group(1).strip()
            key = f'ftp_pass:{val}'
            if key not in seen:
                seen.add(key)
                creds.append({'type': 'FTP Password', 'value': val, 'packet_num': i + 1})

        # SMTP AUTH
        if re.search(r'AUTH\s+(LOGIN|PLAIN)', text, re.IGNORECASE):
            key = f'smtp_auth:{text[:60]}'
            if key not in seen:
                seen.add(key)
                creds.append({'type': 'SMTP Auth', 'value': text.strip()[:200], 'packet_num': i + 1})

        # POST form data with password-like fields
        form_match = re.findall(r'(?:password|passwd|pass|pwd|user|username|login|email)=([^&\s]+)', text, re.IGNORECASE)
        for val in form_match:
            key = f'form:{val}'
            if key not in seen:
                seen.add(key)
                creds.append({'type': 'Form Credential', 'value': val, 'packet_num': i + 1})

        # JSON credentials
        json_cred_match = re.findall(r'"(?:password|passwd|pass|secret|token|api_key)":\s*"([^"]+)"', text, re.IGNORECASE)
        for val in json_cred_match:
            key = f'json:{val}'
            if key not in seen:
                seen.add(key)
                creds.append({'type': 'JSON Credential', 'value': val, 'packet_num': i + 1})

        # Telnet — look for login: / Password: prompts followed by data
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
            key = f'telnet:{text[:60]}'
            if key not in seen and len(text.strip()) > 0:
                seen.add(key)
                creds.append({'type': 'Telnet Data', 'value': text.strip()[:200], 'packet_num': i + 1})

        # SSH banner
        if text.startswith('SSH-'):
            key = f'ssh_banner:{text[:60]}'
            if key not in seen:
                seen.add(key)
                creds.append({'type': 'SSH Banner', 'value': text.strip()[:200], 'packet_num': i + 1})

    return creds


# ---------------------------------------------------------------------------
# 6. DNS Analyzer
# ---------------------------------------------------------------------------
def _analyze_dns(packets):
    queries = []
    responses = []
    seen_queries = set()
    domain_counter = Counter()

    for i, pkt in enumerate(packets):
        if pkt.haslayer(DNS):
            dns = pkt[DNS]

            # Queries
            if dns.qr == 0 and dns.haslayer(DNSQR):
                qname = dns[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')
                qtype = dns[DNSQR].qtype
                type_map = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'}
                qtype_str = type_map.get(qtype, str(qtype))

                if qname not in seen_queries:
                    seen_queries.add(qname)
                    queries.append({
                        'name': qname,
                        'type': qtype_str,
                        'packet_num': i + 1,
                    })

                # Count domain for exfil detection
                parts = qname.split('.')
                if len(parts) >= 2:
                    domain = '.'.join(parts[-2:])
                    domain_counter[domain] += 1

            # Responses
            if dns.qr == 1 and dns.ancount and dns.ancount > 0:
                try:
                    for j in range(dns.ancount):
                        rr = dns.an[j] if hasattr(dns.an, '__getitem__') else dns.an
                        if hasattr(rr, 'rdata'):
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode('utf-8', errors='replace')
                            rrname = rr.rrname.decode('utf-8', errors='replace').rstrip('.') if isinstance(rr.rrname, bytes) else str(rr.rrname).rstrip('.')
                            responses.append({
                                'name': rrname,
                                'data': str(rdata),
                                'packet_num': i + 1,
                            })
                except Exception:
                    pass

    # Detect possible DNS exfiltration
    exfil_suspects = []
    for domain, count in domain_counter.most_common(5):
        if count > 20:
            exfil_suspects.append({'domain': domain, 'query_count': count})

    # Check for unusually long subdomains
    long_subs = []
    for q in queries:
        parts = q['name'].split('.')
        for part in parts[:-2]:
            if len(part) > 30:
                long_subs.append({'query': q['name'], 'long_label': part, 'length': len(part)})
                break

    # Reconstruct potential DNS exfil data
    exfil_data = ''
    if queries:
        labels = []
        for q in queries:
            parts = q['name'].split('.')
            if len(parts) >= 2:
                labels.append(parts[0])
        if labels:
            combined = ''.join(labels)
            # Try hex decode
            try:
                decoded = bytes.fromhex(combined).decode('utf-8', errors='replace')
                if is_printable_flag(decoded):
                    exfil_data = decoded
            except Exception:
                pass
            # If not hex, try direct
            if not exfil_data and is_printable_flag(combined):
                # Check if it looks like meaningful data
                flag_matches = re.findall(r'[a-zA-Z0-9_]+\{[^\}]{4,}\}', combined)
                if flag_matches:
                    exfil_data = combined

    return {
        'queries': queries[:200],
        'responses': responses[:200],
        'exfiltration_suspects': exfil_suspects,
        'long_subdomain_labels': long_subs[:50],
        'unique_domains': len(seen_queries),
        'exfil_reconstructed': exfil_data,
    }


# ---------------------------------------------------------------------------
# 7. HTTP Analyzer
# ---------------------------------------------------------------------------
def _analyze_http(packets):
    requests_list = []
    responses = []

    for i, pkt in enumerate(packets):
        if not pkt.haslayer(Raw) or not pkt.haslayer(TCP):
            continue

        payload = bytes(pkt[Raw].load)
        try:
            text = payload.decode('utf-8', errors='replace')
        except Exception:
            text = payload.decode('latin-1', errors='replace')

        lines = text.split('\r\n')
        if not lines:
            continue

        first_line = lines[0]

        # HTTP Request
        req_match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/', first_line)
        if req_match:
            method = req_match.group(1)
            path = req_match.group(2)

            headers = {}
            body = ''
            header_done = False
            for line in lines[1:]:
                if not header_done:
                    if line == '':
                        header_done = True
                    else:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            headers[parts[0].strip()] = parts[1].strip()
                else:
                    body += line + '\n'

            src_ip = pkt[IP].src if pkt.haslayer(IP) else '?'
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else '?'

            requests_list.append({
                'method': method,
                'path': path,
                'host': headers.get('Host', dst_ip),
                'headers': headers,
                'body': body.strip()[:500] if body.strip() else '',
                'src': src_ip,
                'dst': dst_ip,
                'packet_num': i + 1,
            })

        # HTTP Response
        resp_match = re.match(r'^HTTP/[\d.]+\s+(\d+)\s*(.*)', first_line)
        if resp_match:
            status_code = int(resp_match.group(1))
            status_text = resp_match.group(2)

            headers = {}
            body = ''
            header_done = False
            for line in lines[1:]:
                if not header_done:
                    if line == '':
                        header_done = True
                    else:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            headers[parts[0].strip()] = parts[1].strip()
                else:
                    body += line + '\n'

            responses.append({
                'status_code': status_code,
                'status_text': status_text,
                'content_type': headers.get('Content-Type', ''),
                'headers': headers,
                'body_preview': body.strip()[:500] if body.strip() else '',
                'packet_num': i + 1,
            })

    return {
        'requests': requests_list[:200],
        'responses': responses[:200],
        'total_requests': len(requests_list),
        'total_responses': len(responses),
    }


# ---------------------------------------------------------------------------
# 8. TCP Stream Reassembler
# ---------------------------------------------------------------------------
def _get_tcp_streams(packets):
    """Group packets by TCP stream and reassemble payloads."""
    streams = defaultdict(bytearray)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            key = tuple(sorted([(src, sport), (dst, dport)]))
            stream_key = f"{key[0][0]}:{key[0][1]} <-> {key[1][0]}:{key[1][1]}"
            streams[stream_key].extend(pkt[Raw].load)
    return streams


def _reassemble_streams(packets):
    streams = _get_tcp_streams(packets)
    result = []
    for stream_key, data in streams.items():
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = data.decode('latin-1', errors='replace')

        # Filter out non-printable characters for preview
        printable_preview = ''.join(c if c.isprintable() or c in '\n\r\t' else '\ufffd' for c in text[:2000])

        # Truncate for display
        preview = printable_preview[:2000]
        result.append({
            'stream': stream_key,
            'length': len(data),
            'preview': preview,
            'is_printable': all(c.isprintable() or c in '\n\r\t' for c in text[:200]),
        })

    # Sort by length descending
    result.sort(key=lambda x: x['length'], reverse=True)
    return result[:50]


# ---------------------------------------------------------------------------
# 9. String Extractor
# ---------------------------------------------------------------------------
def _extract_strings(packets):
    all_strings = []
    seen = set()

    interesting_patterns = [
        re.compile(r'password', re.I),
        re.compile(r'secret', re.I),
        re.compile(r'key', re.I),
        re.compile(r'token', re.I),
        re.compile(r'admin', re.I),
        re.compile(r'root', re.I),
        re.compile(r'login', re.I),
        re.compile(r'flag', re.I),
        re.compile(r'auth', re.I),
        re.compile(r'api[_\-]?key', re.I),
        re.compile(r'bearer', re.I),
        re.compile(r'session', re.I),
        re.compile(r'cookie', re.I),
        re.compile(r'private', re.I),
        re.compile(r'BEGIN .* KEY', re.I),
        re.compile(r'ctf\{', re.I),
        re.compile(r'hack', re.I),
        re.compile(r'exploit', re.I),
        re.compile(r'shell', re.I),
        re.compile(r'reverse', re.I),
        re.compile(r'payload', re.I),
        re.compile(r'inject', re.I),
    ]

    for i, pkt in enumerate(packets):
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            # Extract printable strings of length >= 6
            for match in re.finditer(rb'[\x20-\x7e]{6,}', payload):
                s = match.group(0).decode('ascii', errors='replace')
                if s not in seen:
                    seen.add(s)
                    is_interesting = any(p.search(s) for p in interesting_patterns)
                    all_strings.append({
                        'string': s[:300],
                        'packet_num': i + 1,
                        'interesting': is_interesting,
                    })

    # Also extract from UDP payloads
    for i, pkt in enumerate(packets):
        if pkt.haslayer(UDP) and pkt.haslayer(Raw) and not pkt.haslayer(DNS):
            payload = bytes(pkt[Raw].load)
            for match in re.finditer(rb'[\x20-\x7e]{6,}', payload):
                s = match.group(0).decode('ascii', errors='replace')
                if s not in seen:
                    seen.add(s)
                    is_interesting = any(p.search(s) for p in interesting_patterns)
                    all_strings.append({
                        'string': s[:300],
                        'packet_num': i + 1,
                        'interesting': is_interesting,
                    })

    # Sort: interesting first, then by length descending
    all_strings.sort(key=lambda x: (not x['interesting'], -len(x['string'])))
    return all_strings[:500]


# ---------------------------------------------------------------------------
# 10. File Carver
# ---------------------------------------------------------------------------
def _carve_files(packets, output_dir):
    """Extract files from TCP streams by detecting file signatures."""
    os.makedirs(output_dir, exist_ok=True)
    carved = []

    streams = _get_tcp_streams(packets)

    for stream_key, data in streams.items():
        data_bytes = bytes(data)
        for sig, (ext, mime) in FILE_SIGNATURES.items():
            offset = 0
            while True:
                idx = data_bytes.find(sig, offset)
                if idx == -1:
                    break

                # Determine file end heuristically
                file_data = data_bytes[idx:]

                # For known formats, try to find proper end
                if ext == 'png':
                    end = file_data.find(b'IEND')
                    if end != -1:
                        file_data = file_data[:end + 12]
                elif ext == 'jpg':
                    end = file_data.find(b'\xff\xd9')
                    if end != -1:
                        file_data = file_data[:end + 2]
                elif ext == 'pdf':
                    end = file_data.find(b'%%EOF')
                    if end != -1:
                        file_data = file_data[:end + 5]
                elif ext == 'zip':
                    # ZIP end of central directory
                    end = file_data.find(b'\x50\x4b\x05\x06')
                    if end != -1:
                        file_data = file_data[:end + 22]
                elif ext == 'gif':
                    end = file_data.find(b'\x00\x3b')  # GIF trailer
                    if end != -1:
                        file_data = file_data[:end + 2]
                else:
                    # Cap at 5MB
                    file_data = file_data[:5 * 1024 * 1024]

                if len(file_data) > 50:  # Skip tiny fragments
                    file_hash = hashlib.md5(file_data).hexdigest()[:8]
                    filename = f"carved_{file_hash}.{ext}"
                    filepath = os.path.join(output_dir, filename)
                    with open(filepath, 'wb') as f:
                        f.write(file_data)

                    carved.append({
                        'filename': filename,
                        'size': len(file_data),
                        'type': mime,
                        'stream': stream_key,
                    })

                offset = idx + len(sig)

    # Also carve from raw packets directly (for non-TCP transfers)
    raw_concat = bytearray()
    for pkt in packets:
        if pkt.haslayer(Raw):
            raw_concat.extend(pkt[Raw].load)

    raw_bytes = bytes(raw_concat)
    for sig, (ext, mime) in FILE_SIGNATURES.items():
        offset = 0
        while True:
            idx = raw_bytes.find(sig, offset)
            if idx == -1:
                break

            file_data = raw_bytes[idx:]

            if ext == 'png':
                end = file_data.find(b'IEND')
                if end != -1:
                    file_data = file_data[:end + 12]
            elif ext == 'jpg':
                end = file_data.find(b'\xff\xd9')
                if end != -1:
                    file_data = file_data[:end + 2]
            elif ext == 'pdf':
                end = file_data.find(b'%%EOF')
                if end != -1:
                    file_data = file_data[:end + 5]
            elif ext == 'zip':
                end = file_data.find(b'\x50\x4b\x05\x06')
                if end != -1:
                    file_data = file_data[:end + 22]
            else:
                file_data = file_data[:5 * 1024 * 1024]

            if len(file_data) > 50:
                file_hash = hashlib.md5(file_data).hexdigest()[:8]
                filename = f"carved_{file_hash}.{ext}"
                filepath = os.path.join(output_dir, filename)
                # Only write if not already carved
                if not os.path.exists(filepath):
                    with open(filepath, 'wb') as f:
                        f.write(file_data)
                    carved.append({
                        'filename': filename,
                        'size': len(file_data),
                        'type': mime,
                        'stream': 'raw_packets',
                    })

            offset = idx + len(sig)

    return carved


# ---------------------------------------------------------------------------
# 11. Suspicious Activity Detection
# ---------------------------------------------------------------------------
def _detect_suspicious(packets):
    findings = []

    # Large ICMP packets (potential data exfil)
    icmp_exfil_count = 0
    for i, pkt in enumerate(packets):
        if pkt.haslayer(ICMP) and len(pkt) > 100:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if len(payload) > 48:
                    icmp_exfil_count += 1
                    if icmp_exfil_count <= 5:  # Only show first 5
                        # Filter to printable preview
                        preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload[:100])
                        findings.append({
                            'type': 'Large ICMP Payload',
                            'detail': f'Packet #{i+1}: {len(payload)} bytes payload (possible data exfiltration)',
                            'packet_num': i + 1,
                            'data_preview': preview,
                        })

    if icmp_exfil_count > 5:
        findings.append({
            'type': 'ICMP Exfiltration Pattern',
            'detail': f'Total {icmp_exfil_count} ICMP packets with large payloads detected (showing first 5)',
            'packet_num': 0,
            'data_preview': '',
        })

    # Port scans: single source hitting many ports
    port_per_src = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            port_per_src[pkt[IP].src].add(pkt[TCP].dport)

    for src, ports in port_per_src.items():
        if len(ports) > 50:
            findings.append({
                'type': 'Possible Port Scan',
                'detail': f'{src} contacted {len(ports)} unique destination ports',
                'packet_num': 0,
                'data_preview': '',
            })

    # ARP spoofing: multiple IPs claiming same MAC or multiple MACs for same IP
    arp_ip_to_mac = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # is-at (reply)
            arp_ip_to_mac[pkt[ARP].psrc].add(pkt[ARP].hwsrc)

    for ip, macs in arp_ip_to_mac.items():
        if len(macs) > 1:
            findings.append({
                'type': 'Possible ARP Spoofing',
                'detail': f'IP {ip} associated with {len(macs)} different MAC addresses: {", ".join(macs)}',
                'packet_num': 0,
                'data_preview': '',
            })

    # DNS tunneling detection
    dns_query_lengths = []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNS][DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')
                if len(qname) > 50:
                    dns_query_lengths.append(qname)
            except Exception:
                pass

    if len(dns_query_lengths) > 10:
        findings.append({
            'type': 'Possible DNS Tunneling',
            'detail': f'{len(dns_query_lengths)} DNS queries with unusually long names (>50 chars)',
            'packet_num': 0,
            'data_preview': dns_query_lengths[0][:100] if dns_query_lengths else '',
        })

    # Unusual protocol on common ports
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            dport = pkt[TCP].dport
            payload = bytes(pkt[Raw].load)
            # Check for shell commands on HTTP ports
            if dport in (80, 443, 8080, 8443):
                try:
                    text = payload.decode('ascii', errors='replace')
                    shell_cmds = ['#!/bin', '/bin/sh', '/bin/bash', 'whoami', 'cat /etc', 'nc -e', 'exec(']
                    for cmd in shell_cmds:
                        if cmd in text:
                            findings.append({
                                'type': 'Possible Web Shell / RCE',
                                'detail': f'Shell command pattern "{cmd}" found on port {dport} (Packet #{packets.index(pkt)+1})',
                                'packet_num': packets.index(pkt) + 1,
                                'data_preview': text[:200],
                            })
                            break
                except Exception:
                    pass

    return findings
