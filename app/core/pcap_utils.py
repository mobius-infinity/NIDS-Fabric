import os
import subprocess
from flask import current_app

FULL_53_FEATURES = [
    '%IPV4_SRC_ADDR', '%IPV4_DST_ADDR', '%L4_SRC_PORT', '%L4_DST_PORT',
    '%PROTOCOL', '%L7_PROTO', '%IN_BYTES', '%OUT_BYTES',
    '%IN_PKTS', '%OUT_PKTS', '%FLOW_DURATION_MILLISECONDS',
    '%TCP_FLAGS', '%CLIENT_TCP_FLAGS', '%SERVER_TCP_FLAGS',
    '%DURATION_IN', '%DURATION_OUT', '%MIN_TTL', '%MAX_TTL',
    '%LONGEST_FLOW_PKT', '%SHORTEST_FLOW_PKT', '%MIN_IP_PKT_LEN', '%MAX_IP_PKT_LEN',
    '%SRC_TO_DST_SECOND_BYTES', '%DST_TO_SRC_SECOND_BYTES',
    '%RETRANSMITTED_IN_BYTES', '%RETRANSMITTED_IN_PKTS',
    '%RETRANSMITTED_OUT_BYTES', '%RETRANSMITTED_OUT_PKTS',
    '%SRC_TO_DST_AVG_THROUGHPUT', '%DST_TO_SRC_AVG_THROUGHPUT',
    '%NUM_PKTS_UP_TO_128_BYTES', '%NUM_PKTS_128_TO_256_BYTES',
    '%NUM_PKTS_256_TO_512_BYTES', '%NUM_PKTS_512_TO_1024_BYTES',
    '%NUM_PKTS_1024_TO_1514_BYTES', '%TCP_WIN_MAX_IN', '%TCP_WIN_MAX_OUT',
    '%ICMP_TYPE', '%ICMP_IPV4_TYPE', '%DNS_QUERY_ID', '%DNS_QUERY_TYPE',
    '%DNS_TTL_ANSWER', '%FTP_COMMAND_RET_CODE',
    '%FLOW_START_MILLISECONDS', '%FLOW_END_MILLISECONDS',
    '%SRC_TO_DST_IAT_MIN', '%SRC_TO_DST_IAT_MAX', '%SRC_TO_DST_IAT_AVG', '%SRC_TO_DST_IAT_STDDEV',
    '%DST_TO_SRC_IAT_MIN', '%DST_TO_SRC_IAT_MAX', '%DST_TO_SRC_IAT_AVG', '%DST_TO_SRC_IAT_STDDEV'
]


# Danh sách Feature cần thiết cho nprobe (giống file gốc)
LIGHTGBM_23_FEATURES = [
    '%PROTOCOL', '%L7_PROTO', '%IN_PKTS', '%OUT_PKTS', '%FLOW_DURATION_MILLISECONDS',
    '%SERVER_TCP_FLAGS', '%DURATION_OUT', '%MIN_TTL', '%MAX_TTL', '%MAX_IP_PKT_LEN',
    '%RETRANSMITTED_IN_BYTES', '%SRC_TO_DST_AVG_THROUGHPUT', '%DST_TO_SRC_AVG_THROUGHPUT',
    '%NUM_PKTS_UP_TO_128_BYTES', '%NUM_PKTS_128_TO_256_BYTES', '%NUM_PKTS_256_TO_512_BYTES',
    '%NUM_PKTS_512_TO_1024_BYTES', '%NUM_PKTS_1024_TO_1514_BYTES', '%TCP_WIN_MAX_OUT',
    '%ICMP_IPV4_TYPE', '%DNS_QUERY_ID', '%DNS_QUERY_TYPE', '%FTP_COMMAND_RET_CODE'
]

DISPLAY_FEATURES = ['%IPV4_SRC_ADDR', '%IPV4_DST_ADDR', '%L4_SRC_PORT', '%L4_DST_PORT', '%FLOW_START_MILLISECONDS', '%FLOW_END_MILLISECONDS']

# Feature list cho DNN và Random Forest (bỏ dấu %)
FEATURES_DNN_RF = [f[1:] for f in LIGHTGBM_23_FEATURES]

def convert_pcap_to_csv(pcap_path, dump_dir):
    """
    Sử dụng nprobe để trích xuất feature từ PCAP ra CSV.
    """
    nprobe_path = current_app.config['NPROBE_PATH']
    
    # Tạo chuỗi template cho nprobe
    full_feature_list = FULL_53_FEATURES
    template_str = "".join([f.strip() for f in full_feature_list])
    
    if not os.path.exists(nprobe_path):
        current_app.logger.error(f"nprobe not found at {nprobe_path}")
        return None

    abs_dump = os.path.abspath(dump_dir)
    os.makedirs(abs_dump, exist_ok=True)
    
    cmd = [
        nprobe_path, 
        "-i", os.path.abspath(pcap_path), 
        "-V", "9", 
        "-n", "none", 
        "-T", template_str, 
        "--dump-path", abs_dump, 
        "--dump-format", "t", 
        "--csv-separator", "#",
        "--dont-reforge-timestamps",
        "-F", "ip"  # Filter chỉ IPv4 flows
    ]
    #print(f"[nProbe] Running command: {' '.join(cmd)}")
    try:
        # Chạy lệnh với timeout 600s
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        
        # Tìm các file csv được tạo ra (chỉ lấy .flows files từ nprobe)
        found_files = [
            os.path.join(r, f) 
            for r, d, fs in os.walk(abs_dump) 
            for f in fs 
            if f.endswith('.flows') and os.path.getsize(os.path.join(r, f)) > 0
        ]
        
        if not found_files:
            return None
        
        # nprobe trial version creates only one file, copy it directly
        out_path = os.path.join(dump_dir, "processed.csv")
        import shutil
        shutil.copy(found_files[0], out_path)
        
        return out_path
        
    except Exception as e:
        current_app.logger.exception("PCAP conversion error")
        return None

