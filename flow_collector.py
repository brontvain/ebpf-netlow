from bcc import BPF
import socket
import struct
import time
import os
import logging
from logging.handlers import RotatingFileHandler

INTERFACE = os.environ.get("INTERFACE", "eth0")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "/tmp/flows.txt")
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", 5 * 1024 * 1024))  # 5MB default
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", 5))
NETFLOW_COLLECTOR = os.environ.get("NETFLOW_COLLECTOR")  # e.g. "192.168.1.100"
NETFLOW_PORT = int(os.environ.get("NETFLOW_PORT", 2055))

b = BPF(src_file="flow_collector.c")
fn = b.load_func("xdp_flow_collector", BPF.XDP)
b.attach_xdp(dev=INTERFACE, fn=fn, flags=0)

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack("I", ip))

def send_netflow_v5(flows, seq, uptime, collector, port):
    # NetFlow v5 header: 24 bytes
    # NetFlow v5 record: 48 bytes
    MAX_RECORDS_PER_PACKET = 30  # Maximum number of flow records per packet
    
    # Convert flows dictionary to list for batch processing
    flow_items = list(flows.items())
    
    # Process flows in batches
    for i in range(0, len(flow_items), MAX_RECORDS_PER_PACKET):
        batch = flow_items[i:i + MAX_RECORDS_PER_PACKET]
        version = 5
        count = len(batch)
        sys_uptime = uptime
        unix_secs = int(time.time())
        unix_nsecs = int((time.time() % 1) * 1e9)
        flow_sequence = seq + i
        engine_type = 0
        engine_id = 0
        sampling = 0
        
        header = struct.pack('!HHIIIIBBBxxxHH',
            version, count, sys_uptime, unix_secs, unix_nsecs, flow_sequence,
            engine_type, engine_id, sampling, 0, 0)
        
        records = b''
        for k, v in batch:
            # srcaddr, dstaddr, nexthop, input, output, dPkts, dOctets, first, last, srcport, dstport, tcp_flags, prot, tos, src_as, dst_as, src_mask, dst_mask, pad
            records += struct.pack('!IIIHH IIII HHBBBBHHBB',
                k.src_ip, k.dst_ip, 0, 0, 0,  # srcaddr, dstaddr, nexthop, input, output
                v.value, 0, uptime, uptime,  # dPkts, dOctets, first, last
                socket.ntohs(k.src_port), socket.ntohs(k.dst_port),  # srcport, dstport
                0, k.proto, 0,  # tcp_flags, prot, tos
                0, 0, 0, 0, 0)  # src_as, dst_as, src_mask, dst_mask, pad
        
        packet = header + records
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(packet, (collector, port))
        finally:
            sock.close()

# Set up rotating logger
logger = logging.getLogger("FlowLogger")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(OUTPUT_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.handlers = []
logger.addHandler(handler)

netflow_seq = 0
start_time = time.time()

try:
    print(f"Collecting flows on {INTERFACE}. Output: {OUTPUT_FILE} (rotation: {LOG_MAX_BYTES} bytes, {LOG_BACKUP_COUNT} backups)")
    if NETFLOW_COLLECTOR:
        print(f"NetFlow export enabled: {NETFLOW_COLLECTOR}:{NETFLOW_PORT}")
    while True:
        flows = b.get_table("flows")
        # Write each flow as a log line
        for k, v in flows.items():
            logger.info(f"{ip_to_str(k.src_ip)}:{socket.ntohs(k.src_port)} -> {ip_to_str(k.dst_ip)}:{socket.ntohs(k.dst_port)} proto={k.proto} count={v.value}")
        # NetFlow export
        if NETFLOW_COLLECTOR and len(flows) > 0:
            uptime = int((time.time() - start_time) * 1000)
            send_netflow_v5(flows, netflow_seq, uptime, NETFLOW_COLLECTOR, NETFLOW_PORT)
            netflow_seq += len(flows)
        time.sleep(10)
except KeyboardInterrupt:
    pass
finally:
    b.remove_xdp(dev=INTERFACE, flags=0) 