import socket
import struct
import time
import sys
import math

STUDENT_ID_XOR = 0x5A3C
MAGIC_NUMBER = 0xABCD

class PacketType:
    CONNECT_REQ = 0x01
    CONNECT_ACK = 0x02
    DATA = 0x03
    DATA_ACK = 0x04

class UDPClient:
    def __init__(self, server_ip, server_port, student_id_last4):
        self.server_ip = server_ip
        self.server_port = server_port
        self.student_id = student_id_last4 ^ STUDENT_ID_XOR
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(0.3)
        self.rtt_list = []
        self.total_packets_sent = 0
        self.retransmitted_packets = 0
        
    def pack_connect_req(self):
        return struct.pack('!HBL', MAGIC_NUMBER, PacketType.CONNECT_REQ, self.student_id)
    
    def unpack_connect_ack(self, data):
        if len(data) < 4:
            return False
        magic, packet_type, success = struct.unpack('!HBB', data[:4])
        return magic == MAGIC_NUMBER and packet_type == PacketType.CONNECT_ACK and success == 1
    
    def pack_data_packet(self, seq_num, start_byte, end_byte, payload):
        return struct.pack('!HBBHH', MAGIC_NUMBER, PacketType.DATA, seq_num, start_byte, end_byte) + payload
    
    def unpack_data_ack(self, data):
        if len(data) < 7:
            return None
        magic, packet_type, seq_num, hours, minutes, seconds = struct.unpack('!HBBBBB', data[:7])
        if magic != MAGIC_NUMBER or packet_type != PacketType.DATA_ACK:
            return None
        return seq_num, hours, minutes, seconds
    
    def connect(self):
        print(f"Connecting to {self.server_ip}:{self.server_port} with StudentID: {self.student_id}")
        packet = self.pack_connect_req()
        
        for attempt in range(3):
            try:
                self.socket.sendto(packet, (self.server_ip, self.server_port))
                data, _ = self.socket.recvfrom(1024)
                if self.unpack_connect_ack(data):
                    print("Connection established successfully")
                    return True
                else:
                    print("Connection rejected by server")
                    return False
            except socket.timeout:
                print(f"Connection attempt {attempt + 1} timed out")
        
        print("Connection failed after 3 attempts")
        return False
    
    def send_data(self, total_packets=30, window_size=5, packet_size=80):
        base = 0
        next_seq_num = 0
        packets_to_send = total_packets
        sent_packets = {}
        rtt_values = []
        acked_count = 0
        
        while acked_count < total_packets:
            while next_seq_num < base + window_size and next_seq_num < total_packets:
                start_byte = next_seq_num * packet_size
                end_byte = start_byte + packet_size - 1
                payload = b'x' * packet_size
                
                packet = self.pack_data_packet(next_seq_num, start_byte, end_byte, payload)
                self.socket.sendto(packet, (self.server_ip, self.server_port))
                sent_packets[next_seq_num] = {
                    'send_time': time.time(),
                    'start_byte': start_byte,
                    'end_byte': end_byte,
                    'retransmitted': False
                }
                self.total_packets_sent += 1
                print(f"第 {next_seq_num} 个（第 {start_byte}~{end_byte} 字节）client端已经发送")
                next_seq_num += 1
            
            try:
                data, _ = self.socket.recvfrom(1024)
                result = self.unpack_data_ack(data)
                if result is not None:
                    ack_seq, hours, minutes, seconds = result
                    
                    if ack_seq >= base:
                        rtt = (time.time() - sent_packets[ack_seq]['send_time']) * 1000
                        rtt_values.append(rtt)
                        server_time = f"{hours:02d}-{minutes:02d}-{seconds:02d}"
                        
                        start_byte = sent_packets[ack_seq]['start_byte']
                        end_byte = sent_packets[ack_seq]['end_byte']
                        print(f"第 {ack_seq} 个（第 {start_byte}~{end_byte} 字节）server端已经收到，RTT是 {rtt:.2f} ms")
                        
                        base = ack_seq + 1
                        acked_count = base
            except socket.timeout:
                print("Timeout occurred, retransmitting unacknowledged packets")
                for seq_num in range(base, min(base + window_size, total_packets)):
                    if seq_num in sent_packets:
                        start_byte = sent_packets[seq_num]['start_byte']
                        end_byte = sent_packets[seq_num]['end_byte']
                        payload = b'x' * packet_size
                        packet = self.pack_data_packet(seq_num, start_byte, end_byte, payload)
                        self.socket.sendto(packet, (self.server_ip, self.server_port))
                        sent_packets[seq_num]['send_time'] = time.time()
                        sent_packets[seq_num]['retransmitted'] = True
                        self.total_packets_sent += 1
                        self.retransmitted_packets += 1
                        print(f"重传第 {seq_num} 个（第 {start_byte}~{end_byte} 字节）数据包")
        
        self.rtt_list = rtt_values
        return rtt_values
    
    def calculate_stats(self):
        if not self.rtt_list:
            return None
        
        min_rtt = min(self.rtt_list)
        max_rtt = max(self.rtt_list)
        avg_rtt = sum(self.rtt_list) / len(self.rtt_list)
        
        variance = sum((rtt - avg_rtt) ** 2 for rtt in self.rtt_list) / len(self.rtt_list)
        std_dev = math.sqrt(variance)
        
        drop_rate = ((self.total_packets_sent - len(self.rtt_list)) / self.total_packets_sent) * 100
        
        return {
            'min_rtt': min_rtt,
            'max_rtt': max_rtt,
            'avg_rtt': avg_rtt,
            'std_dev': std_dev,
            'drop_rate': drop_rate,
            'total_sent': self.total_packets_sent,
            'successful_acks': len(self.rtt_list),
            'retransmitted': self.retransmitted_packets
        }
    
    def print_summary(self):
        stats = self.calculate_stats()
        if stats is None:
            print("No data collected")
            return
        
        print("\n【汇总】")
        print(f"丢包率: {stats['drop_rate']:.2f}%")
        print(f"最大RTT: {stats['max_rtt']:.2f} ms")
        print(f"最小RTT: {stats['min_rtt']:.2f} ms")
        print(f"平均RTT: {stats['avg_rtt']:.2f} ms")
        print(f"RTT标准差: {stats['std_dev']:.2f} ms")
        print(f"实际发送的UDP包数: {stats['total_sent']}")
        print(f"成功确认的包数: {stats['successful_acks']}")
        print(f"重传的包数: {stats['retransmitted']}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python udpclient.py <server_ip> <server_port> <student_id_last4>")
        print("Example: python udpclient.py 127.0.0.1 12345 1234")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    student_id_last4 = int(sys.argv[3])
    
    client = UDPClient(server_ip, server_port, student_id_last4)
    
    if not client.connect():
        sys.exit(1)
    
    client.send_data(total_packets=30, window_size=5, packet_size=80)
    client.print_summary()
    client.socket.close()

if __name__ == "__main__":
    main()