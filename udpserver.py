import socket
import random
import struct
import time
import sys

STUDENT_ID_XOR = 0x5A3C
MAGIC_NUMBER = 0xABCD

class PacketType:
    CONNECT_REQ = 0x01
    CONNECT_ACK = 0x02
    DATA = 0x03
    DATA_ACK = 0x04

class UDPServer:
    def __init__(self, port, drop_rate=0.1):
        self.port = port
        self.drop_rate = drop_rate
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('', port))
        self.clients = {}
        self.log_file = open('run_log.txt', 'w')
        
    def log(self, message):
        current_time = time.localtime()
        ms = int((time.time() - int(time.time())) * 1000)
        timestamp = f"{time.strftime('%Y-%m-%d %H:%M:%S', current_time)}.{ms:03d}"
        log_entry = f"[{timestamp}] {message}\n"
        print(log_entry.strip())
        self.log_file.write(log_entry)
        self.log_file.flush()
        
    def validate_student_id(self, student_id):
        result = student_id ^ STUDENT_ID_XOR
        return 0 <= result <= 9999
    
    def unpack_connect_req(self, data):
        if len(data) < 7:
            return None
        magic, packet_type, student_id = struct.unpack('!HBL', data[:7])
        if magic != MAGIC_NUMBER or packet_type != PacketType.CONNECT_REQ:
            return None
        return student_id
    
    def pack_connect_ack(self, success):
        return struct.pack('!HBB', MAGIC_NUMBER, PacketType.CONNECT_ACK, 1 if success else 0)
    
    def unpack_data_packet(self, data):
        if len(data) < 10:
            return None
        magic, packet_type, seq_num, start_byte, end_byte = struct.unpack('!HBBHH', data[:8])
        if magic != MAGIC_NUMBER or packet_type != PacketType.DATA:
            return None
        payload = data[8:]
        return seq_num, start_byte, end_byte, payload
    
    def pack_data_ack(self, seq_num, server_time):
        hours = server_time.tm_hour
        minutes = server_time.tm_min
        seconds = server_time.tm_sec
        return struct.pack('!HBBBBB', MAGIC_NUMBER, PacketType.DATA_ACK, seq_num, hours, minutes, seconds)
    
    def handle_client(self, data, addr):
        if len(data) < 4:
            return
        
        magic, packet_type = struct.unpack('!HB', data[:3])
        
        if packet_type == PacketType.CONNECT_REQ:
            student_id = self.unpack_connect_req(data)
            if student_id is None:
                self.log(f"Invalid connect request from {addr}")
                return
            
            if self.validate_student_id(student_id):
                self.clients[addr] = {'last_seq': -1, 'connected': True}
                self.log(f"Connection established with {addr}, StudentID: {student_id}")
                self.socket.sendto(self.pack_connect_ack(True), addr)
            else:
                self.log(f"Invalid StudentID {student_id} from {addr}, connection rejected")
                self.socket.sendto(self.pack_connect_ack(False), addr)
                
        elif packet_type == PacketType.DATA:
            if addr not in self.clients or not self.clients[addr]['connected']:
                self.log(f"Data packet from unconnected client {addr}")
                return
            
            result = self.unpack_data_packet(data)
            if result is None:
                self.log(f"Invalid data packet from {addr}")
                return
            
            seq_num, start_byte, end_byte, payload = result
            
            if random.random() < self.drop_rate:
                self.log(f"Dropped packet {seq_num} ({start_byte}-{end_byte} bytes) from {addr}")
                return
            
            self.clients[addr]['last_seq'] = seq_num
            self.log(f"Received packet {seq_num} ({start_byte}-{end_byte} bytes) from {addr}")
            
            ack_packet = self.pack_data_ack(seq_num, time.localtime())
            self.socket.sendto(ack_packet, addr)
            self.log(f"Sent ACK for packet {seq_num} to {addr}")
    
    def run(self):
        self.log(f"UDP Server started on port {self.port}")
        self.log(f"Drop rate: {self.drop_rate * 100}%")
        
        try:
            while True:
                data, addr = self.socket.recvfrom(1024)
                self.handle_client(data, addr)
        except KeyboardInterrupt:
            self.log("Server shutting down...")
            self.log_file.close()
            self.socket.close()

def main():
    if len(sys.argv) != 2:
        print("Usage: python udpserver.py <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    server = UDPServer(port, drop_rate=0.2)
    server.run()

if __name__ == "__main__":
    main()