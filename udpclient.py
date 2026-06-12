#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDP 客户端程序 - 模拟TCP可靠传输协议
实现功能：
1. 基于UDP的三次握手连接建立（带StudentID验证）
2. 滑动窗口流量控制（GBN协议）
3. 超时重传机制
4. RTT计算与统计
5. 丢包率统计

协议格式：
- 魔数(Magic): 2字节，固定为0xABCD，用于识别协议
- 数据包类型(Type): 1字节
  - 0x01: SYN - 连接请求（第一次握手）
  - 0x02: SYN_ACK - 连接确认（第二次握手）
  - 0x03: ACK - 连接确认（第三次握手）
  - 0x04: DATA - 数据报文
  - 0x05: DATA_ACK - 数据确认

三次握手流程：
1. Client → Server: SYN (携带客户端初始序列号client_isn和StudentID)
2. Server → Client: SYN_ACK (确认client_isn，携带服务端初始序列号server_isn)
3. Client → Server: ACK (确认server_isn，连接建立完成)

StudentID验证机制：
- 客户端：学号后4位 XOR 0x5A3C
- 服务端：收到的值 XOR 0x5A3C，检查结果是否在0-9999范围内
"""

import socket
import struct
import time
import sys
import math
import random
import pandas as pd

# 学号验证XOR密钥（作业要求）
STUDENT_ID_XOR = 0x5A3C
# 协议魔数，用于识别自定义协议数据包
MAGIC_NUMBER = 0xABCD

# 数据包类型枚举（三次握手版本）
class PacketType:
    SYN = 0x01        # 第一次握手：连接请求
    SYN_ACK = 0x02    # 第二次握手：连接确认
    ACK = 0x03        # 第三次握手：连接确认
    DATA = 0x04       # 数据报文
    DATA_ACK = 0x05   # 数据确认

class UDPClient:
    """
    UDP客户端类，实现可靠数据传输
    """
    def __init__(self, server_ip, server_port, student_id_last4):
        """
        初始化客户端
        :param server_ip: 服务器IP地址
        :param server_port: 服务器端口号
        :param student_id_last4: 学号后4位数字
        """
        self.server_ip = server_ip
        self.server_port = server_port
        # 学号后4位与XOR密钥进行异或运算，用于连接验证
        self.student_id = student_id_last4 ^ STUDENT_ID_XOR
        
        # 创建UDP套接字
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 设置超时时间为300ms（作业要求）
        self.socket.settimeout(0.3)
        
        # 序列号（用于三次握手）
        self.client_isn = random.randint(0, 255)  # 客户端初始序列号
        self.server_isn = None                    # 服务端初始序列号
        
        # 统计数据
        self.rtt_list = []              # 存储每个数据包的RTT
        self.total_packets_sent = 0     # 发送的总数据包数
        self.retransmitted_packets = 0  # 重传的数据包数
    
    # ==================== 三次握手相关方法 ====================
    
    def pack_syn(self):
        """
        打包SYN数据包（第一次握手）
        :return: 打包后的字节流
        格式：魔数(2B) + 类型(1B) + 客户端初始序列号(1B) + StudentID(4B)
        """
        return struct.pack('!HBBL', MAGIC_NUMBER, PacketType.SYN, self.client_isn, self.student_id)
    
    def unpack_syn_ack(self, data):
        """
        解包SYN_ACK数据包（第二次握手）
        :param data: 接收到的字节流
        :return: (server_isn, ack_num) 或 None
        格式：魔数(2B) + 类型(1B) + 服务端初始序列号(1B) + 确认号(1B)
        """
        if len(data) < 5:
            return None
        magic, packet_type, server_isn, ack_num = struct.unpack('!HBBB', data[:5])
        # 验证魔数和类型
        if magic != MAGIC_NUMBER or packet_type != PacketType.SYN_ACK:
            return None
        # 验证确认号是否正确（应该确认client_isn+1）
        if ack_num != (self.client_isn + 1) % 256:
            return None
        return server_isn, ack_num
    
    def pack_ack(self, ack_num):
        """
        打包ACK数据包（第三次握手）
        :param ack_num: 确认号（确认server_isn+1）
        :return: 打包后的字节流
        格式：魔数(2B) + 类型(1B) + 确认号(1B)
        """
        return struct.pack('!HBB', MAGIC_NUMBER, PacketType.ACK, ack_num)
    
    def connect(self):
        """
        建立连接（模拟TCP三次握手）
        三次握手流程：
        1. Client → Server: SYN (client_isn, StudentID)
        2. Server → Client: SYN_ACK (server_isn, ack=client_isn+1)
        3. Client → Server: ACK (ack=server_isn+1)
        :return: True表示连接成功，False表示失败
        """
        print(f"【三次握手开始】")
        print(f"客户端初始序列号(ISN): {self.client_isn}")
        print(f"Connecting to {self.server_ip}:{self.server_port} with StudentID: {self.student_id}")
        
        # 最多尝试3次连接
        for attempt in range(3):
            try:
                # ========== 第一次握手：发送SYN ==========
                syn_packet = self.pack_syn()
                self.socket.sendto(syn_packet, (self.server_ip, self.server_port))
                print(f"[第一次握手] 发送SYN: client_isn={self.client_isn}, StudentID={self.student_id}")
                
                # ========== 第二次握手：接收SYN_ACK ==========
                data, _ = self.socket.recvfrom(1024)#等待监听SYN_ACK数据包，最多1024字节
                result = self.unpack_syn_ack(data)
                if result is None:
                    print(f"连接尝试 {attempt + 1} 失败：收到无效的SYN_ACK")
                    continue
                
                server_isn, ack_num = result
                self.server_isn = server_isn
                print(f"[第二次握手] 收到SYN_ACK: server_isn={server_isn}, ack={ack_num}")
                
                # ========== 第三次握手：发送ACK ==========
                # 确认号应该是server_isn+1
                ack_packet = self.pack_ack((server_isn + 1) % 256)#适配报文里 1 字节的 ACK 字段
                self.socket.sendto(ack_packet, (self.server_ip, self.server_port))
                print(f"[第三次握手] 发送ACK: ack={(server_isn + 1) % 256}")
                
                print("【三次握手完成，连接建立成功】")
                return True
                
            except socket.timeout:
                print(f"连接尝试 {attempt + 1} 超时")
        
        print("连接失败：3次尝试后仍无法建立连接")
        return False
    
    # ==================== 数据传输相关方法 ====================
    
    def pack_data_packet(self, seq_num, start_byte, end_byte, payload):
        """
        打包数据报文
        :param seq_num: 序列号
        :param start_byte: 数据起始字节位置
        :param end_byte: 数据结束字节位置
        :param payload: 数据载荷
        :return: 打包后的字节流
        格式：魔数(2B) + 类型(1B) + 序列号(1B) + 起始字节(2B) + 结束字节(2B) + 载荷
        """
        return struct.pack('!HBBHH', MAGIC_NUMBER, PacketType.DATA, seq_num, start_byte, end_byte) + payload
    
    def unpack_data_ack(self, data):
        """
        解包数据确认报文
        :param data: 接收到的字节流
        :return: (序列号, 小时, 分钟, 秒) 或 None
        """
        if len(data) < 7:
            return None
        # 解包：魔数(2B) + 类型(1B) + 序列号(1B) + 小时(1B) + 分钟(1B) + 秒(1B)
        magic, packet_type, seq_num, hours, minutes, seconds = struct.unpack('!HBBBBB', data[:7])
        # 验证魔数和类型
        if magic != MAGIC_NUMBER or packet_type != PacketType.DATA_ACK:
            return None
        return seq_num, hours, minutes, seconds
    
    def send_data(self, total_packets=30, window_size=5, packet_size=80):
        """
        发送数据（实现GBN滑动窗口协议）
        :param total_packets: 要发送的数据包总数
        :param window_size: 滑动窗口大小
        :param packet_size: 每个数据包的数据载荷大小
        :return: RTT列表
        """
        base = 0                    # 窗口起始序列号
        next_seq_num = 0            # 下一个要发送的序列号
        sent_packets = {}           # 存储已发送但未确认的数据包信息
        rtt_values = []             # 存储RTT值
        acked_count = 0             # 已确认的数据包数
        
        # 循环直到所有数据包都被确认
        while acked_count < total_packets:
            # 发送窗口内的所有数据包
            while next_seq_num < base + window_size and next_seq_num < total_packets:
                # 计算当前数据包的数据范围
                start_byte = next_seq_num * packet_size
                end_byte = start_byte + packet_size - 1
                # 生成数据载荷（用'x'填充）#模拟业务数据
                payload = b'x' * packet_size
                
                # 打包数据报文
                packet = self.pack_data_packet(next_seq_num, start_byte, end_byte, payload)
                # 发送数据包
                self.socket.sendto(packet, (self.server_ip, self.server_port))
                
                # 记录发送信息
                sent_packets[next_seq_num] = {
                    'send_time': time.time(),  # 发送时间戳
                    'start_byte': start_byte,
                    'end_byte': end_byte,
                    'retransmitted': False
                }
                self.total_packets_sent += 1
                
                # 打印发送信息
                print(f"第 {next_seq_num} 个（第 {start_byte}~{end_byte} 字节）client端已经发送")
                next_seq_num += 1
            
            # 等待ACK或超时
            try:
                # 接收响应
                data, _ = self.socket.recvfrom(1024)
                # 解析ACK
                result = self.unpack_data_ack(data)
                if result is not None:
                    ack_seq, hours, minutes, seconds = result
                    
                    # 如果收到的ACK序列号大于等于窗口起始，说明可以滑动窗口
                    if ack_seq >= base:
                        # 计算RTT（毫秒）
                        rtt = (time.time() - sent_packets[ack_seq]['send_time']) * 1000
                        rtt_values.append(rtt)
                        # 格式化服务器时间
                        server_time = f"{hours:02d}-{minutes:02d}-{seconds:02d}"
                        
                        # 获取确认数据包的字节范围
                        start_byte = sent_packets[ack_seq]['start_byte']
                        end_byte = sent_packets[ack_seq]['end_byte']
                        print(f"第 {ack_seq} 个（第 {start_byte}~{end_byte} 字节）server端已经收到，RTT是 {rtt:.2f} ms")
                        
                        # 滑动窗口：移动base到确认序列号+1
                        base = ack_seq + 1
                        acked_count = base
            except socket.timeout:
                # 超时处理：重传窗口内所有未确认的数据包
                print("Timeout occurred, retransmitting unacknowledged packets")
                for seq_num in range(base, min(base + window_size, total_packets)):
                    if seq_num in sent_packets:
                        start_byte = sent_packets[seq_num]['start_byte']
                        end_byte = sent_packets[seq_num]['end_byte']
                        payload = b'x' * packet_size
                        packet = self.pack_data_packet(seq_num, start_byte, end_byte, payload)
                        # 重传数据包
                        self.socket.sendto(packet, (self.server_ip, self.server_port))
                        # 更新发送时间
                        sent_packets[seq_num]['send_time'] = time.time()
                        sent_packets[seq_num]['retransmitted'] = True
                        self.total_packets_sent += 1
                        self.retransmitted_packets += 1
                        print(f"重传第 {seq_num} 个（第 {start_byte}~{end_byte} 字节）数据包")
        
        # 保存RTT列表
        self.rtt_list = rtt_values
        return rtt_values
    
    def calculate_stats(self):
        """
        计算统计信息（使用pandas进行统计计算）
        :return: 统计字典
        """
        if not self.rtt_list:
            return None
        
        # 使用pandas Series进行统计计算
        rtt_series = pd.Series(self.rtt_list)
        
        # 使用pandas内置函数计算统计量
        min_rtt = rtt_series.min()          # 最小RTT
        max_rtt = rtt_series.max()          # 最大RTT
        avg_rtt = rtt_series.mean()         # 平均RTT
        std_dev = rtt_series.std()          # 标准差（pandas默认使用样本标准差）
        
        # 计算丢包率
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
        """
        打印汇总统计信息
        """
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
    """
    主函数：解析命令行参数并运行客户端
    """
    # 检查命令行参数
    if len(sys.argv) != 4:
        print("Usage: python udpclient.py <server_ip> <server_port> <student_id_last4>")
        print("Example: python udpclient.py 127.0.0.1 12345 2906")
        sys.exit(1)
    
    # 解析参数
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    student_id_last4 = int(sys.argv[3])
    
    # 创建客户端实例
    client = UDPClient(server_ip, server_port, student_id_last4)
    
    # 尝试连接（三次握手）
    if not client.connect():
        sys.exit(1)
    
    # 发送数据
    client.send_data(total_packets=30, window_size=5, packet_size=80)
    
    # 打印统计信息
    client.print_summary()
    
    # 关闭套接字
    client.socket.close()

if __name__ == "__main__":
    main()