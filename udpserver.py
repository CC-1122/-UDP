#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDP 服务端程序 - 模拟TCP可靠传输协议
实现功能：
1. 三次握手连接建立（带StudentID验证）
2. 随机丢包模拟
3. 数据包接收与确认
4. 运行日志记录

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
- 收到的值 XOR 0x5A3C，检查结果是否在0-9999范围内
"""

import socket
import random
import struct
import time
import sys

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

class UDPServer:
    """
    UDP服务端类，实现可靠数据接收
    """
    def __init__(self, port, drop_rate=0.1):
        """
        初始化服务端
        :param port: 监听端口号
        :param drop_rate: 丢包率（0.0-1.0）
        """
        self.port = port
        self.drop_rate = drop_rate  # 丢包率，用于模拟网络丢包
        
        # 创建UDP套接字
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 设置SO_REUSEADDR选项，允许端口快速复用
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 绑定端口
        self.socket.bind(('', port))
        
        # 存储已连接客户端信息（三次握手版本）
        # 格式: {地址: {'client_isn': 客户端ISN, 'server_isn': 服务端ISN, 
        #              'connected': 是否完成三次握手, 'handshake_step': 当前握手阶段}}
        self.clients = {}
        
        # 打开日志文件
        self.log_file = open('run_log.txt', 'w')
        
    def log(self, message):
        """
        记录日志（带毫秒级时间戳）
        :param message: 日志消息
        """
        # 获取当前时间
        current_time = time.localtime()
        # 获取毫秒部分
        ms = int((time.time() - int(time.time())) * 1000)
        # 格式化时间戳
        timestamp = f"{time.strftime('%Y-%m-%d %H:%M:%S', current_time)}.{ms:03d}"
        # 组装日志条目
        log_entry = f"[{timestamp}] {message}\n"
        # 打印到控制台
        print(log_entry.strip())
        # 写入日志文件
        self.log_file.write(log_entry)
        # 立即刷新缓冲区
        self.log_file.flush()
        
    def validate_student_id(self, student_id):
        """
        验证StudentID是否合法
        :param student_id: 收到的StudentID值
        :return: True表示合法，False表示非法
        验证规则：收到的值 XOR 0x5A3C 后必须在0-9999范围内
        """
        # 进行XOR运算解密
        result = student_id ^ STUDENT_ID_XOR
        # 检查是否在合法范围内
        return 0 <= result <= 9999
    
    # ==================== 三次握手相关方法 ====================
    
    def unpack_syn(self, data):
        """
        解包SYN数据包（第一次握手）
        :param data: 接收到的字节流
        :return: (client_isn, student_id) 或 None
        格式：魔数(2B) + 类型(1B) + 客户端初始序列号(1B) + StudentID(4B)
        """
        if len(data) < 8:
            return None
        magic, packet_type, client_isn, student_id = struct.unpack('!HBBL', data[:8])
        # 验证魔数和类型
        if magic != MAGIC_NUMBER or packet_type != PacketType.SYN:
            return None
        return client_isn, student_id
    
    def pack_syn_ack(self, server_isn, ack_num):
        """
        打包SYN_ACK数据包（第二次握手）
        :param server_isn: 服务端初始序列号
        :param ack_num: 确认号（确认client_isn+1）
        :return: 打包后的字节流
        格式：魔数(2B) + 类型(1B) + 服务端初始序列号(1B) + 确认号(1B)
        """
        return struct.pack('!HBBB', MAGIC_NUMBER, PacketType.SYN_ACK, server_isn, ack_num)
    
    def unpack_ack(self, data):
        """
        解包ACK数据包（第三次握手）
        :param data: 接收到的字节流
        :return: ack_num 或 None
        格式：魔数(2B) + 类型(1B) + 确认号(1B)
        """
        if len(data) < 4:
            return None
        magic, packet_type, ack_num = struct.unpack('!HBB', data[:4])
        # 验证魔数和类型
        if magic != MAGIC_NUMBER or packet_type != PacketType.ACK:
            return None
        return ack_num
    
    # ==================== 数据传输相关方法 ====================
    
    def unpack_data_packet(self, data):
        """
        解包数据报文
        :param data: 接收到的字节流
        :return: (序列号, 起始字节, 结束字节, 载荷) 或 None
        格式：魔数(2B) + 类型(1B) + 序列号(1B) + 起始字节(2B) + 结束字节(2B) + 载荷
        """
        if len(data) < 10:
            return None
        # 解包头信息
        magic, packet_type, seq_num, start_byte, end_byte = struct.unpack('!HBBHH', data[:8])
        # 验证魔数和类型
        if magic != MAGIC_NUMBER or packet_type != PacketType.DATA:
            return None
        # 获取载荷数据
        payload = data[8:]
        return seq_num, start_byte, end_byte, payload
    
    def pack_data_ack(self, seq_num, server_time):
        """
        打包数据确认报文
        :param seq_num: 确认的序列号
        :param server_time: 服务器时间（time.localtime()格式）
        :return: 打包后的字节流
        格式：魔数(2B) + 类型(1B) + 序列号(1B) + 小时(1B) + 分钟(1B) + 秒(1B)
        """
        # 提取时间信息
        hours = server_time.tm_hour
        minutes = server_time.tm_min
        seconds = server_time.tm_sec
        # 打包
        return struct.pack('!HBBBBB', MAGIC_NUMBER, PacketType.DATA_ACK, seq_num, hours, minutes, seconds)
    
    def handle_client(self, data, addr):
        """
        处理客户端请求（支持三次握手和数据传输）
        :param data: 接收到的数据
        :param addr: 客户端地址（IP, 端口）
        """
        # 检查数据长度
        if len(data) < 4:
            return
        
        # 先解析魔数和数据包类型
        magic, packet_type = struct.unpack('!HB', data[:3])
        
        # 根据数据包类型进行处理
        if packet_type == PacketType.SYN:
            # ========== 第一次握手：处理SYN ==========
            result = self.unpack_syn(data)
            if result is None:
                self.log(f"[第一次握手失败] 无效的SYN包来自 {addr}")
                return
            
            client_isn, student_id = result
            
            # 验证StudentID
            if not self.validate_student_id(student_id):
                self.log(f"[第一次握手失败] 无效的StudentID {student_id} 来自 {addr}")
                return
            
            # 生成服务端初始序列号
            server_isn = random.randint(0, 255)
            
            # 记录客户端信息（半连接状态）
            self.clients[addr] = {
                'client_isn': client_isn,
                'server_isn': server_isn,
                'connected': False,  # 尚未完成三次握手
                'handshake_step': 2  # 当前处于第二次握手阶段
            }
            
            self.log(f"[第一次握手] 收到SYN: client_isn={client_isn}, StudentID={student_id}")
            
            # ========== 发送SYN_ACK（第二次握手） ==========
            ack_num = (client_isn + 1) % 256  # 确认client_isn+1
            syn_ack_packet = self.pack_syn_ack(server_isn, ack_num)
            self.socket.sendto(syn_ack_packet, addr)
            self.log(f"[第二次握手] 发送SYN_ACK: server_isn={server_isn}, ack={ack_num}")
            
        elif packet_type == PacketType.ACK:
            # ========== 第三次握手：处理ACK ==========
            # 检查客户端是否处于半连接状态
            if addr not in self.clients:
                self.log(f"[第三次握手失败] 未知的ACK来自 {addr}（未收到SYN）")
                return
            
            client_info = self.clients[addr]
            if client_info['handshake_step'] != 2:
                self.log(f"[第三次握手失败] ACK来自 {addr} 但握手阶段不正确")
                return
            
            ack_num = self.unpack_ack(data)
            if ack_num is None:
                self.log(f"[第三次握手失败] 无效的ACK包来自 {addr}")
                return
            
            # 验证ACK确认号是否正确（应该是server_isn+1）
            expected_ack = (client_info['server_isn'] + 1) % 256
            if ack_num != expected_ack:
                self.log(f"[第三次握手失败] ACK确认号错误: 期望{expected_ack}, 收到{ack_num}")
                return
            
            # 三次握手完成，更新客户端状态
            self.clients[addr]['connected'] = True
            self.clients[addr]['handshake_step'] = 3
            self.clients[addr]['last_seq'] = -1
            
            self.log(f"[第三次握手] 收到ACK: ack={ack_num}")
            self.log(f"【三次握手完成】 与 {addr} 建立连接，client_isn={client_info['client_isn']}, server_isn={client_info['server_isn']}")
            
        elif packet_type == PacketType.DATA:
            # ========== 处理数据报文 ==========
            # 检查客户端是否已完成三次握手
            if addr not in self.clients or not self.clients[addr]['connected']:
                self.log(f"数据包来自未连接的客户端 {addr}（需要先完成三次握手）")
                return
            
            # 解包数据
            result = self.unpack_data_packet(data)
            if result is None:
                self.log(f"无效的数据包来自 {addr}")
                return
            
            seq_num, start_byte, end_byte, payload = result
            
            # 模拟丢包（根据丢包率随机决定是否丢弃）
            if random.random() < self.drop_rate:
                self.log(f"丢包: packet {seq_num} ({start_byte}-{end_byte} bytes) 来自 {addr}")
                return  # 不发送ACK，模拟丢包
            
            # 更新客户端最后收到的序列号
            self.clients[addr]['last_seq'] = seq_num
            self.log(f"收到数据包 {seq_num} ({start_byte}-{end_byte} bytes) 来自 {addr}")
            
            # 发送确认报文
            ack_packet = self.pack_data_ack(seq_num, time.localtime())
            self.socket.sendto(ack_packet, addr)
            self.log(f"发送ACK: packet {seq_num} 到 {addr}")
    
    def run(self):
        """
        启动服务端主循环
        """
        self.log(f"UDP Server started on port {self.port}")
        self.log(f"Drop rate: {self.drop_rate * 100}%")
        self.log(f"支持三次握手连接建立")
        
        try:
            # 持续监听
            while True:
                # 接收数据（阻塞）
                data, addr = self.socket.recvfrom(1024)
                # 处理客户端请求
                self.handle_client(data, addr)
        except KeyboardInterrupt:
            # 捕获Ctrl+C，优雅退出
            self.log("Server shutting down...")
            self.log_file.close()
            self.socket.close()

def main():
    """
    主函数：解析命令行参数并启动服务端
    """
    # 检查命令行参数
    if len(sys.argv) != 2:
        print("Usage: python udpserver.py <port>")
        sys.exit(1)
    
    # 解析端口参数
    port = int(sys.argv[1])
    
    # 创建服务端实例（丢包率设置为20%）
    server = UDPServer(port, drop_rate=0.2)
    
    # 启动服务
    server.run()

if __name__ == "__main__":
    main()