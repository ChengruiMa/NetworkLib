#!/usr/bin/env python3
"""
Network layers library for Ethernet, IP, ICMP, TCP, UDP, and DNS
As discussed with Ravin, we're only submitting the part2 version since 
it contains part 1 as well.
Written with assistance from ChatGPT and Claude on 
hexadecimals, bytes, library usage, and debugging.
"""

import struct
import socket

class PacketBase:
    """Base class for all network layers"""
    def __init__(self):
        self.payload = None
    
    def __truediv__(self, other):
        """Overload / operator to stack layers (like Scapy)"""
        # Find the deepest layer (the one without a payload)
        current = self
        while current.payload is not None:
            current = current.payload
        
        # Set the payload on the deepest layer
        current.payload = other
        
        # Special handling for TCP/UDP over IP: automatically set src_ip and dst_ip
        if isinstance(current, IP) and isinstance(other, (TCP, UDP)):
            other.src_ip = current.src_ip
            other.dst_ip = current.dst_ip
        
        return self
    
    def show(self, indent=0):
        """Display packet contents recursively"""
        self._show_layer(indent)
        if self.payload:
            self.payload.show(indent + 2)
    
    def _show_layer(self, indent):
        """Override in subclasses to display layer-specific info"""
        pass
    
    def build(self):
        """Build packet bytes recursively"""
        my_bytes = self._build_header()
        if self.payload:
            my_bytes += self.payload.build()
        return my_bytes
    
    def _build_header(self):
        """Override in subclasses to build layer-specific header"""
        return b''
    
    def get_layer(self, layer_name):
        """Recursively search for a layer by name"""
        if self.__class__.__name__ == layer_name:
            return self
        if self.payload:
            return self.payload.get_layer(layer_name)
        return None


class Ether(PacketBase):
    """Ethernet Layer 2"""
    def __init__(self, raw_bytes=None, src_mac=None, dst_mac=None, eth_type=0x0800):
        super().__init__()
        
        if raw_bytes is not None:
            # Parse from bytes
            self.dst_mac = ':'.join(f'{b:02x}' for b in raw_bytes[0:6])
            self.src_mac = ':'.join(f'{b:02x}' for b in raw_bytes[6:12])
            self.type = struct.unpack('!H', raw_bytes[12:14])[0]
            
            # Create next layer based on type
            if self.type == 0x0800:  # IPv4
                self.payload = IP(raw_bytes=raw_bytes[14:])
        else:
            # Build from parameters
            self.src_mac = src_mac or "00:00:00:00:00:00"
            self.dst_mac = dst_mac or "ff:ff:ff:ff:ff:ff"
            self.type = eth_type
    
    def _build_header(self):
        """Convert MAC addresses and type to bytes"""
        dst = bytes.fromhex(self.dst_mac.replace(':', ''))
        src = bytes.fromhex(self.src_mac.replace(':', ''))
        eth_type = struct.pack('!H', self.type)
        return dst + src + eth_type
    
    def _show_layer(self, indent):
        spaces = ' ' * indent
        print(f"{spaces}### Ether ###")
        print(f"{spaces}  dst_mac: {self.dst_mac}")
        print(f"{spaces}  src_mac: {self.src_mac}")
        print(f"{spaces}  type: {self.type:04x}")


class IP(PacketBase):
    """IP Layer 3"""
    def __init__(self, raw_bytes=None, src_ip=None, dst_ip=None, ttl=64, proto=None):
        super().__init__()
        
        if raw_bytes is not None:
            # Parse from bytes
            ver_ihl = raw_bytes[0]
            self.version = ver_ihl >> 4
            self.ihl = ver_ihl & 0x0F
            self.tos = raw_bytes[1]
            self.total_len = struct.unpack('!H', raw_bytes[2:4])[0]
            self.ident = struct.unpack('!H', raw_bytes[4:6])[0]
            self.flags_frag = struct.unpack('!H', raw_bytes[6:8])[0]
            self.ttl = raw_bytes[8]
            self.proto = raw_bytes[9]
            self.checksum = struct.unpack('!H', raw_bytes[10:12])[0]
            self.src_ip = socket.inet_ntoa(raw_bytes[12:16])
            self.dst_ip = socket.inet_ntoa(raw_bytes[16:20])
            
            header_len = self.ihl * 4
            payload_bytes = raw_bytes[header_len:]
            
            # Create next layer based on protocol
            if self.proto == 1:  # ICMP
                self.payload = ICMP(raw_bytes=payload_bytes)
            elif self.proto == 6:  # TCP
                self.payload = TCP(raw_bytes=payload_bytes, src_ip=self.src_ip, dst_ip=self.dst_ip)
            elif self.proto == 17:  # UDP
                self.payload = UDP(raw_bytes=payload_bytes, src_ip=self.src_ip, dst_ip=self.dst_ip)
        else:
            # Build from parameters
            self.version = 4
            self.ihl = 5
            self.tos = 0
            self.total_len = 0  # Will be calculated
            self.ident = 0
            self.flags_frag = 0
            self.ttl = ttl
            self.proto = proto if proto is not None else 0
            self.checksum = 0  # Will be calculated
            self.src_ip = src_ip or "0.0.0.0"
            self.dst_ip = dst_ip or "0.0.0.0"
    
    def _build_header(self):
        """Build IP header with checksum"""
        # Determine protocol from payload if not set
        if self.proto == 0 and self.payload:
            if isinstance(self.payload, ICMP):
                self.proto = 1
            elif isinstance(self.payload, TCP):
                self.proto = 6
            elif isinstance(self.payload, UDP):
                self.proto = 17
        
        # Calculate total length
        payload_bytes = self.payload.build() if self.payload else b''
        self.total_len = 20 + len(payload_bytes)
        
        # Build header without checksum
        header = struct.pack('!BBHHHBBH',
                           (self.version << 4) | self.ihl,
                           self.tos,
                           self.total_len,
                           self.ident,
                           self.flags_frag,
                           self.ttl,
                           self.proto,
                           0)  # Checksum placeholder
        header += socket.inet_aton(self.src_ip)
        header += socket.inet_aton(self.dst_ip)
        
        # Calculate checksum
        self.checksum = self._calculate_checksum(header)
        
        # Rebuild with correct checksum
        header = struct.pack('!BBHHHBBH',
                           (self.version << 4) | self.ihl,
                           self.tos,
                           self.total_len,
                           self.ident,
                           self.flags_frag,
                           self.ttl,
                           self.proto,
                           self.checksum)
        header += socket.inet_aton(self.src_ip)
        header += socket.inet_aton(self.dst_ip)
        
        return header
    
    def _calculate_checksum(self, data):
        """Calculate Internet checksum (one's complement)"""
        if len(data) % 2 == 1:
            data += b'\x00'
        
        total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ~total & 0xffff
    
    def _show_layer(self, indent):
        spaces = ' ' * indent
        print(f"{spaces}### IP ###")
        print(f"{spaces}  version: {self.version}")
        print(f"{spaces}  ihl: {self.ihl}")
        print(f"{spaces}  tos: {self.tos}")
        print(f"{spaces}  total_len: {self.total_len}")
        print(f"{spaces}  ident: {self.ident:x}")
        print(f"{spaces}  flags_frag: {self.flags_frag:04x}")
        print(f"{spaces}  ttl: {self.ttl}")
        print(f"{spaces}  proto: {self.proto}")
        print(f"{spaces}  checksum: {self.checksum:04x}")
        print(f"{spaces}  src_ip: {self.src_ip}")
        print(f"{spaces}  dst_ip: {self.dst_ip}")


class ICMP(PacketBase):
    """ICMP Layer 3"""
    def __init__(self, raw_bytes=None, type=8, code=0, id=0, seq=0, data=b''):
        super().__init__()
        
        if raw_bytes is not None:
            # Parse from bytes
            self.type = raw_bytes[0]
            self.code = raw_bytes[1]
            self.checksum = struct.unpack('!H', raw_bytes[2:4])[0]
            self.id = struct.unpack('!H', raw_bytes[4:6])[0]
            self.seq = struct.unpack('!H', raw_bytes[6:8])[0]
            self.data = raw_bytes[8:]
        else:
            # Build from parameters
            self.type = type
            self.code = code
            self.checksum = 0
            self.id = id
            self.seq = seq
            self.data = data if isinstance(data, bytes) else b''
    
    def _build_header(self):
        """Build ICMP header with checksum"""
        # Build header without checksum
        header = struct.pack('!BBHHH',
                           self.type,
                           self.code,
                           0,  # Checksum placeholder
                           self.id,
                           self.seq)
        
        # Calculate checksum including data
        full_packet = header + self.data
        self.checksum = self._calculate_checksum(full_packet)
        
        # Rebuild with correct checksum
        header = struct.pack('!BBHHH',
                           self.type,
                           self.code,
                           self.checksum,
                           self.id,
                           self.seq)
        
        return header + self.data
    
    def _calculate_checksum(self, data):
        """Calculate Internet checksum"""
        if len(data) % 2 == 1:
            data += b'\x00'
        
        total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ~total & 0xffff
    
    def _show_layer(self, indent):
        spaces = ' ' * indent
        print(f"{spaces}### ICMP ###")
        print(f"{spaces}  type: {self.type}")
        print(f"{spaces}  code: {self.code}")
        print(f"{spaces}  checksum: {self.checksum:04x}")
        print(f"{spaces}  id: {self.id}")
        print(f"{spaces}  seq: {self.seq}")
        print(f"{spaces}  data: {self.data.hex()}")


class UDP(PacketBase):
    """UDP Layer 4"""
    def __init__(self, raw_bytes=None, sport=None, dport=None, data=b'', src_ip=None, dst_ip=None):
        super().__init__()
        
        if raw_bytes is not None:
            # Parse from bytes
            self.sport = struct.unpack('!H', raw_bytes[0:2])[0]
            self.dport = struct.unpack('!H', raw_bytes[2:4])[0]
            self.length = struct.unpack('!H', raw_bytes[4:6])[0]
            self.checksum = struct.unpack('!H', raw_bytes[6:8])[0]
            self.src_ip = src_ip
            self.dst_ip = dst_ip
            
            # Parse next layer (DNS if port 53)
            payload_bytes = raw_bytes[8:]
            if self.sport == 53 or self.dport == 53:
                self.payload = DNS(raw_bytes=payload_bytes)
                self.data = b'' 
            else:
                self.data = payload_bytes
        else:
            # Build from parameters
            self.sport = sport or 0
            self.dport = dport or 0
            self.length = 0  # Will be calculated
            self.checksum = 0  # Will be calculated
            self.data = data if isinstance(data, bytes) else b''
            self.src_ip = src_ip
            self.dst_ip = dst_ip
    
    def _build_header(self):
        """Build UDP header with checksum"""
        # Get payload bytes
        payload_bytes = self.payload.build() if self.payload else self.data
        self.length = 8 + len(payload_bytes)
        
        # Build header without checksum
        header = struct.pack('!HHHH',
                           self.sport,
                           self.dport,
                           self.length,
                           0)  # Checksum placeholder
        
        # Calculate checksum with pseudo-header
        if self.src_ip and self.dst_ip:
            pseudo_header = socket.inet_aton(self.src_ip)
            pseudo_header += socket.inet_aton(self.dst_ip)
            pseudo_header += struct.pack('!BBH', 0, 17, self.length)
            
            checksum_data = pseudo_header + header + payload_bytes
            self.checksum = self._calculate_checksum(checksum_data)
        
        # Rebuild with correct checksum
        header = struct.pack('!HHHH',
                           self.sport,
                           self.dport,
                           self.length,
                           self.checksum)
        
        return header + payload_bytes
    
    def _calculate_checksum(self, data):
        """Calculate Internet checksum"""
        if len(data) % 2 == 1:
            data += b'\x00'
        
        total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ~total & 0xffff
    
    def _show_layer(self, indent):
        spaces = ' ' * indent
        print(f"{spaces}### UDP ###")
        print(f"{spaces}  sport: {self.sport}")
        print(f"{spaces}  dport: {self.dport}")
        print(f"{spaces}  length: {self.length}")
        print(f"{spaces}  checksum: {self.checksum:04x}")
        if getattr(self, "data", b""):
            print(f"{spaces}  data: {self.data.hex()}")



class TCP(PacketBase):
    """TCP Layer 4"""
    def __init__(self, raw_bytes=None, sport=None, dport=None, seq=0, ack=0, 
                 flags=0, window=8192, data=b'', src_ip=None, dst_ip=None):
        super().__init__()
        
        if raw_bytes is not None:
            # Parse from bytes
            self.sport = struct.unpack('!H', raw_bytes[0:2])[0]
            self.dport = struct.unpack('!H', raw_bytes[2:4])[0]
            self.seq = struct.unpack('!I', raw_bytes[4:8])[0]
            self.ack = struct.unpack('!I', raw_bytes[8:12])[0]
            offset_flags = struct.unpack('!H', raw_bytes[12:14])[0]
            self.offset = offset_flags >> 12
            self.flags = offset_flags & 0x0FFF
            self.window = struct.unpack('!H', raw_bytes[14:16])[0]
            self.checksum = struct.unpack('!H', raw_bytes[16:18])[0]
            self.urg = struct.unpack('!H', raw_bytes[18:20])[0]
            
            header_len = self.offset * 4
            if header_len > 20:
                self.header_data = raw_bytes[20:header_len]
            else:
                self.header_data = b''
            
            self.message = raw_bytes[header_len:]
            self.src_ip = src_ip
            self.dst_ip = dst_ip
        else:
            # Build from parameters
            self.sport = sport or 0
            self.dport = dport or 0
            self.seq = seq
            self.ack = ack
            self.offset = 5  # 5 * 4 = 20 bytes (minimum)
            self.flags = flags
            self.window = window
            self.checksum = 0  # Will be calculated
            self.urg = 0
            self.header_data = b''
            self.data = data if isinstance(data, bytes) else b''
            self.src_ip = src_ip
            self.dst_ip = dst_ip
    
    def _build_header(self):
        """Build TCP header with checksum"""
        payload_bytes = self.payload.build() if self.payload else self.data
        
        # Build header without checksum
        header = struct.pack('!HHIIHHH',
                           self.sport,
                           self.dport,
                           self.seq,
                           self.ack,
                           (self.offset << 12) | self.flags,
                           self.window,
                           0)  # Checksum placeholder
        header += struct.pack('!H', self.urg)
        header += self.header_data
        
        # Calculate checksum with pseudo-header
        if self.src_ip and self.dst_ip:
            tcp_len = len(header) + len(payload_bytes)
            pseudo_header = socket.inet_aton(self.src_ip)
            pseudo_header += socket.inet_aton(self.dst_ip)
            pseudo_header += struct.pack('!BBH', 0, 6, tcp_len)
            
            checksum_data = pseudo_header + header + payload_bytes
            self.checksum = self._calculate_checksum(checksum_data)
        
        # Rebuild with correct checksum
        header = struct.pack('!HHIIHHH',
                           self.sport,
                           self.dport,
                           self.seq,
                           self.ack,
                           (self.offset << 12) | self.flags,
                           self.window,
                           self.checksum)
        header += struct.pack('!H', self.urg)
        header += self.header_data
        
        return header + payload_bytes
    
    def _calculate_checksum(self, data):
        """Calculate Internet checksum"""
        if len(data) % 2 == 1:
            data += b'\x00'
        
        total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ~total & 0xffff
    
    def _show_layer(self, indent):
        spaces = ' ' * indent
        print(f"{spaces}### TCP ###")
        print(f"{spaces}  sport: {self.sport}")
        print(f"{spaces}  dport: {self.dport}")
        print(f"{spaces}  seq: {self.seq}")
        print(f"{spaces}  ack: {self.ack}")
        print(f"{spaces}  flags: {self.flags:04x}")
        print(f"{spaces}  window: {self.window}")
        print(f"{spaces}  checksum: {self.checksum:04x}")
        if hasattr(self, 'message') and self.message:
            msg = self.message.decode('utf-8', errors='ignore')
            print(f"{spaces}  message: {msg}")


class DNS(PacketBase):
    """DNS Layer 7"""
    def __init__(self, raw_bytes=None, qname=None, qtype=1, qclass=1, id=None):
        super().__init__()
        
        if raw_bytes is not None:
            # Parse DNS response
            self.id = struct.unpack('!H', raw_bytes[0:2])[0]
            flags = struct.unpack('!H', raw_bytes[2:4])[0]
            self.codes = flags
            self.response = (flags >> 15) & 1
            self.opcode = (flags >> 11) & 0xF
            self.questions = struct.unpack('!H', raw_bytes[4:6])[0]
            self.answers = struct.unpack('!H', raw_bytes[6:8])[0]
            self.authorityrr = struct.unpack('!H', raw_bytes[8:10])[0]
            self.additionalrr = struct.unpack('!H', raw_bytes[10:12])[0]
            
            # Parse question
            pos = 12
            name_parts = []
            while raw_bytes[pos] != 0:
                length = raw_bytes[pos]
                pos += 1
                name_parts.append(raw_bytes[pos:pos+length].decode())
                pos += length
            self.qname = '.'.join(name_parts)
            pos += 1  # Skip null terminator
            
            # Skip qtype and qclass
            pos += 4
            
            # Parse answer if present
            if self.answers > 0:
                # Skip name (compression pointer)
                pos += 2
                # Skip type, class, ttl
                pos += 8
                # Get data length
                data_len = struct.unpack('!H', raw_bytes[pos:pos+2])[0]
                pos += 2
                # Get IP address
                if data_len == 4:
                    self.addr = socket.inet_ntoa(raw_bytes[pos:pos+4])
        else:
            # Build DNS query
            import random
            self.id = id if id is not None else random.randint(0, 65535)
            self.qr = 0  # Query
            self.opcode = 0
            self.aa = 0
            self.tc = 0
            self.rd = 1  # Recursion desired
            self.ra = 0
            self.z = 0
            self.rcode = 0
            self.qdcount = 1
            self.ancount = 0
            self.nscount = 0
            self.arcount = 0
            self.qname = qname or ""
            self.qtype = qtype
            self.qclass = qclass
    
    def _build_header(self):
        """Build DNS query"""
        # Build header
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | \
                (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | \
                (self.z << 4) | self.rcode
        
        header = struct.pack('!HHHHHH',
                           self.id,
                           flags,
                           self.qdcount,
                           self.ancount,
                           self.nscount,
                           self.arcount)
        
        # Build question
        question = b''
        for part in self.qname.split('.'):
            question += struct.pack('!B', len(part))
            question += part.encode()
        question += b'\x00'  # Null terminator
        question += struct.pack('!HH', self.qtype, self.qclass)
        
        return header + question
    
    def _show_layer(self, indent):
        spaces = ' ' * indent
        print(f"{spaces}### DNS ###")
        print(f"{spaces}  id: {self.id:04x}")
        
        if hasattr(self, 'response'):
            # Response
            print(f"{spaces}  response: {self.response}")
            print(f"{spaces}  questions: {self.questions}")
            print(f"{spaces}  answers: {self.answers}")
            print(f"{spaces}  qname: {self.qname}")
            if hasattr(self, 'addr'):
                print(f"{spaces}  addr: {self.addr}")
        else:
            # Query
            print(f"{spaces}  qname: {self.qname}")
            print(f"{spaces}  qtype: {self.qtype}")
            print(f"{spaces}  qclass: {self.qclass}")

