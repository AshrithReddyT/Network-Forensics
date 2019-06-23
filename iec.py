from scapy.all import *

class asdu_head(Packet):
	name = "IEC104"
	fields_desc = [ XByteField("TypeID", 0x45),
			XByteField("SQ", 0x01),
			XByteField("Cause", 0x06),
			XByteField("OA", 0x04),
			LEShortField("Addr", 0x0003)]

class CP56Time(Packet):
	name = "IEC104"
	#1991-02-19_10:30:1.237
	fields_desc = [ 
			XShortField("Ms", 0xd504),
			XByteField("Min", 0x1e),
			XByteField("Hour", 0xa),
			XByteField("Day", 0x13),
			XByteField("Month", 0x02),
			XByteField("Year", 0x5b),
			]

class asdu_infobj_45(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			XByteField("SCO", 0x80)]

class asdu_infobj_46(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			XByteField("DCO", 0x80)]

class asdu_infobj_47(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			XByteField("RCO", 0x80)]

class asdu_infobj_48(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			StrField("Value", '', fmt="H", remain=0),
			XByteField("QOS", 0x80)]

class asdu_infobj_49(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			StrField("Value", '', fmt="H", remain=0),
			XByteField("QOS", 0x80)]

class asdu_infobj_50(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			StrField("Value", '', fmt="f", remain=0),
			XByteField("QOS", 0x80)]

class asdu_infobj_51(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			StrField("Value", '', fmt="I", remain=0)]

class asdu_infobj_58(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			XByteField("SCO", 0x80),
			PacketField("CP56Time", CP56Time, Packet)]

class asdu_infobj_59(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			XByteField("DCO", 0x80),
			PacketField("CP56Time", CP56Time, Packet)]

class asdu_infobj_60(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			XByteField("RCO", 0x80),
			PacketField("CP56Time", CP56Time, Packet)]

class asdu_infobj_61(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			StrField("Value", '', fmt="H", remain=0),
			XByteField("QOS", 0x80),
			PacketField("CP56Time", CP56Time, Packet)]

class asdu_infobj_62(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			StrField("Value", '', fmt="H", remain=0),
			XByteField("QOS", 0x80),
			PacketField("CP56Time", CP56Time, Packet)]

class asdu_infobj_63(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			StrField("Value", '', fmt="f", remain=0),
			XByteField("QOS", 0x80),
			PacketField("CP56Time", CP56Time, Packet)]

class asdu_infobj_64(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x23),
			StrField("Value", '', fmt="I", remain=0),
			PacketField("CP56Time", CP56Time, Packet)]

class asdu_infobj_101(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x0),
			XByteField("Operation", 0x05)]

class asdu_infobj_103(Packet):
	name = "IEC104"
	fields_desc = [ 
			X3BytesField  ("IOA", 0x0),
			PacketField("CP56Time", CP56Time, Packet)]

# IEC104 apci
class i_frame(Packet):
	name = "IEC104"
	fields_desc = [ XByteField("START", 0x68),
			XByteField("ApduLen", None),
			LEShortField("Tx", 0x0000),
			LEShortField("Rx", 0x0000),
			]

	def post_build(self, p, pay):
		if self.ApduLen is None:
			l = len(pay)+4
			p = p[:1] + struct.pack("!B", l) + p[2:]
		return p+pay


class s_frame(Packet):
	name = "IEC104"
	fields_desc = [ XByteField("START", 0x68),
			XByteField("ApduLen", 0x04),
			LEShortField("Type", 0x01),
			LEShortField("Rx", 0x0000)]


class u_frame(Packet):
	name = "IEC104"
	fields_desc = [ XByteField("START", 0x68),
			XByteField("ApduLen", 0x04),
			LEShortField("Type", 0x07),
			LEShortField("Default", 0x0000)]

bind_layers( TCP,           i_frame,		dport=2404)
bind_layers( TCP,           i_frame,		sport=2404)
bind_layers( TCP,           s_frame,		dport=2404)
bind_layers( TCP,           s_frame,		sport=2404)
bind_layers( TCP,           u_frame,		dport=2404)
bind_layers( TCP,           u_frame,		sport=2404)
bind_layers( TCP,           i_frame,		dport=2404)
bind_layers( TCP,           i_frame,		sport=2404)
bind_layers( TCP,           s_frame,		dport=2404)
bind_layers( TCP,           s_frame,		sport=2404)
bind_layers( TCP,           u_frame,		dport=2404)
bind_layers( TCP,           u_frame,		sport=2404)
