from scapy.all import *

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

bind_layers( TCP,           i_frame,		dport=58156)
bind_layers( TCP,           i_frame,		sport=58156)
bind_layers( TCP,           s_frame,		dport=58156)
bind_layers( TCP,           s_frame,		sport=58156)
bind_layers( TCP,           u_frame,		dport=58156)
bind_layers( TCP,           u_frame,		sport=58156)
bind_layers( TCP,           i_frame,		dport=54844)
bind_layers( TCP,           i_frame,		sport=54844)
bind_layers( TCP,           s_frame,		dport=54844)
bind_layers( TCP,           s_frame,		sport=54844)
bind_layers( TCP,           u_frame,		dport=54844)
bind_layers( TCP,           u_frame,		sport=54844)
