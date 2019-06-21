from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP


function_codes = {
    1:   "Read Coil",
    2:   "Read Discrete Input",
    3:   "Read Holding Input",
    4:   "Read Input Registers",
    5: 	 "Write Single Coil",
    6:	 "Write Single Holding Register",
    15:  "Write Multiple Coils",
    16:  "Write Multiple Holding Registers",
    90:  "Unity (Schneider)"
}

class ModbusTCP(Packet):
    name="Modbus"
    fields_desc = [ ShortField("Transaction_Identifier", None),
		    ShortField("Protocol_Identifier", None),
		    ShortField("Length", None),
		    ByteField("Unit_Identifier", 255) ]

class Modbus(Packet):
    name="ModbusTCP"
    fields_desc = [ ByteEnumField("reg_type", 3, function_codes),
		    ShortEnumField("ref_num",71, {71: "71", 152: "152"}),
		    ShortField("Word/Bit_count", None) ]



bind_layers( TCP,           ModbusTCP,		dport=502)
bind_layers( TCP,           ModbusTCP,		sport=502)
bind_layers( ModbusTCP,           Modbus,	)



