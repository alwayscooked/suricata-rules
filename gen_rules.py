#Ver|P|X|CCcount|M|Payload_type_
#0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
import itertools


def add_some_bytes(existing_bytes, payload):
    res = []
    for i in existing_bytes:
        for j in payload:
            res.append(i+j)
    
    return res

def binary_to_int(str_bytes):
    res = 0
    for i in range(len(str_bytes)):
        res += int(str_bytes[i])*(2**((len(str_bytes)-1)-i))
    return res

def tuple_to_str(t):
    s = ""
    for i in t:
        s = s+str(i)
    return s


#INIT values
#FIRST_BYTE
versions = ['00','01','10']
possible_cccount_t = itertools.product([0,1],repeat=4)
possible_cccount = []

for i in list(possible_cccount_t):
    possible_cccount.append(tuple_to_str(i))

p_bite = add_some_bytes(versions, ['0','1'])
extens_bite = add_some_bytes(p_bite, ['0','1'])
first_byte = add_some_bytes(extens_bite, possible_cccount) 

#SECOND_BYTE
m_bites = ['0','1']
possible_payloads_type_t = itertools.product([0,1],repeat=7)

possible_payloads_type = []

for i in list(possible_payloads_type_t):
    possible_payloads_type.append(tuple_to_str(i))

second_byte = add_some_bytes(m_bites, possible_payloads_type)

#FOR MSG
def parse_first_byte(str_byte):
    version = binary_to_int(str_byte[0]+str_byte[1])
    return f"version: {version}, p bit: {str_byte[2]}, Extension bite: {str_byte[3]}, CCcount: {binary_to_int(str_byte[4:])}"

def parse_second_byte(str_byte):
    return f"m bit:{str_byte[0]}, pt:{str_byte[1:]}"

all_comb = [(i,j) for i in first_byte for j in second_byte]

def gen_rules():
    with open('rtp.rules','a') as fl:
        for i in range(len(all_comb)):
            f_b = all_comb[i][0]
            s_b = all_comb[i][1]
            rule = f'alert udp $EXTERNAL_NET any <> $HOME_NET any (msg:"RTC packet(possibly) with follow features was detected: {parse_first_byte(f_b)+parse_second_byte(s_b)}"; content:"|{hex(binary_to_int(f_b))[2:].upper()} {hex(binary_to_int(s_b))[2:].upper()}|"; sid:{1000005+i}; rev:1;)'
            fl.write(rule)
            fl.write('\n')

gen_rules()