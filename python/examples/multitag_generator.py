NUM_TAGS = 1
import sys
if len(sys.argv) > 1:
    NUM_TAGS = int(sys.argv[1])
else:
    print '# No tag number specified. Defaulting to 1.'

asset_preamble = \
"""network model = 
    assets :
        attacker;
        reader;"""

fact_preamble = \
"""    facts :
        # Reader:
        platform:reader,cpe:/h::VulnerableReader;
        quality:reader,status=up;
        # Topologies:
        topology:attacker -> reader,connected_network;
"""
tag_string = \
"""        # Tag TAGNAME:
        platform:TAGNAME,cpe:/h::Tag;
        quality:TAGNAME,status=up;
        quality:TAGNAME,power:=100;
        quality:TAGNAME,mode=sleep;
        topology:reader -> TAGNAME,connected_rfid;
"""

print asset_preamble
for i in range(NUM_TAGS):
    print '        tag%i;' % i
print fact_preamble
for i in range(NUM_TAGS):
    print tag_string.replace('TAGNAME', 'tag%i' % i)

print '.'