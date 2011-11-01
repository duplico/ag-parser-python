NUM_CARS = 1
import sys
if len(sys.argv) > 1:
    NUM_CARS = int(sys.argv[1])
else:
    print '# No tag number specified. Defaulting to 1.'

asset_preamble = \
"""network model=
    assets:
        wall;"""

fact_preamble = \
"""    facts:
        # Wall
        quality:wall,wall=true;"""
car_string = \
"""        # CARNAME
        platform:CARNAME,cpe:/h:honda:civic;
        quality:CARNAME,compromised=false;
        topology:CARNAME<->wall,distance:=50;
        quality:CARNAME,status=up;
"""

print asset_preamble
for i in range(NUM_CARS):
    print '        car%i;' % i
print fact_preamble
for i in range(NUM_CARS):
    print car_string.replace('CARNAME', 'car%i' % i)

print '.'