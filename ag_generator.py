import sys
import ag_parser


def main(nm_file, xp_file):
    netmodel = ag_parser.networkmodel.parseFile(nm_file)
    exploits = ag_parser.exploits.parseFile(xp_file)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'usage: python ag_generator.py nmfile xpfile'
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])