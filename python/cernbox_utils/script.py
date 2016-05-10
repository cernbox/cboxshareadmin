def arg_parser(**kwds):
    """ Create an ArgumentParser with common options for scripts and tools.
    """
    import argparse
    parser = argparse.ArgumentParser(**kwds)
    
    parser.add_argument('--dry-run', '-n', action='store_true', help='show config options and print what tests would be run')
    parser.add_argument('--quiet', '-q', action="store_true", help='do not produce output (other than errors)')
    parser.add_argument('--verbose', '-v', action="store_true", help='produce more output')
    parser.add_argument('--debug', action="store_true", help='produce very verbose output')
    parser.add_argument('--config','-c',dest="config",default="/etc/cbox/config/config.php",action="store",help='config file in original owncloud php format')
    return parser

def configure(config_path):
    import string
    d = {}

    for line in file(config_path):
        line = line.strip()
        if line and '=>' in line:
            line = line.rstrip(',')
            key,value = line.split('=>')
            key = key.strip().strip("'")

            value = value.strip().strip("'")
            d[key] = value

    return d
