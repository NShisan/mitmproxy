import sys,re
from mitmproxy.tools.main import mitmweb

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(mitmweb())