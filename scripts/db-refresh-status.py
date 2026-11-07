#!/usr/bin/env python3
"""Write a public, credential-free refresh status atomically."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time

path=Path(sys.argv[1])/'refresh-status.json'
status,stage=sys.argv[2:4]
assert status in ('running','success','failed')
assert stage in ('previous-publication','acquisition','policy','pack','sign','publication-recovery','complete')
fd,name=tempfile.mkstemp(dir=path.parent,prefix='.refresh-status-')
with os.fdopen(fd,'w') as out:
    json.dump({'status':status,'stage':stage,'updated_at':int(time.time())},out)
    out.flush();os.fsync(out.fileno())
os.chmod(name,0o644)
os.replace(name,path)
