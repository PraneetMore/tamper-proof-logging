#!/bin/bash
# End-to-end live system test.
set -e
cd ~/tamper-proof-logging
source venv/bin/activate

DEV="live-test"
rm -f "data/server_store/${DEV}.jsonl"

# Start server in background
python server.py > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Collect for 60 seconds
python -c "
import time
from src.logger.monitor import Monitor
m = Monitor('${DEV}', 'live-deployment', interval=5, verbose=True)
for _ in range(12):
    m.run_once()
    time.sleep(5)
"

# Flush any pending
python -c "
from src.logger.sync import SyncManager
s = SyncManager()
print('flush:', s.flush_pending('${DEV}'))
"

# Verify
python -c "
from src.logger.storage import Storage
from src.logger.verify import verify_all_checkpoints
s = Storage()
ok, msg = verify_all_checkpoints(s, '${DEV}')
print('verify:', ok, '|', msg)
with s._conn() as c:
    n = c.execute(\"SELECT COUNT(*) FROM entries WHERE device_id='${DEV}'\").fetchone()[0]
    cp = c.execute(\"SELECT COUNT(*) FROM checkpoints WHERE device_id='${DEV}'\").fetchone()[0]
print(f'SQLite: {n} entries, {cp} checkpoints')
"

wc -l "data/server_store/${DEV}.jsonl"

kill $SERVER_PID 2>/dev/null
echo "Live test complete."
