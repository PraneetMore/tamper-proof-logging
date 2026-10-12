"""
Rebuild the checkpoints table from the entries table.
Preserves the original cadence (approximately 100 entries per checkpoint
for live-collected devices, single checkpoint for bulk-imported devices).
"""
from src.logger.storage import Storage
from src.logger.chain import segment_digest, batch_digest, utc_now_iso
from src.logger.sync import checkpoint_digest

CADENCE = 100
BULK_DEVICES = {'windows-1'}


def main():
    s = Storage()

    with s._conn() as c:
        c.execute('DELETE FROM checkpoints')

        for dev in ('dev-1', 'windows-1', 'offline-test', 'windows-live'):
            rows = c.execute(
                'SELECT * FROM entries WHERE device_id=? ORDER BY entry_index ASC',
                (dev,),
            ).fetchall()
            if not rows:
                print(f'{dev}: no entries')
                continue

            first_index = rows[0]['entry_index']
            last_index = rows[-1]['entry_index']

            # Compute segment boundaries
            if dev in BULK_DEVICES:
                boundaries = [(first_index, last_index)]
            else:
                boundaries = []
                seg_start = first_index
                count = 0
                for row in rows:
                    count += 1
                    if count >= CADENCE:
                        boundaries.append((seg_start, row['entry_index']))
                        seg_start = row['entry_index'] + 1
                        count = 0
                if count > 0:
                    boundaries.append((seg_start, last_index))

            # Build rows
            prev_cp = None
            for seq, (seg_start, seg_end) in enumerate(boundaries, start=1):
                seg_rows = [r for r in rows if seg_start <= r['entry_index'] <= seg_end]
                if not seg_rows:
                    continue
                entries = [dict(r) for r in seg_rows]

                cp = {
                    'device_id': dev,
                    'sequence': seq,
                    'segment_start': seg_start,
                    'segment_end': seg_end,
                    'chain_start': entries[0]['prev_hash'],
                    'chain_end': entries[-1]['chain_hash'],
                    'timestamp': utc_now_iso(),
                    'prev_digest': prev_cp['checkpoint_digest'] if prev_cp else ('0' * 128),
                    'segment_digest': segment_digest(entries),
                    'batch_digest': batch_digest(entries),
                }
                cp['checkpoint_digest'] = checkpoint_digest(cp)

                c.execute("""
                    INSERT INTO checkpoints
                    (device_id, seq, segment_start, segment_end,
                     chain_start, chain_end, timestamp, prev_digest,
                     checkpoint_digest, segment_digest, batch_digest)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cp['device_id'], cp['sequence'], cp['segment_start'], cp['segment_end'],
                    cp['chain_start'], cp['chain_end'], cp['timestamp'], cp['prev_digest'],
                    cp['checkpoint_digest'], cp['segment_digest'], cp['batch_digest'],
                ))
                prev_cp = cp

            print(f'{dev:15} rebuilt {len(boundaries)} checkpoints')

    # Report
    print()
    print('Final counts:')
    with s._conn() as c:
        for dev in ('dev-1', 'windows-1', 'offline-test', 'windows-live'):
            n = c.execute(
                'SELECT COUNT(*) FROM checkpoints WHERE device_id=?', (dev,)
            ).fetchone()[0]
            print(f'  {dev:15} {n}')


if __name__ == '__main__':
    main()
