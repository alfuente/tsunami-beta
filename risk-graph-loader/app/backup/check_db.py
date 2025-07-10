#!/usr/bin/env python3

import sqlite3

# Check database content
conn = sqlite3.connect('risk_loader_queue.db')

# Check discovered domains
cursor = conn.execute('SELECT COUNT(*) FROM discovered_domains')
print('Discovered domains:', cursor.fetchone()[0])

cursor = conn.execute('SELECT * FROM discovered_domains LIMIT 5')
print('Sample discovered:')
for row in cursor.fetchall():
    print(f'  {row[1]} -> {row[2]} (via {row[3]})')

# Check queue status
cursor = conn.execute('SELECT state, COUNT(*) FROM domain_queue GROUP BY state')
print('\nQueue status:')
for row in cursor.fetchall():
    print(f'  {row[0]}: {row[1]}')

cursor = conn.execute('SELECT domain, depth, state, worker_id FROM domain_queue LIMIT 10')
print('\nSample domains:')
for row in cursor.fetchall():
    print(f'  {row[0]} (depth={row[1]}, state={row[2]}, worker={row[3]})')

conn.close()