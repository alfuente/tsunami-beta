#!/usr/bin/env python3

import sqlite3

# Check test database
conn = sqlite3.connect('test_simple.db')

cursor = conn.execute('SELECT COUNT(*) FROM discovered_domains')
print('Discovered domains:', cursor.fetchone()[0])

cursor = conn.execute('SELECT * FROM discovered_domains LIMIT 10')
print('Sample domains:')
for row in cursor.fetchall():
    print(f'  {row[1]} -> {row[2]} (via {row[3]})')

conn.close()