import sqlite3

conn = sqlite3.connect('packet_logs.db')
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS packets (
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        length INTEGER,
        flags TEXT
    )
''')

conn.commit()
conn.close()
print("Database and table initialized.")
