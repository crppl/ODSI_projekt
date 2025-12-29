import sqlite3

sql = sqlite3.connect("test.db")
db = sql.cursor()
# db.execute("DROP TABLE IF EXISTS USERS;")
# db.execute("CREATE TABLE USERS (username NVARCHAR(20) NOT NULL, password NVARCHAR(100) NOT NULL);")
# db.execute("CREATE UNIQUE INDEX userid ON USERS (username);")
print(db.execute("SELECT * FROM USERS;").fetchall())
# db.execute('''INSERT INTO USERS (username, password) VALUES('admin', 'gvba1234asdf5678|fghhgghhjdjdjdjd') ''')
# print(db.execute("SELECT * FROM USERS;").fetchall())
sql.commit()
db.close()
sql.close()