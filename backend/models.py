import sqlite3

conn = sqlite3.connect("password_manager.db")
cursor = conn.cursor()

cursor.execute("SELECT user_id, COUNT(*) FROM passwords GROUP BY user_id HAVING COUNT(*) > 1")
duplicates = cursor.fetchall()

if duplicates:
    print("❌ Duplicate entries found:", duplicates)
else:
    print("✅ No duplicate users found!")

conn.close()
