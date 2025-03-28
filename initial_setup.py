import sqlite3
from security import hash_password, verify_password

DATABASE = 'members.db'

# Users to add
USERS = {
    "staff": {"password": "staffpass", "role": "staff"},
    "member": {"password": "memberpass", "role": "member"},
    "pakkarim": {"password": "karim", "role": "staff"}
}

# Connect to the database
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

# Optional: Clear the users table before inserting new users
cursor.execute("DELETE FROM users")

# Insert users with hashed and salted passwords
for username, details in USERS.items():
    salt, hashed_password = hash_password(details['password'])
    try:
        cursor.execute("INSERT INTO users (username, salt, hashed_password, role) VALUES (?, ?, ?, ?)", 
                       (username, salt, hashed_password, details['role']))
        # Print the details for each user
        print(f"User: {username}")
        print(f"Salt: {salt}")
        print(f"Hashed Password: {hashed_password}")
        print("Password is valid:", verify_password(hashed_password, salt, details['password']))
    except sqlite3.IntegrityError:
        print(f"User {username} already exists. Skipping.")

# Commit and close the connection
conn.commit()
conn.close()