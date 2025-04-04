import sqlite3
import logging
from backend.security import encrypt_password, decrypt_password

DATABASE_NAME = "password_manager.db"

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def get_db_connection():
    """
    Connects to the local SQLite database.
    """
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        conn.row_factory = sqlite3.Row  # Enables column access by name
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        raise


def initialize_database():
    """
    Ensures the database has the required table.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                user_id TEXT PRIMARY KEY,  -- Ensures each user_id is UNIQUE
                encrypted_password TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        logging.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        raise


def save_password(user_id: str, password: str):
    """
    Encrypts and saves a password in the database.
    If the user already exists, their password is updated.
    """
    try:
        encrypted_password = encrypt_password(password)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO passwords (user_id, encrypted_password)
            VALUES (?, ?)
            ON CONFLICT(user_id) DO UPDATE SET encrypted_password = excluded.encrypted_password;
        """, (user_id, encrypted_password))
        conn.commit()
        conn.close()
        logging.info(f"Password saved for user: {user_id}")
    except sqlite3.Error as e:
        logging.error(f"Error saving password for {user_id}: {e}")
        raise


def get_password(user_id: str) -> str:
    """
    Retrieves and decrypts a password from the database.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT encrypted_password FROM passwords WHERE user_id = ?
        """, (user_id,))
        result = cursor.fetchone()
        conn.close()

        if result:
            try:
                decrypted_password = decrypt_password(result["encrypted_password"])
                logging.info(f"Password retrieved successfully for user: {user_id}")
                return decrypted_password
            except Exception as e:
                logging.error(f"Decryption failed for user {user_id}: {e}")
                raise ValueError(f"Decryption failed: {str(e)}")
        else:
            logging.warning(f"No password found for user: {user_id}")
            raise ValueError("No password found for the given user ID.")

    except sqlite3.Error as e:
        logging.error(f"Database error retrieving password for {user_id}: {e}")
        raise


# Initialize DB on import
initialize_database()

