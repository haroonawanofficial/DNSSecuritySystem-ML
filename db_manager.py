# db_manager.py
import mysql.connector

def create_database_if_not_exists():
    # Establish a MySQL connection
    db_connection = mysql.connector.connect(
        host="localhost",
        user="your_username",
        password="your_password"
    )

    # Create a cursor object
    cursor = db_connection.cursor()

    # Create a database if it doesn't exist
    cursor.execute("CREATE DATABASE IF NOT EXISTS dns_spoofing")

    # Close the cursor and the database connection
    cursor.close()
    db_connection.close()
