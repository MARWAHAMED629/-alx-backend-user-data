#!/usr/bin/env python3
"""
Personal data.
"""

import logging
import os
import re
from typing import List
import mysql.connector

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    Replace sensitive data in the message with redacted values.

    Args:
        fields (List[str]): List of field names to be redacted.
        redaction (str): The redaction string to replace sensitive data.
        message (str): The message containing the data to redact.
        separator (str): The separator used in the message.

    Returns:
        str: The message with redacted fields.
    """
    for field in fields:
        pattern = rf"{field}=(.*?)\{separator}"
        replacement = f'{field}={redaction}{separator}'
        message = re.sub(pattern, replacement, message)
    return message


class RedactingFormatter(logging.Formatter):
    """
    Formatter class that redacts sensitive information in log messages.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the RedactingFormatter.

        Args:
            fields (List[str]): List of field names to redact.
        """
        self.fields = fields
        super().__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record, redacting sensitive information.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The formatted log message with redacted fields.
        """
        return filter_datum(
            self.fields, self.REDACTION,
            super().format(record), self.SEPARATOR
        )


def get_logger() -> logging.Logger:
    """
    Set up a logger with a RedactingFormatter.

    Returns:
        logging.Logger: The configured logger.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establish a database connection.

    Returns:
        mysql.connector.connection.MySQLConnection: The database connection.
    """
    password = os.environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    username = os.environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    host = os.environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.environ.get("PERSONAL_DATA_DB_NAME")

    conn = mysql.connector.connect(
        host=host,
        database=db_name,
        user=username,
        password=password
    )
    return conn


def main() -> None:
    """
    Main function to retrieve and print user data.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    for row in cursor:
        message = (
            f"name={row[0]}; email={row[1]}; phone={row[2]}; "
            f"ssn={row[3]}; password={row[4]}; ip={row[5]}; "
            f"last_login={row[6]}; user_agent={row[7]};"
        )
        print(message)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
