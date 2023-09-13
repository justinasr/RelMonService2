"""
Convert directories with htmlgz files to SQLite database
"""
import sqlite3
import os
import logging
import sys

logging.basicConfig(
    stream=sys.stdout,
    format="[%(asctime)s][%(levelname)s] %(message)s",
    level=logging.INFO,
)

categories = [
    entry for entry in os.listdir(".") if os.path.isdir(os.path.join(".", entry))
]
logging.info("Categories %s", categories)
db_connection = sqlite3.connect("reports.sqlite")
db_cursor = db_connection.cursor()
indexes_to_create = []

for category in categories:
    # Create tables
    logging.info("Recreating table for %s", category)
    db_cursor.execute("DROP TABLE IF EXISTS %s;" % (category))
    db_cursor.execute("DROP INDEX IF EXISTS %sIndex;" % (category))
    db_cursor.execute("CREATE TABLE %s (path text, htmlgz blob);" % (category))
    # Walk through files and add to database
    files_inserted = 0
    for root, dirs, files in os.walk(category, topdown=False):
        for name in files:
            file_path = os.path.join(root, name)
            with open(file_path, "rb") as f:
                ablob = f.read()

            db_cursor.execute(
                "INSERT INTO %s VALUES (?, ?)" % (category), [file_path, ablob]
            )
            files_inserted += 1
            if files_inserted % 1000 == 0:
                logging.info(
                    "Commit after %s inserted files for %s", files_inserted, category
                )
                db_connection.commit()

        logging.info("Commit after %s inserted files for %s", files_inserted, category)
        db_connection.commit()

    db_connection.commit()
    if files_inserted == 0:
        logging.info("No files were inserted for %s, dropping empty table", category)
        db_cursor.execute("DROP TABLE IF EXISTS %s;" % (category))
    else:
        indexes_to_create.append(category)

    db_connection.commit()

# Reclaim space from deleted entries
db_cursor.execute("VACUUM;")
db_connection.commit()

# Create index
for category in indexes_to_create:
    logging.info("Creating index for %s", category)
    db_cursor.execute("CREATE INDEX %sIndex ON %s(path)" % (category, category))

db_connection.commit()
db_connection.close()
