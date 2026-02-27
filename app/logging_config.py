import logging
import os

os.makedirs("logs", exist_ok=True)

access_logger = logging.getLogger("access")
error_logger = logging.getLogger("error")
sql_logger = logging.getLogger("sql")

for logger, path in [
    (access_logger, "logs/access.log"),
    (error_logger, "logs/error.log"),
    (sql_logger, "logs/error.log"),
]:
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(path)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
