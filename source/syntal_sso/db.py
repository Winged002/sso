from flask import current_app, g
from pymongo import MongoClient


def mongo_client():
    if "mongo_client" not in g:
        g.mongo_client = MongoClient(current_app.config["MONGO_URI"], tz_aware=True, serverSelectionTimeoutMS=3000)
    return g.mongo_client


def db():
    return mongo_client()[current_app.config["MONGO_DB"]]


def close_db(_exc=None):
    client = g.pop("mongo_client", None)
    if client is not None:
        client.close()
