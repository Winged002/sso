import os, threading
from flask import current_app
from pymongo import MongoClient

_lock=threading.Lock()


def mongo_client():
    app=current_app._get_current_object();pid=os.getpid()
    with _lock:
        state=app.extensions.get('syntal_mongo')
        if not state or state['pid']!=pid:
            if state:state['client'].close()
            state={'pid':pid,'client':MongoClient(app.config['MONGO_URI'],tz_aware=True,serverSelectionTimeoutMS=3000,maxPoolSize=50)}
            app.extensions['syntal_mongo']=state
        return state['client']


def db():return mongo_client()[current_app.config['MONGO_DB']]


def close_db(_exc=None):
    # The client owns a process-local pool and lives until worker shutdown.
    return None
