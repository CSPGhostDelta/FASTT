from celery import Celery

celery = Celery(__name__, broker='redis://172.18.0.2:6379/0') 

def make_celery(app):
    celery.conf.update(app.config)
    return celery

import app.scanner 