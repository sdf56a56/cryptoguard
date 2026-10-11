"""
gunicorn 多 worker 配置(R7)—— 启动:gunicorn app.main:app -c gunicorn_conf.py

CPU 核数个 uvicorn worker;QPS 承诺挂多 worker(README 启动命令同此)。
"""
import os

workers = os.cpu_count()
worker_class = "uvicorn.workers.UvicornWorker"
bind = "0.0.0.0:8000"
