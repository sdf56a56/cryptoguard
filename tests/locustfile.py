"""
负载压测脚本(spec §6.3 PERF-BUDGET-3)—— Locust 100 VU x 60s。

用法(多 worker 起后端后):
    gunicorn app.main:app -c gunicorn_conf.py        # Linux 部署形态
    locust -f tests/locustfile.py --headless -u 100 -t 60s \
        --host http://localhost:8000 --csv /tmp/locust_cg

达标线:>= 100 QPS、P95 端到端 < 500ms(密码学段 < 20ms 从 /api/perf 聚合)。
"""
from locust import HttpUser, between, task


class CryptoGuardUser(HttpUser):
    wait_time = between(0.01, 0.05)

    @task
    def query(self):
        self.client.post("/api/proxy/query2", json={
            "schema_version": "CG/2.0",
            "text": "张三 13800138000 查询余额",
            "scenario": "medical",
        })
