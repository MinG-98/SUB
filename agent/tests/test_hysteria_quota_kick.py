import importlib.util
import json
import threading
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "agent", Path(__file__).resolve().parent.parent / "node-agent.py"
)
agent_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_mod)


class Response:
    def __init__(self, body=b""):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit=-1):
        return self.body


def test_quota_kick_denies_reconnect_before_targeted_session_disconnect(monkeypatch):
    agent = agent_mod.Agent.__new__(agent_mod.Agent)
    agent.state = {"nodes": {"42": {"traffic_secret": "test-api-secret"}}}
    agent.desired = {
        42: {
            "users": [
                {"stats_id": "over-quota", "protocol": "hysteria2"},
                {"stats_id": "within-quota", "protocol": "hysteria2"},
            ]
        }
    }
    agent.lock = threading.RLock()
    requests = []

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        if request.full_url.endswith("/online"):
            return Response(b'{"over-quota":2,"within-quota":1}')
        return Response()

    monkeypatch.setattr(agent_mod, "urlopen", fake_urlopen)

    kicked = agent.process_quota_kicks(
        {"node_id": 42, "protocol": "hysteria2", "stats_port": 9999},
        {"kick_stats_ids": ["over-quota", "over-quota", ""]},
    )

    assert kicked == 1
    assert [item[0].full_url for item in requests] == [
        "http://127.0.0.1:9999/online",
        "http://127.0.0.1:9999/kick",
    ]
    assert json.loads(requests[1][0].data) == ["over-quota"]
    assert requests[1][0].headers["Authorization"] == "test-api-secret"
    assert [item["stats_id"] for item in agent.desired[42]["users"]] == ["within-quota"]
