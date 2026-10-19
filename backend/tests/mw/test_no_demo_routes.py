"""确保演示平台没有被“顺手保留”回来：路由表里不应再出现 /api/* 或静态托管。"""
from __future__ import annotations

from fastapi.routing import APIRoute
from starlette.routing import Mount

from app.main import app


def _routes(routes):
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            yield from _routes(getattr(original, "routes", []) or [])
            continue
        yield route
        for child in getattr(route, "routes", []) or []:
            yield from _routes([child])


def _paths() -> set[str]:
    return {route.path for route in _routes(app.routes)
            if isinstance(route, APIRoute)}


def test_no_api_routes_remain():
    paths = _paths()
    assert not any(path.startswith("/api") for path in paths)
    assert not any(path.startswith("/ws") for path in paths)
    # 网关自己需要的路径仍在
    for expected in ("/health", "/ready", "/metrics", "/v1/chat/completions",
                     "/v1/messages", "/v1/responses"):
        assert expected in paths, expected


def test_no_static_mount_or_spa_catch_all():
    for route in _routes(app.routes):
        assert not isinstance(route, Mount), f"不应再有静态/子应用挂载: {route}"
        if isinstance(route, APIRoute):
            assert route.path not in ("/{full_path:path}",), route.path


def test_removed_demo_endpoints_are_404(client):
    for path in ("/api/health", "/api/detect", "/api/chat/sessions", "/",
                 "/assets/index.js"):
        response = client.get(path)
        assert response.status_code == 404, (path, response.status_code)
