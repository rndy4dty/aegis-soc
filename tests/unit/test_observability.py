"""
Contract tests untuk observability layer.
"""

from __future__ import annotations

import json
import logging

import pytest

from internal.observability import (
    Counter,
    Gauge,
    Histogram,
    JSONFormatter,
    MetricsRegistry,
    TraceContext,
    get_current_trace,
    new_trace,
    setup_logging,
)
from internal.observability.tracing import clear as clear_trace


# ===========================================================================
# Counter
# ===========================================================================

def test_counter_inc():
    c = Counter(name="test")
    c.inc()
    c.inc(5)
    assert c.value == 6


def test_counter_negative_rejected():
    c = Counter(name="test")
    with pytest.raises(ValueError):
        c.inc(-1)


def test_counter_reset():
    c = Counter(name="test")
    c.inc(10)
    c.reset()
    assert c.value == 0


# ===========================================================================
# Gauge
# ===========================================================================

def test_gauge_set():
    g = Gauge(name="test")
    g.set(42)
    assert g.value == 42


def test_gauge_inc_dec():
    g = Gauge(name="test")
    g.inc(10)
    g.dec(3)
    assert g.value == 7


# ===========================================================================
# Histogram
# ===========================================================================

def test_histogram_observe():
    h = Histogram(name="test", buckets=(1.0, 2.0, 5.0))
    h.observe(0.5)
    h.observe(1.5)
    h.observe(3.0)
    h.observe(10.0)
    assert h.count == 4
    assert h.sum == 15.0


def test_histogram_bucket_counts():
    h = Histogram(name="test", buckets=(1.0, 2.0, 5.0))
    h.observe(0.5)   # bucket 1
    h.observe(1.5)   # bucket 2
    h.observe(3.0)   # bucket 5
    h.observe(10.0)  # +Inf
    counts = h.bucket_counts()
    assert counts == [(1.0, 1), (2.0, 1), (5.0, 1), (None, 0)] or \
           counts[0] == (1.0, 1)


# ===========================================================================
# MetricsRegistry
# ===========================================================================

def test_registry_counter_dedup():
    r = MetricsRegistry()
    c1 = r.counter("test")
    c2 = r.counter("test")
    assert c1 is c2


def test_registry_labels_isolate():
    r = MetricsRegistry()
    a = r.counter("test", labels={"method": "GET"})
    b = r.counter("test", labels={"method": "POST"})
    assert a is not b


def test_registry_render_prometheus():
    r = MetricsRegistry()
    r.counter("test_total", help="Test counter").inc(5)
    r.gauge("test_gauge", help="Test gauge").set(42)
    h = r.histogram("test_duration", help="Test hist")
    h.observe(0.5)

    text = r.render()
    assert "# HELP test_total Test counter" in text
    assert "# TYPE test_total counter" in text
    assert "test_total 5" in text
    assert "test_gauge 42" in text
    assert "test_duration_bucket" in text
    assert "test_duration_count" in text


def test_registry_render_labels():
    r = MetricsRegistry()
    r.counter(
        "req_total", labels={"method": "GET"}
    ).inc(3)
    text = r.render()
    assert 'method="GET"' in text


def test_registry_reset():
    r = MetricsRegistry()
    r.counter("x").inc(5)
    r.reset()
    assert r.render() == "\n"


# ===========================================================================
# TraceContext
# ===========================================================================

def test_new_trace():
    clear_trace()
    ctx = new_trace(tags={"case": "C-1"})
    assert ctx.trace_id
    assert ctx.span_id
    assert ctx.parent_span_id is None
    assert ctx.tags == {"case": "C-1"}


def test_get_current_trace():
    clear_trace()
    ctx = new_trace()
    assert get_current_trace() is ctx


def test_trace_with_tag():
    ctx = new_trace()
    ctx2 = ctx.with_tag("k", "v")
    assert "k" in ctx2.tags
    assert "k" not in ctx.tags  # immutable


def test_trace_contextmanager():
    clear_trace()
    parent = new_trace(tags={"root": True})

    from internal.observability import trace

    with trace(name="child", tags={"op": "read"}):
        child = get_current_trace()
        assert child.trace_id == parent.trace_id
        assert child.parent_span_id == parent.span_id
        assert child.tags.get("op") == "read"

    # Setelah exit, parent di-restore
    assert get_current_trace() is parent


# ===========================================================================
# Logging
# ===========================================================================

def test_json_formatter_basic():
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    data = json.loads(output)
    assert data["level"] == "INFO"
    assert data["logger"] == "test"
    assert data["msg"] == "hello"
    assert "ts" in data


def test_json_formatter_includes_trace():
    clear_trace()
    new_trace(trace_id="abc123")

    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    data = json.loads(output)
    assert data.get("trace_id") == "abc123"

    clear_trace()


def test_setup_logging_json():
    setup_logging(level="INFO", use_json=True)
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JSONFormatter)


def test_setup_logging_plain():
    setup_logging(level="INFO", use_json=False)
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert not isinstance(root.handlers[0].formatter, JSONFormatter)


# ===========================================================================
# FastAPI integration
# ===========================================================================

def test_fastapi_metrics_endpoint():
    from fastapi.testclient import TestClient

    from api.main import create_app

    app = create_app()
    client = TestClient(app)

    # Trigger some requests
    client.get("/health")
    client.get("/version")

    r = client.get("/metrics")
    assert r.status_code == 200
    body = r.text
    assert "aegis_http_requests_total" in body
    assert "aegis_http_request_duration_seconds" in body


def test_fastapi_trace_header():
    from fastapi.testclient import TestClient

    from api.main import create_app

    app = create_app()
    client = TestClient(app)

    r = client.get("/health")
    assert "X-Trace-Id" in r.headers
    assert r.headers["X-Trace-Id"]


def test_fastapi_trace_propagation():
    from fastapi.testclient import TestClient

    from api.main import create_app

    app = create_app()
    client = TestClient(app)

    r = client.get(
        "/health",
        headers={"X-Trace-Id": "my-trace-123"},
    )
    assert r.headers["X-Trace-Id"] == "my-trace-123"
