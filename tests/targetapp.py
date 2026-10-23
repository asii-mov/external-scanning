"""A deliberately exposed local target, for exercising the extscan pipeline.

Serves what an external audit trips over: a Swagger UI page, an OpenAPI spec
with unauthenticated write operations, a readable .env, a GraphQL endpoint with
introspection on, and a soft-404 that returns 200 for everything else (which is
what the soft-404 guard has to survive).

Bound to loopback on an ephemeral port by the tests. Nothing here talks to a
network the test host does not own.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT_PLACEHOLDER = "__PORT__"

SPEC = {
    "openapi": "3.0.1",
    "info": {"title": "ACME Billing API", "version": "2.4.1"},
    "servers": [{"url": f"http://127.0.0.1:{PORT_PLACEHOLDER}/api"},
                {"url": "https://internal-billing.corp.acme.example/api"}],
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearerAuth": []}],
    "paths": {
        "/health": {"get": {"summary": "Liveness", "security": []}},
        "/invoices": {
            "get": {"summary": "List invoices"},
            "post": {"summary": "Create invoice", "security": []},
        },
        "/invoices/{id}": {
            "delete": {"summary": "Delete invoice", "security": []},
            "get": {"summary": "Get invoice"},
        },
        "/admin/users": {
            "get": {"summary": "List all users", "security": []},
            "post": {"summary": "Create user", "operationId": "createUserAdmin"},
        },
        "/internal/debug/config": {"get": {"summary": "Dump config", "security": []}},
        "/payments/token": {"post": {"summary": "Issue payment token"}},
    },
}

# Fake credentials for the redaction tests.
#
# Keep these values deliberately UNLIKE real credential formats. An earlier
# version used a realistic `sk_live_...` Stripe shape and GitHub's push
# protection blocked the push -- correctly, since a scanner cannot tell an
# invented key from a live one. Realism here buys nothing: the probe matches on
# the key *name*, so the values only need to be greppable to prove they were
# redacted out of the report.
ENV = """APP_ENV=production
DATABASE_URL=postgres://billing:NOT-A-REAL-PASSWORD@db-prod-01.corp.acme.example:5432/billing
STRIPE_SECRET_KEY=fake-stripe-value-for-tests-only
JWT_SIGNING_SECRET=fake-jwt-signing-value-for-tests
AWS_ACCESS_KEY_ID=fake-aws-key-id-for-tests
SMTP_PASSWORD=fake-smtp-password
DEBUG=false
"""

INDEX = """<!doctype html>
<html><head><title>ACME Billing &mdash; API Console</title></head>
<body>
<h1>ACME Billing API Console</h1>
<p>Internal use only. API reference: <a href="/swagger.json">/swagger.json</a></p>
<div id="swagger-ui"></div>
<script src="/static/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/swagger.json", dom_id: '#swagger-ui' });
</script>
</body></html>
"""

GRAPHQL_SCHEMA = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "kind": "OBJECT",
             "fields": [{"name": "invoices"}, {"name": "users"}, {"name": "internalAuditLog"}]},
            {"name": "Mutation", "kind": "OBJECT",
             "fields": [{"name": "deleteInvoice"}, {"name": "promoteUserToAdmin"}]},
            {"name": "User", "kind": "OBJECT",
             "fields": [{"name": "id"}, {"name": "email"}, {"name": "passwordHash"}]},
        ],
    }}
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.18.0"
    sys_version = ""

    def log_message(self, *a):            # keep the test output readable
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._send(200, INDEX)
        if path == "/swagger.json":
            return self._send(200, json.dumps(SPEC), "application/json")
        if path == "/.env":
            return self._send(200, ENV, "text/plain")
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /internal\n",
                              "text/plain")
        if path == "/metrics":
            return self._send(200,
                              "# HELP http_requests_total Total requests\n"
                              "# TYPE http_requests_total counter\n"
                              'http_requests_total{instance="db-prod-01.corp.acme.example"} 4821\n',
                              "text/plain")
        if path == "/actuator":
            return self._send(401, '{"error":"unauthorized"}', "application/json")
        if path == "/api/health":
            return self._send(200, '{"status":"ok","build":"2.4.1"}', "application/json")
        if path == "/api/admin/users":
            return self._send(200,
                              '[{"id":1,"email":"jane.doe@acme.example","role":"admin"},'
                              '{"id":2,"email":"bob@acme.example","role":"billing"}]',
                              "application/json")
        if path == "/api/internal/debug/config":
            return self._send(403, '{"error":"forbidden"}', "application/json")
        if path == "/graphql":
            return self._send(400, '{"errors":[{"message":"Must provide query string"}]}',
                              "application/json")
        # Soft 404: 200 with the app shell. The path checker must not count
        # these as hits, or every probed path "exists".
        return self._send(200, "<html><head><title>ACME Billing</title></head>"
                               "<body><h1>Page not found</h1></body></html>")

    def do_POST(self):
        if self.path.split("?")[0] == "/graphql":
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            return self._send(200, json.dumps(GRAPHQL_SCHEMA), "application/json")
        return self._send(405, '{"error":"method not allowed"}', "application/json")


class TargetApp:
    """Start the target on an ephemeral loopback port for the duration of a test."""

    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        # The spec advertises its own base URL, so patch in the real port.
        SPEC["servers"][0]["url"] = f"http://127.0.0.1:{self.port}/api"
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
