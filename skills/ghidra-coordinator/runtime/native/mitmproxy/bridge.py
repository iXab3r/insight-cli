"""MIT first-party typed HTTP observation bridge; never installs trust or system proxy settings."""
import asyncio
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import time
from mitmproxy import ctx, http
from mitmproxy.io import FlowReader, FlowWriter


class Bridge:
    def __init__(self):
        plan_path = Path(os.environ['INSIGHT_MITMPROXY_PLAN'])
        if not plan_path.is_absolute() or plan_path.stat().st_size > 16384:
            raise ValueError('Invalid bounded private plan')
        self.plan = json.loads(plan_path.read_text())
        p = self.plan
        if p['schema'] != 1 or p['mode'] not in ('record', 'inspect') or not 0 <= p['bodyBytes'] <= 65536 or not 1 <= p['maxFlows'] <= 1000:
            raise ValueError('Invalid typed HTTP operation')
        self.directory = plan_path.parent
        self.report = open(self.directory / 'flows.jsonl', 'xb')
        self.capture = open(self.directory / 'capture.mitm', 'xb') if p['mode'] == 'record' else None
        self.ids = set()
        self.active = {}
        self.count = self.skipped = self.report_bytes = self.archive_bytes = 0
        self.complete = False
        self.reason = 'interrupted'
        self.error_text = None
        self.finished = False
        self.tls_failures = []
        self.emit({'kind': 'header', 'schema': 1, 'nonce': p['nonce'], 'mode': p['mode']})

    def emit(self, value):
        data = (json.dumps(value, ensure_ascii=True, separators=(',', ':')) + '\n').encode()
        if self.report_bytes + len(data) > 8 * 1024 * 1024:
            self.end(False, 'report_limit')
            return False
        self.report.write(data)
        self.report.flush()
        os.fsync(self.report.fileno())
        self.report_bytes += len(data)
        return True

    def message(self, message):
        if message is None:
            return None
        available = message.raw_content is not None
        body = message.raw_content or b''
        headers = list(message.headers.items(multi=True))
        limit = self.plan['bodyBytes']
        return {'httpVersion': message.http_version, 'headers': [[k[:256], v[:4096]] for k, v in headers[:64]],
                'headersTruncated': len(headers) > 64 or any(len(k) > 256 or len(v) > 4096 for k, v in headers),
                'bodyAvailable': available, 'bodyBase64': base64.b64encode(body[:limit]).decode() if available else None,
                'bodyBytes': len(body) if available else None,
                'bodySha256': hashlib.sha256(body).hexdigest() if available else None, 'bodyTruncated': len(body) > limit if available else None}

    def observe(self, flow):
        if self.finished:
            return
        if self.count + self.skipped >= self.plan['maxFlows']:
            self.end(False, 'flow_limit')
            return
        if not isinstance(flow, http.HTTPFlow):
            self.skipped += 1
            return
        if flow.id in self.ids:
            return
        if self.count >= self.plan['maxFlows']:
            self.end(False, 'flow_limit')
            return
        if self.capture is not None:
            buffer = io.BytesIO()
            FlowWriter(buffer).add(flow)
            data = buffer.getvalue()
            if self.archive_bytes + len(data) > 64 * 1024 * 1024:
                self.end(False, 'archive_limit')
                return
            self.capture.write(data)
            self.capture.flush()
            os.fsync(self.capture.fileno())
            self.archive_bytes += len(data)
        request = self.message(flow.request)
        request.update(method=flow.request.method, scheme=flow.request.scheme, host=flow.request.host,
                       port=flow.request.port, path=flow.request.path, url=flow.request.pretty_url)
        response = self.message(flow.response)
        if response is not None:
            response['statusCode'] = flow.response.status_code
        row = {'kind': 'http', 'id': flow.id, 'request': request, 'response': response,
               'error': flow.error.msg[:4096] if flow.error else None,
               'timestampStart': flow.request.timestamp_start,
               'timestampEnd': flow.response.timestamp_end if flow.response else flow.request.timestamp_end,
               'websocketPayloadObserved': False, 'pending': flow.response is None and flow.error is None}
        if self.emit(row):
            self.ids.add(flow.id)
            self.count += 1

    def requestheaders(self, flow: http.HTTPFlow):
        if len(self.active) + self.count >= self.plan['maxFlows']:
            self.end(False, 'flow_limit')
        else:
            self.active[flow.id] = flow

    def tls_failed_client(self, data):
        self.tls_failure('client', data)

    def tls_failed_server(self, data):
        self.tls_failure('server', data)

    def tls_failure(self, side, data):
        if len(self.tls_failures) < 64:
            self.tls_failures.append({'side': side, 'error': str(getattr(data.conn, 'error', 'TLS handshake failed'))[:4096]})

    def response(self, flow: http.HTTPFlow):
        self.active.pop(flow.id, None)
        self.observe(flow)

    def error(self, flow: http.HTTPFlow):
        self.active.pop(flow.id, None)
        self.observe(flow)

    async def running(self):
        if self.plan['mode'] == 'inspect':
            try:
                with open(self.plan['input'], 'rb') as source:
                    for flow in FlowReader(source).stream():
                        self.observe(flow)
                        if self.finished:
                            return
                self.end(self.skipped == 0, 'eof' if self.skipped == 0 else 'unsupported_flow_types')
            except Exception as error:
                self.error_text = str(error)[:4096]
                self.end(False, 'read_error')
        else:
            addresses = ctx.master.addons.get('proxyserver').listen_addrs()
            if not addresses or any(a[0] != '127.0.0.1' or a[1] != self.plan['port'] for a in addresses):
                self.error_text = 'The owned loopback HTTP proxy did not bind the selected endpoint'
                self.end(False, 'bind_unverified')
                return
            with open(self.directory / 'ready.json', 'x') as ready:
                json.dump({'schema': 1, 'nonce': self.plan['nonce'], 'host': '127.0.0.1', 'port': self.plan['port']}, ready)
                ready.flush()
                os.fsync(ready.fileno())
            asyncio.create_task(self.deadline())

    async def deadline(self):
        await asyncio.sleep(self.plan['durationSeconds'])
        pending = len(self.active)
        for flow in list(self.active.values()):
            self.observe(flow)
        self.end(pending == 0, 'duration' if pending == 0 else 'in_flight_at_deadline')

    def end(self, complete, reason):
        if self.finished:
            return
        self.complete, self.reason, self.finished = complete, reason, True
        ctx.master.shutdown()

    def done(self):
        if self.capture:
            self.capture.flush()
            os.fsync(self.capture.fileno())
            self.capture.close()
        self.report.flush()
        os.fsync(self.report.fileno())
        self.report.close()
        with open(self.directory / 'result.json', 'x') as result:
            json.dump({'schema': 1, 'nonce': self.plan['nonce'], 'mode': self.plan['mode'],
                       'complete': self.complete and not self.tls_failures,
                       'reason': 'tls_handshake_failure' if self.complete and self.tls_failures else self.reason,
                       'error': self.error_text, 'tlsFailures': self.tls_failures,
                       'pendingRequests': len(self.active), 'httpFlows': self.count, 'skippedFlows': self.skipped, 'archiveBytes': self.archive_bytes,
                       'reportBytes': self.report_bytes}, result)
            result.flush()
            os.fsync(result.fileno())


addons = [Bridge()]
