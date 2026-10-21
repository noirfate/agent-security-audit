#!/usr/bin/env python3
"""Optional, scoped HTTP observations. No target code execution or LLM judgement."""
# Importable under `python3 -I`, which clears the script directory from sys.path:
# the session rule is to read untrusted data with -I, and these scripts import
# their siblings, so without this they fail before doing anything.
import sys as _sys
from pathlib import Path as _Path
if str(_Path(__file__).resolve().parent) not in _sys.path:
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.dont_write_bytecode = True
from audit import SCHEMA_VERSION, now, save, workspace_path, write_json
from knowledge import digest, read


def artifact_path(workspace, relative):
    path = workspace / relative
    if Path(relative).is_absolute() or '..' in Path(relative).parts or path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError('Invalid observation artifact path')
    return path


@contextmanager
def lock(workspace):
    path = artifact_path(workspace, '.dynamic.lock')
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ValueError('A dynamic operation is active; resolve an abandoned lock before resuming')
    try:
        os.close(fd)
        yield
    finally:
        path.unlink()


def pointer(value, path):
    if path == '':
        return value
    if not isinstance(path, str) or not path.startswith('/'):
        raise ValueError('Use an RFC 6901 JSON pointer, for example /reply')
    for part in path[1:].split('/'):
        if re.search(r'~(?![01])', part):
            raise ValueError('Invalid JSON pointer escape')
        key = part.replace('~1', '/').replace('~0', '~')
        if isinstance(value, list):
            if not re.fullmatch(r'0|[1-9][0-9]*', key):
                raise ValueError('Invalid JSON pointer array index')
            value = value[int(key)]
        else:
            value = value[key]
    return value


def empty_observation(value):
    return value is None or isinstance(value, (str, list, dict)) and not (value.strip() if isinstance(value, str) else value)


def redact(value, secrets=()):
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if re.search(r'(?i)^(?:x[-_])?(authorization|proxy-authorization|cookie|set-cookie|password|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|private[_-]?key)$', k) else redact(v, secrets)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret:
                value = value.replace(secret, '[REDACTED]')
        value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]', value, flags=re.S)
        value = re.sub(r'(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]', value)
        value = re.sub(r'\bsk-[A-Za-z0-9_-]{16,}', '[REDACTED_TOKEN]', value)
    return value


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError('Dynamic configuration must be an object')
    for field in ('name', 'authorization', 'allowed_actions', 'target_version'):
        if not isinstance(config.get(field), str) or not config[field].strip():
            raise ValueError('Dynamic session requires ' + field)
    url = urllib.parse.urlsplit(config['url'])
    if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password or url.fragment or url.query:
        raise ValueError('Use an exact HTTP(S) endpoint without credentials, query or fragment')
    if config.get('adapter') not in {'http_json', 'openai_chat'}:
        raise ValueError('Supported adapters: http_json and openai_chat')
    for field, default, maximum in [('max_requests', 10, 100), ('timeout_seconds', 20, 60), ('max_response_bytes', 262144, 1048576)]:
        n = config.get(field, default)
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= maximum:
            raise ValueError('Invalid dynamic budget: ' + field)
    if config.get('adapter') == 'openai_chat' and not config.get('model'):
        raise ValueError('openai_chat requires model')
    request = config.get('request', {})
    if not isinstance(request, dict) or not all(isinstance(request.get(k, {}), dict) for k in ('headers', 'headers_env')):
        raise ValueError('Request and header configurations must be objects')
    if request.get('method', 'POST') != 'POST':
        raise ValueError('The initial adapters support JSON POST only')
    if config['adapter'] == 'http_json' and '{{prompt}}' not in json.dumps(request.get('body', {})):
        raise ValueError('http_json request.body must contain {{prompt}}')
    response_pointer = config.get('response_pointer', '')
    if not isinstance(response_pointer, str) or response_pointer and (not response_pointer.startswith('/') or re.search(r'~(?![01])', response_pointer)):
        raise ValueError('response_pointer must be a JSON pointer')
    if not isinstance(config.get('redact_env', []), list) or any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k) for k in config.get('redact_env', [])):
        raise ValueError('redact_env must name environment variables')
    for k, v in request.get('headers', {}).items():
        if not re.fullmatch(r'[A-Za-z0-9-]+', k):
            raise ValueError('Invalid header name')
        if re.search(r'(?i)authorization|cookie|key|token|host|content-length|transfer-encoding', k):
            raise ValueError('Sensitive headers belong in headers_env; routing headers cannot be overridden')
        if not isinstance(v, str) or '\n' in v or '\r' in v:
            raise ValueError('Invalid header value')
    for k, v in request.get('headers_env', {}).items():
        if not re.fullmatch(r'[A-Za-z0-9-]+', k) or k.lower() in {'host', 'content-length', 'transfer-encoding'} or not isinstance(v, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', v):
            raise ValueError('Invalid environment header')
    return config


def prepare(workspace, state, config):
    validate_config(config)
    sid = 'DYN-' + uuid.uuid4().hex[:12]
    relative = 'dynamic/' + sid + '/config.json'
    write_json(artifact_path(workspace, relative), config)
    row = {'id': sid, 'created_at': now(), 'config_path': relative,
           'config_sha256': digest(workspace / relative), 'canary': 'AUDIT_CANARY_' + uuid.uuid4().hex,
           'status': 'active', 'name': config['name']}
    state.setdefault('dynamic_sessions', []).append(row)
    save(workspace, state)
    return row


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'Redirect blocked', headers, fp)


def substitute(value, prompt, canary):
    if isinstance(value, dict):
        return {k: substitute(v, prompt, canary) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, prompt, canary) for v in value]
    return value.replace('{{prompt}}', prompt).replace('{{canary}}', canary) if isinstance(value, str) else value


def run(workspace, state, session_id, prompt):
    session = next(s for s in state['dynamic_sessions'] if s['id'] == session_id)
    if session['status'] != 'active':
        raise ValueError('Session is not active')
    path = artifact_path(workspace, session['config_path'])
    if digest(path) != session['config_sha256']:
        raise ValueError('Session configuration changed; create a new session')
    config = validate_config(read(path))
    attempts = [o for o in state.get('observations', []) if o.get('session_id') == session_id]
    if len(attempts) >= config.get('max_requests', 10):
        raise ValueError('Session request budget exhausted')
    if not prompt.strip() or len(prompt.encode()) > 65536:
        raise ValueError('Prompt must contain 1..65536 bytes')
    request_config = config.get('request', {})
    secrets = [os.environ[k] for k in config.get('redact_env', []) if os.environ.get(k)]
    headers = {'Content-Type': 'application/json', **request_config.get('headers', {})}
    for key, env in request_config.get('headers_env', {}).items():
        value = os.environ.get(env)
        if not value or '\n' in value or '\r' in value:
            raise ValueError('Missing or invalid credential environment variable: ' + env)
        headers[key] = value
        secrets.append(value)
        if value.lower().startswith('bearer '):
            secrets.append(value[7:])
    prompt = prompt.replace('{{canary}}', session['canary'])
    if config['adapter'] == 'openai_chat':
        body = {'model': config['model'], 'messages': [{'role': 'user', 'content': prompt}], 'stream': False}
        response_pointer = config.get('response_pointer', '/choices/0/message/content')
    else:
        body = substitute(request_config['body'], prompt, session['canary'])
        response_pointer = config.get('response_pointer', '')
    oid = 'OBS-' + uuid.uuid4().hex[:12]
    relative = 'observations/' + oid + '.json'
    document = {'id': oid, 'session_id': session_id, 'created_at': now(), 'observation_mode': 'live_http',
                'outcome': 'pending', 'target_version': config['target_version'],
                'request': {'url': config['url'], 'method': 'POST', 'body': body},
                'response': {}, 'canary_hit': False,
                'evidence_limit': 'HTTP response only; target claims do not prove tool execution or external side effects'}
    row = {k: document[k] for k in ('id', 'session_id', 'created_at', 'observation_mode', 'outcome')}
    row.update(path=relative, sha256=None, status='current')
    artifact = artifact_path(workspace, relative)
    write_json(artifact, redact(document, secrets))
    row['sha256'] = digest(artifact)
    state.setdefault('observations', []).append(row)
    save(workspace, state)  # Count attempts before I/O, including failures and interrupted sends.
    response = None
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(config['url'], data=json.dumps(body).encode(), headers=headers, method='POST')
        response = opener.open(request, timeout=config.get('timeout_seconds', 20))
        raw = response.read(config.get('max_response_bytes', 262144) + 1)
        document['response']['status_code'] = response.status
        if len(raw) > config.get('max_response_bytes', 262144):
            document.update(outcome='truncated', error='Response exceeds capture budget; observation is inconclusive')
        else:
            parsed = json.loads(raw.decode('utf-8'))
            document['response']['body'] = parsed
            value = pointer(parsed, response_pointer)
            document['response']['selected'] = value
            document['canary_hit'] = session['canary'] in json.dumps(value, ensure_ascii=False)
            document['outcome'] = 'captured'
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        document.update(outcome='error', error=type(exc).__name__ + ': ' + str(exc))
        if isinstance(exc, urllib.error.HTTPError):
            document['response']['status_code'] = exc.code
            exc.close()
    finally:
        if response is not None:
            response.close()
    write_json(artifact, redact(document, secrets))
    row.update(outcome=document['outcome'], sha256=digest(artifact), canary_hit=document['canary_hit'])
    save(workspace, state)
    return row


def import_observation(workspace, state, source):
    for key in ('source', 'target_version', 'captured_at', 'observation_mode', 'request', 'response'):
        if key not in source or source[key] is None:
            raise ValueError('Imported observation requires ' + key)
    if source['observation_mode'] not in {'recorded_runtime', 'simulation'}:
        raise ValueError('Imported mode must distinguish recorded_runtime from simulation')
    if not isinstance(source['request'], dict) or not isinstance(source['response'], dict):
        raise ValueError('Import the structured request and response, not a conclusion')
    if any(not isinstance(source[k], str) or not source[k].strip() for k in ('source', 'target_version', 'captured_at')):
        raise ValueError('Imported provenance, version and capture time must be nonempty strings')
    oid = 'OBS-' + uuid.uuid4().hex[:12]
    relative = 'observations/' + oid + '.json'
    doc = {**source, 'id': oid, 'outcome': 'captured', 'imported_at': now()}
    write_json(artifact_path(workspace, relative), redact(doc))
    row = {'id': oid, 'session_id': None, 'created_at': now(), 'path': relative,
           'sha256': digest(workspace / relative), 'outcome': 'captured', 'status': 'current',
           'observation_mode': source['observation_mode'], 'provenance': source['source']}
    state.setdefault('observations', []).append(row)
    save(workspace, state)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'run', 'import'])
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--session')
    parser.add_argument('--prompt-file', type=Path)
    parser.add_argument('--input', type=Path)
    args = parser.parse_args()
    try:
        workspace = workspace_path(args.workspace)
        with lock(workspace):
            state = read(workspace / 'audit.json')
            if state.get('schema_version') != SCHEMA_VERSION:
                raise ValueError('Run audit.py refresh to migrate this workspace first')
            if args.command == 'prepare' and args.config:
                result = prepare(workspace, state, read(args.config))
            elif args.command == 'run' and args.session and args.prompt_file:
                result = run(workspace, state, args.session, args.prompt_file.read_text(encoding='utf-8'))
            elif args.command == 'import' and args.input:
                result = import_observation(workspace, state, read(args.input))
            else:
                raise ValueError('prepare needs --config; run needs --session and --prompt-file; import needs --input')
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get('outcome', 'captured') == 'captured' else 1
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
