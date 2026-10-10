#!/usr/bin/env python3
"""Exercise the real packaged local model worker with public fixtures only.
Never opens a VPN profile, Keychain, proxy settings or system VPN component.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request

MODEL_NAME = 'Qwen3-0.6B-Q8_0.gguf'
MODEL_BYTES = 639446688
MODEL_SHA = '9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031'
MODEL_URL = 'https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/resolve/23749fefcc72300e3a2ad315e1317431b06b590a/' + MODEL_NAME

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()

def alive(pid):
    if sys.platform == 'win32':
        import ctypes as c
        kernel = c.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.restype = c.c_void_p
        kernel.GetExitCodeProcess.argtypes = [c.c_void_p, c.POINTER(c.c_ulong)]
        kernel.CloseHandle.argtypes = [c.c_void_p]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle: return False
        try:
            code = c.c_ulong()
            return bool(kernel.GetExitCodeProcess(handle, c.byref(code))) and code.value == 259
        finally: kernel.CloseHandle(handle)
    result = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True)
    return bool(result.stdout.strip()) and not result.stdout.strip().startswith('Z')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--installer', type=Path)
    args = parser.parse_args()
    executable = args.executable.resolve()
    model = args.model.resolve()
    if not model.is_file():
        model.parent.mkdir(parents=True, exist_ok=True)
        partial = model.with_suffix('.part')
        with urllib.request.urlopen(MODEL_URL, timeout=30) as source, partial.open('wb') as out:
            total = 0
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > MODEL_BYTES: raise RuntimeError('oversized model')
                out.write(chunk)
        assert partial.stat().st_size == MODEL_BYTES and digest(partial) == MODEL_SHA
        partial.rename(model)
    assert model.stat().st_size == MODEL_BYTES and digest(model) == MODEL_SHA
    facts = dict(platform='windows' if sys.platform == 'win32' else 'macos', core_ok=True,
        helper_ok=None if sys.platform == 'win32' else True, connection_ok=True, dns_ok=None,
        proxy_ok=None, servers_available=None, tested=0, has_servers=True,
        has_recommendation=False, action='none')
    results = []
    def run(job, expected):
        start = time.monotonic()
        process = subprocess.run([str(executable), '--foxvpn-ai-worker', str(os.getpid())],
            input=job, capture_output=True, timeout=95)
        assert (process.returncode == 0) == expected, process.stderr.decode(errors='replace')[-1200:]
        return process, round(time.monotonic() - start, 3)
    cases = [('connected', {}, 'HTTPS'),
        ('missing_server', {'has_servers':False, 'connection_ok':None, 'action':'add_server'}, 'сервер'),
        ('missing_core', {'core_ok':False, 'connection_ok':None, 'action':'reinstall'}, 'приложен'),
        ('stale_helper', {'platform':'macos', 'helper_ok':False, 'connection_ok':None, 'action':'helper'}, 'компонент'),
        ('windows_proxy', {'platform':'windows', 'helper_ok':None, 'proxy_ok':False, 'action':'windows_proxy'}, 'прокси'),
        ('unknown_failure', {'connection_ok':False, 'action':'none'}, 'не')]
    for name, changes, expected_word in cases:
        process, elapsed = run(json.dumps({'model':str(model), 'facts':facts | changes}).encode(), True)
        text = json.loads(process.stdout)
        assert isinstance(text, str) and any('а' <= c <= 'я' for c in text)
        assert '<think>' not in text and len(text) <= 1800
        assert expected_word.lower() in text.lower(), (name, text)
        assert '"core_ok"' not in text and '"platform"' not in text, (name, text)
        results.append(dict(case=name, elapsed_seconds=elapsed, response=text))
    with tempfile.TemporaryDirectory(prefix='foxvpn-public-ai-fixtures-') as temp:
        bad = Path(temp) / MODEL_NAME
        bad.write_bytes(b'GGUF corrupted public fixture')
        run(json.dumps({'model':str(bad), 'facts':facts}).encode(), False)
    run(json.dumps({'model':str(model), 'facts':facts | {'secret':'PUBLIC_TEST_SENTINEL'}}).encode(), False)
    run(b'X' * 8193, False)
    # A forced GUI/parent death must not leave an inference process behind.
    wrapper = """import json,os,subprocess,sys,time
p=subprocess.Popen([sys.argv[1],'--foxvpn-ai-worker',str(os.getpid())],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(p.pid,flush=True)
p.stdin.write(sys.argv[2].encode());p.stdin.flush();time.sleep(300)
"""
    parent = subprocess.Popen([sys.executable, '-c', wrapper, str(executable),
        json.dumps({'model':str(model), 'facts':facts})], stdout=subprocess.PIPE, text=True)
    child_pid = int(parent.stdout.readline())
    time.sleep(0.5)
    parent.kill(); parent.wait(timeout=5)
    deadline = time.monotonic() + 5
    while alive(child_pid) and time.monotonic() < deadline: time.sleep(0.1)
    assert not alive(child_pid), 'inference worker survived parent death'
    report = dict(platform=sys.platform, executable_sha256=digest(executable), model_sha256=MODEL_SHA,
        model_bytes=MODEL_BYTES, inference=results, corrupted_model_rejected=True,
        unknown_fields_rejected=True, oversized_input_rejected=True, parent_death_cleanup=True)
    if sys.platform == 'darwin':
        import resource
        report['peak_child_rss_mib'] = round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1048576, 1)
    if args.installer: report['installer_sha256'] = digest(args.installer)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))

if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'): sys.stdout.reconfigure(encoding='utf-8')
    main()
