#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import asyncio
import fcntl
import os
import re
import sys
import tempfile
import traceback
from contextlib import asynccontextmanager
from enum import IntEnum
from typing import List, AsyncGenerator, Optional, Callable, Awaitable, TypeVar, TextIO

T = TypeVar('T')


class ReturnCode(IntEnum):
    OK = 0
    UNKNOWN = 1
    SUBCOMMAND = 2
    PERMISSION = 3
    BLOCKING = 4


def acquire_lock(filename: str) -> TextIO:
    f = open(filename, 'w')
    fcntl.flock(f, fcntl.LOCK_EX)
    return f


@asynccontextmanager
async def lock(filename: str) -> AsyncGenerator[None, None]:
    f = await asyncio.get_running_loop().run_in_executor(None, acquire_lock, filename)
    try:
        yield
    finally:
        f.close()


def is_root() -> bool:
    return os.getuid() == 0


async def stop(if_started: bool = False) -> int:
    if not is_root():
        print('This script must be run as root.', file=sys.stderr)
        return ReturnCode.PERMISSION
    proc = await asyncio.create_subprocess_shell(
        'ip rule del fwmark 1 table 100;'
        'ip route del local 0.0.0.0/0 dev lo table 100;'
        'iptables -t mangle -F V2RAY;'
        'iptables -t mangle -F V2RAY_MARK;'
        'iptables -t mangle -D PREROUTING -j V2RAY;'
        'iptables -t mangle -D OUTPUT -j V2RAY_MARK;'
        'iptables -t mangle -X V2RAY;'
        'iptables -t mangle -X V2RAY_MARK;',
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode:
        return_code = ReturnCode.SUBCOMMAND
        if if_started:
            print(stderr.decode(), end='', file=sys.stderr)
        else:
            for line in stderr.decode().split('\n'):
                if line and 'for more information' not in line and \
                        'No such file or directory' not in line and \
                        'No such process' not in line and \
                        'No chain/target/match by that name' not in line:
                    print(line, file=sys.stderr)
                    break
            else:
                return_code = ReturnCode.OK
    else:
        return_code = ReturnCode.OK
    return return_code


async def start(port: int) -> int:
    if not is_root():
        print('This script must be run as root.', file=sys.stderr)
        return ReturnCode.PERMISSION
    return_code = await stop()
    if return_code != ReturnCode.OK:
        return return_code
    proc = await asyncio.create_subprocess_exec(
        'ip', '-4', 'route', 'ls',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode:
        print(stderr.decode(), end='', file=sys.stderr)
        return ReturnCode.SUBCOMMAND
    ip4: List[str] = []
    for line in stdout.decode().split('\n'):
        if not line.startswith('default'):
            continue
        match = re.search(r'(?<=dev )(\S+)', line)
        if not match:
            continue
        interface = match.group(1)
        proc2 = await asyncio.create_subprocess_exec(
            'ip', '-o', '-4', 'addr', 'list', interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout2, stderr2 = await proc2.communicate()
        if proc2.returncode:
            print(stderr2.decode(), end='', file=sys.stderr)
            return ReturnCode.SUBCOMMAND
        for line2 in stdout2.decode().split('\n'):
            if not line2:
                continue
            ip4.append(line2.split()[3].split('/')[0])
    proc3 = await asyncio.create_subprocess_shell(
        # Setting up routes
        'ip rule add fwmark 1 table 100;'
        'ip route add local 0.0.0.0/0 dev lo table 100;'
        # Create chains
        'iptables -t mangle -N V2RAY;'
        'iptables -t mangle -N V2RAY_MARK;' +
        # Proxy local network connections
        ''.join([f'iptables -t mangle -A V2RAY -d "{ip}" -j RETURN;' for ip in ip4]) +
        'iptables -t mangle -A V2RAY -d 0.0.0.0/8 -j RETURN;'
        'iptables -t mangle -A V2RAY -d 127.0.0.0/8 -j RETURN;'
        'iptables -t mangle -A V2RAY -d 169.254.0.0/16 -j RETURN;'
        'iptables -t mangle -A V2RAY -d 224.0.0.0/4 -j RETURN;'
        'iptables -t mangle -A V2RAY -d 240.0.0.0/4 -j RETURN;'
        'iptables -t mangle -A V2RAY -d 255.255.255.255/32 -j RETURN;'
        'iptables -t mangle -A V2RAY -d 10.0.0.0/8 -p tcp -j RETURN;'
        'iptables -t mangle -A V2RAY -d 10.0.0.0/8 -p udp ! --dport 53 -j RETURN;'
        'iptables -t mangle -A V2RAY -d 172.16.0.0/12 -p tcp -j RETURN;'
        'iptables -t mangle -A V2RAY -d 172.16.0.0/12 -p udp ! --dport 53 -j RETURN;'
        'iptables -t mangle -A V2RAY -d 192.168.0.0/16 -p tcp -j RETURN;'
        'iptables -t mangle -A V2RAY -d 192.168.0.0/16 -p udp ! --dport 53 -j RETURN;'
        f'iptables -t mangle -A V2RAY -p udp -j TPROXY --on-port "{port}" --tproxy-mark 1;'
        f'iptables -t mangle -A V2RAY -p tcp -j TPROXY --on-port "{port}" --tproxy-mark 1;'
        # Proxy self connections
        'iptables -t mangle -A V2RAY_MARK -d 0.0.0.0/8 -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 127.0.0.0/8 -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 169.254.0.0/16 -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 224.0.0.0/4 -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 240.0.0.0/4 -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 255.255.255.255/32 -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 10.0.0.0/8 -p tcp -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 10.0.0.0/8 -p udp ! --dport 53 -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 172.16.0.0/12 -p tcp -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 172.16.0.0/12 -p udp ! --dport 53 -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 192.168.0.0/16 -p tcp -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -d 192.168.0.0/16 -p udp ! --dport 53 -j RETURN;'
        'iptables -t mangle -A V2RAY_MARK -j RETURN -m mark --mark 0xff;'
        'iptables -t mangle -A V2RAY_MARK -p udp -j MARK --set-mark 1;'
        'iptables -t mangle -A V2RAY_MARK -p tcp -j MARK --set-mark 1;'
        # Apply rules
        'iptables -t mangle -A PREROUTING -j V2RAY;'
        'iptables -t mangle -A OUTPUT -j V2RAY_MARK;',
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr3 = await proc3.communicate()
    if proc3.returncode:
        print(stderr3.decode(), end='', file=sys.stderr)
        return_code = ReturnCode.SUBCOMMAND
    else:
        return_code = ReturnCode.OK
    return return_code


async def status() -> int:
    if not is_root():
        print('This script must be run as root.', file=sys.stderr)
        return ReturnCode.PERMISSION
    proc = await asyncio.create_subprocess_exec(
        'iptables', '-t', 'mangle', '-nL',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode:
        print(stderr.decode(), end='', file=sys.stderr)
        return ReturnCode.SUBCOMMAND
    match = re.search(r'TPROXY\s+redirect\s+0\.0\.0\.0:([0-9]+)', stdout.decode())
    if match:
        print(f'active@{match.group(1)}')
    else:
        print('inactive')
    return ReturnCode.OK


def default_lockfile(flavor_id: str = "") -> str:
    basename = os.path.splitext(os.path.abspath(sys.argv[0]))[0].replace(
        "/", "-").replace(":", "").replace("\\", "-") + '-%s' % flavor_id + '.lock'
    return os.path.normpath(tempfile.gettempdir() + '/' + basename)


async def run_exclusively(lock_file: Optional[str], no_wait: bool, func: Callable[[], Awaitable[T]]) -> T:
    resolved_lock_file = lock_file or default_lockfile()
    if no_wait:
        with open(resolved_lock_file, 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return await func()
    else:
        async with lock(resolved_lock_file):
            return await func()


async def nop() -> int:
    return ReturnCode.OK


async def main(argv: List[str]) -> None:
    # noinspection PyBroadException
    try:
        parser = argparse.ArgumentParser(description='Transparent proxy via iptables.')
        parser.add_argument('--lock-file', help='lock file ensuring one instance')
        parser.add_argument('--no-wait', action='store_true', help='don\'t wait for other instances\' exiting')
        subparsers = parser.add_subparsers(dest='action', help='sub-commands')
        parser_stop = subparsers.add_parser('stop', help='remove transparent proxy rules from iptables')
        parser_stop.add_argument('--if-started', action='store_true',
                                 help='report error if proxy hasn\'t been started')
        parser_start = subparsers.add_parser('start', help='setup transparent proxy rules in iptables')
        parser_start.add_argument('--port', type=int, required=True,
                                  help='port to which traffic is redirected')
        subparsers.add_parser('status', help='check whether transparent proxy has been setup')
        subparsers.add_parser('nop', help='do nothing but acquire a lock')
        args = parser.parse_args(argv)
        if args.action == 'start':
            sys.exit(await run_exclusively(args.lock_file, args.no_wait, lambda: start(args.port)))
        elif args.action == 'stop':
            sys.exit(await run_exclusively(args.lock_file, args.no_wait, lambda: stop(args.if_started)))
        elif args.action == 'status':
            sys.exit(await run_exclusively(args.lock_file, args.no_wait, status))
        elif args.action == 'nop':
            sys.exit(await run_exclusively(args.lock_file, args.no_wait, nop))
    except SystemExit:
        raise
    except BlockingIOError:
        print('Would been blocked.', file=sys.stderr)
        sys.exit(ReturnCode.BLOCKING)
    except Exception:
        traceback.print_exc()
        sys.exit(ReturnCode.UNKNOWN)


if __name__ == '__main__':
    asyncio.run(main(sys.argv[1:]))
