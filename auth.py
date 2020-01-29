#!/usr/bin/env python
# coding:utf-8

"""
这是一个用户认证插件，可以创建包含如下文本 auth.csv 来管理用户

username,password,vip
foobar,123456,1
test,test123,0

也可以请进一步修改此脚本添加远程数据库认证，用户限速等功能。
"""

import base64
import csv
import io
import json
import sys


def do_authorize(username, password, remote_addr):
    """authorize basic function"""
    response = {
        'username': username, # 用户名
        'ttl': 600,           # 认证缓存，认证结果在内存中缓存多久。
        'vip': 0,             # VIP 用户，不受站点黑名单控制。
        'speedlimit': 0,      # 速率限制，单位为 bytes/s, 0 表示不作限制。
        'error': '',          # 出错信息，不为空表示认证失败。
    }
    try:
        filename = 'auth.csv'
        data = open(filename, 'rb').read().decode()+'\n'
        info = {}
        for row in csv.DictReader(io.StringIO(data)):
            info[row['username']] = row
        if username not in info:
            response['error'] = 'wrong username'
        elif password != info[username]['password']:
            response['error'] = 'wrong password'
        else:
            response['vip'] = int(info[username].get('vip', 0))
    except Exception as error:
        response['error'] = str(error)
    return response


def authorize(auth_type, *auth_args):
    """authorize function"""
    if auth_type not in ('basic', 'socks'):
        return {'error': 'unsupported auth type: ' + auth_type}
    if auth_type == 'basic':
        username, password = base64.b64decode(auth_args[0]).decode().split(':')
        remote_addr = auth_args[1]
    elif auth_type in ('socks', 'dtls'):
        username, password, remote_addr = auth_args
    else:
        pass
    return do_authorize(username, password, remote_addr)


if __name__ == "__main__":
    auth_type, auth_args = sys.argv[1], sys.argv[2:]
    sys.stdout.write(json.dumps(authorize(auth_type.lower(), *auth_args)))
