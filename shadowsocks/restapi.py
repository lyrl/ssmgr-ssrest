#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement
import json
from flask import Flask, Response, request
import threading
from shadowsocks.manager import Manager
from shadowsocks.cryptor import Cryptor

manager = Manager(
    config={"server": "0.0.0.0", "server_port": 12223, "local_port": 1081, "password": "1z2x3c4v", "timeout": 600,
            "method": "aes-256-cfb", "fast_open": False, "crypto_path": False})

threading._start_new_thread(manager.run, ())

app = Flask(__name__)


@app.route('/api/ping')
def ping():
    return 'pong'

@app.route('/api/state')
def stat():
    return Response(json.dumps({'alive': threading.activeCount()}), mimetype='application/json')


@app.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def users():
    if request.method == 'GET':
        return Response(json.dumps({'users': manager.get_all_ports()}), mimetype='application/json')
    elif request.method == 'POST':
        data = json.loads(request.data)['user']

        if data.has_key('port'):
            data['server_port'] = data['port']
        else:
            data['server_port'] = manager.gen_port_num()

        method_info = Cryptor.get_method_info(data['method'].lower())

        data['password'] = data['password'].encode('utf-8')

        print(method_info)

        if not method_info:
            return Response(json.dumps({'errors': {'message': u'不支持的加密算法 %s！' % data['method']}}), mimetype='application/json')

        if manager.is_has_port(data['server_port']):
            return Response(json.dumps({'errors': {'message': '端口已经存在！'}}), mimetype='application/json')

        if manager.add_port(data):
            return Response(json.dumps({'user': data}), mimetype='application/json')


@app.route('/api/users/<int:port>', methods=['DELETE'])
def delete_port(port):
    if request.method == 'DELETE':
        if not manager.is_has_port(port):
            return Response(json.dumps({'errors': {'message': '端口不存在！'}}), mimetype='application/json')

        if manager.remove_port({'server_port': port}):
            return Response(json.dumps({'server_port': port}), mimetype='application/json')


if __name__ == "__main__":
    app.run(port=9999)