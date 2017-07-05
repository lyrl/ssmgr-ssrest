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

import sys

import gevent
from flask import Flask, Response, request
from flask_cors import CORS
import threading
from shadowsocks.manager import Manager
from shadowsocks.cryptor import Cryptor
from flask import abort
import logging
from shadowsocks import cryptor
from shadowsocks.queue import add_task
from shadowsocks.queue import loop

logging.basicConfig(level=20,
                        format='%(asctime)s [%(module)s] %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

manager = Manager()
app = Flask(__name__)
config = None
CORS(app)


@app.route('/api/ping')
def ping():
    return 'pong'


@app.route('/api/state')
def stat():
    _check_security_key()

    return Response(json.dumps({'alive': threading.activeCount()}), mimetype='application/json')


@app.route('/api/users', methods=['GET', 'POST', 'DELETE'])
def users():
    _check_security_key()

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
        data['method'] = data['method'].encode('utf-8')

        if not method_info:
            logging.error(u"不支持的加密算法%s!" % data['method'])
            return Response(json.dumps({'errors': {'message': u'不支持的加密算法 %s！' % data['method']}}), mimetype='application/json')

        if manager.is_has_port(data['server_port']):
            logging.error(u"端口已经存在%s!")
            return Response(json.dumps({'errors': {'message': '端口已经存在！'}}), mimetype='application/json')

        if manager.add_port(data):
            logging.error(u"端口%s添加成功!" % data['server_port'])
            return Response(json.dumps({'user': data}), mimetype='application/json')


@app.route('/api/users/<string:username>', methods=['DELETE'])
def delete_user(username):
    _check_security_key()

    if request.method == 'DELETE':
        port = manager.get_port_by_username(username)

        if not port:
            return Response(json.dumps({'errors': {'message': '用户不存在！'}}), mimetype='application/json')

        if manager.remove_port({'server_port': port}):
            return Response(json.dumps({'server_port': port}), mimetype='application/json')


@app.route('/api/ports/<int:port>', methods=['DELETE'])
def delete_port(port):
    _check_security_key()

    if request.method == 'DELETE':
        if not manager.is_has_port(port):
            return Response(json.dumps({'errors': {'message': '端口不存在！'}}), mimetype='application/json')

        if manager.remove_port({'server_port': port}):
            return Response(json.dumps({'server_port': port}), mimetype='application/json')


def _check_security_key():
    security_key = request.headers.get('Authorization')

    if security_key != config['security_key']:
        abort(403)


if __name__ == "__main__":
    try:
        file = open('config.json', 'r')
    except IOError as e:
        logging.error(u'在当前目录下找不到配置文件：config.json!')
        sys.exit(0)

    config = json.loads(file.read())
    manager.set_config(config)

    manager.sync_users()

    # new thread to run loop
    threading._start_new_thread(manager.run, ())
    threading._start_new_thread(loop, ())

    app.run(port=config['rest_api_port'], host='0.0.0.0')