#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Created on 2016-07-26 11:04:34

import socket
import urllib2
import json
import requests
import logging

def is_port_using(port):
    '''
    https://docs.python.org/2/library/socket.html#example
    '''
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('', port)) ## Try to open port
        except socket.error as e:
            if e.errno is 98: ## Errorno 98 means address already bound
                return True
            else:
                print e
        s.close()
        return False


def send_post(url, data):
    """
    HTTP POST Util
    Args:
        url (str): resource url eg: http://xxxx.com/api/users
        data (dict): post body
    Returns:
        str: response content
    """
    logging.debug("send data %s to url %s !" % (json.dumps(data), url))

    headers = {'content-type': 'application/json'}
    try:
        response = requests.post(url, data=json.dumps(data), headers=headers)
    except requests.exceptions.ConnectionError as e:
        logging.error(e.message)
        raise HttpUtilException("Failed to establish a new connection!")

    logging.debug("return code: %s content: %s" % (response.status_code, response.content))
    return response.content


class UtilException(Exception):
    def __init__(self, msg):
        self.message = msg

    def __str__(self):
        return self.message


class HttpUtilException(UtilException):
    def __init__(self, msg):
        self.message = msg

    def __str__(self):
        return self.message


if __name__ == '__main__':
    # port = 1080
    # b = is_port_using(port)
    # print("Is port {0} open {1}".format(port,b))

    logging.basicConfig(level=5,
                        format='%(asctime)s [%(module)-16s] %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    send_post('http://baidu21231.com', {"test": "test"})