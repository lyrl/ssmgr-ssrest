import gevent
from gevent.queue import Queue
import shadowsocks.util
from shadowsocks.util import HttpUtilException
import logging


tasks = Queue()
failedTasks = []


def add_task(task):
    tasks.put_nowait(task)


def loop():
    logging.info('Traffic Data Push Service Started!')

    while True:
        while not tasks.empty():
            task = tasks.get()
            work(task)

        logging.info('Sleep 10 seconds for next push !')
# add task
# loop
# task_failed_handle


def work(task):
    task = tasks.get()
    logging.info('Prepare push traffic data to %s' % (task['url']))

    try:
        data = shadowsocks.util.send_post(task['url'], {'data': task['data']})

        logging.info('Traffice data push sucessed , server return msg %s' % (data))
    except HttpUtilException as e:
        logging.warn('Traffice data push failed, reason:  [%s] ' % e.message)

        if task['data']['traffics']:
            tasks.put_nowait(task)
            logging.info('Task refill to task queue wating next push !')
        else:
            logging.info('Task traffic data is null will not refill to task queue !')

