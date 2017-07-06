import gevent
from gevent.queue import Queue
import shadowsocks.util
from shadowsocks.util import HttpUtilException
import logging


tasks = Queue()
failedTasks = []

def worker(n):
    task = tasks.get()
    logging.info('Worker %s got task %s' % (n, task))

    try:
        data = shadowsocks.util.send_post(task['url'], {'data': task['data']})
        print data
    except HttpUtilException as e:
        logging.warn('create a new task!!! %s' % e.message)

        if task['data']['traffics']:
            failedTasks.append(task)

    gevent.sleep(0)

    logging.info('Worker %s Quitting!' % n)


def add_task(task):
    tasks.put_nowait(task)


def loop():
    while True:
        while not tasks.empty():
            gevent.joinall([
                gevent.spawn(worker, 'poster 1'),
            ])

        logging.info('Sleep 10 seconds!')
        gevent.sleep(10)
        for task in failedTasks:
            tasks.put_nowait(task)






