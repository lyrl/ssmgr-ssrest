import socket

def test_port(PORT):
    '''
    https://docs.python.org/2/library/socket.html#example
    '''
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('', PORT)) ## Try to open port
        except socket.error as e:
            if e.errno is 98: ## Errorno 98 means address already bound
                return True
            else:
                print e
        s.close()
        return False


if __name__ == '__main__':
    port = 1080
    b = test_port(port)
    print("Is port {0} open {1}".format(port,b))