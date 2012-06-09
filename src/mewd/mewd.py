import socket, sys
from daemon import Daemon

port = 8888
buff = 1024

class LibMewDaemon(Daemon):
    def run(self):
        global port
        server_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM )
        server_sock.bind( (socket.gethostname(), port) )
        server_sock.listen(5)
        
        # start the recv loop
        while 1:
            process_requests(server_sock)
            

def process_requests(server_sock):
    # get client
    (s, address) = server_sock.accept()
    try:
        while 1:
            retmsg = s.recv(buff)
            if retmsg == 'sync  \r\n\r\n':
                print 'syncing'
            else:
                print 'unkown command'
            s.send('got it')
            print "retmsg = %s" % retmsg
    except:
        print 'done'

        
def main():
    daemon = LibMewDaemon('/tmp/libmew.pid')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print 'Unknown Command!'
            sys.exit(2)
        sys.exit(0)
    else:
        print 'usage :%s start|stop|restart' % sys.argv[0]
        sys.exit(2)

if __name__ == '__main__':
    main()
