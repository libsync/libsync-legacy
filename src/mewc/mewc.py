#!/usr/bin/env python2
import argparse as ap
#import connector
import cmd, shlex, getpass, socket, sys, ConfigParser, os

"""
***************************************************************************************
                                Help Strings
***************************************************************************************
"""

interactive_string = """
Specify whether to run as interactive of not:
-i <flag>
interactive off: <flag> = 0
interactive on: <flag> = 1
"""
init_string = """
Initializes a mew directory for syncing. Will make a config.
"""

"""
***************************************************************************************
                                 Arg Parser
***************************************************************************************
"""

parser = ap.ArgumentParser(description='Interface to Libmew.')
parser.add_argument('-t','--type',dest='type', default='webdav',
        help='Pick the type of connection to use: webdav, ftp, ...')
parser.add_argument('-l','--toolong',dest='toolong', type=int, default=5,
        help='No. of seconds before program is determined non-responsive.')
parser.add_argument('-i','--interactive',dest='interactive', type=int, default=1,
        help=interactive_string)
parser.add_argument('--init',dest='init', help=init_string)
args = parser.parse_args()

"""
***************************************************************************************
                                 Main and Co
***************************************************************************************
"""


"""
***************************************************************************************
                               CLI Implementation
***************************************************************************************
"""

interactive_greeting = """
--------------------------------------------------
Welcome to the Libmewc Interactive Console: (LIC)
--------------------------------------------------


--------------------------------------------------
Instructions:
--------------------------------------------------
  get <filename1> <filename2> ...
  put <filename1> <filename2> ...
  sync

"""

prompt_string = '>> '

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
C = None
default_url = "https://www.box.net/dav/"
default_user = "random@courseguide.info"
default_pass = "Uv6$3UnNF4r3znveWx*YDr87CRxfnzp#"


def parse_config():
    config = ConfigParser.RawConfigParser()
    try:
        config.read('config.ini')
    except:
        print "Error: no config.ini file present, loading default."
        url = 'https://www.box.net/dav/'
        name = 'anon'
        email = 'anon@gmail.com'
        active = 'True'
        port = 8888
        host = 'localhost'

    url = config.get('User', 'Url')
    name = config.get('User', 'Name')
    email = config.get('User', 'Email')
    active = config.get('User', 'Active')

    port = config.getint('Protocol', 'Port')
    host = config.get('Protocol', 'Host')
    return locals()


def send_data(cmds, data):
    print "Sending data to dameon"
    out = cmds + " " + data + " \r\n\r\n"
    s.send(out)
    size = 1024
    retmsg = s.recv(size)

class MewCmd(cmd.Cmd):
    """ Interface to libmew """

    intro = interactive_greeting
    prompt = prompt_string

    def run_get_put(self, line, cmds):
        args = shlex.split(line)
        #print args
        if len(args) == 0:
            print "No files specified."
            return

        for path in args:
            print cmds.capitalize() + ": " + path
            send_data(cmds, path)
        

    def do_get(self, line):
        """ 
        Gets file from server 
        get <filename1> <filename2> ...
        """
        self.run_get_put(line, "get")
        #C.get_file(file_name = path, obj= 'outfile')
        print "Get complete."

    def do_put(self, line):
        """ 
        Puts file to server 
        put <filename1> <filename2> ...
        """
        self.run_get_put(line, "put")
        #C.put_file(file_name = line, obj = 'outfile')
        print "Put complete."
        
    def do_sync(self, file):
        send_data("sync", "")
        """
        Syncs all of the files (pulls and pushes)
        sync
        """
        print 'Sync complete.'

#change to do_connect if this is fixed and ready to hook back up
    def connect(self, line):
        """ 
        Connects to a server 
        connect <url> <username>
        or
        connect <url>
        or
        connect
        then...
        Password: <password>
        """
        args = shlex.split(line)
        if len(args) > 2:
            print 'Incorrect syntax, use: connect <url> <username>'
            return
        nurl = None
        nuser = None
        if len(args) > 0:
            nurl = args[0]
        if len(args) > 1:
            nuser = args[1]
        
        passd = default_user
        if nuser != None:
            passd = getpass.getpass() #need to prompt user for pass

        if nuser == None and nurl == None:
            print 'no url or user'
            #C.connect(user=default_user, url = default_url, password = passd)
        if nuser == None and nurl != None:
            print 'no user'
            #C.connect(user=default_user, url = nurl, password = passd)
        if nuser != None and nurl != None:
            print 'user and url specified'
            #C.connect(user=nuser, url = nurl, password = passd)
        print 'Connected'

    def default(self, line):
        return ''
        
    def do_EOF(self, line):
        return True

def interactive_mode():
    global C
    global s
    #connector.start('webdav')
    #C = connector.Connector('webdav')
    config = parse_config()
    #try and connect to port
    try: 
        s.connect((config['host'],config['port'])) 
    except socket.error, (value,message):
        if s: 
            s.close() 
        print "Could not open socket: " + message 
        sys.exit(1)

    cli = MewCmd()
    cli.cmdloop()
    s.close()
    

def main():
    if args.interactive == 1:
        interactive_mode()
    print args

if __name__ == '__main__':
    main()
