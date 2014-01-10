import paramiko
import os
import sys
import base64
import socket
import time
import json
import traceback
import subprocess
import threading
import itertools
import uuid
from collections import defaultdict, namedtuple
from docopt import docopt
from ptools.current import *

UUID_NAME='PYRAS_UUID'
RUNNING, STARTING, STOPPING, STOPPED, BAD = 'RUNNING STARTING STOPPING STOPPED BAD'.split()

Command = namedtuple('Command', 'uuid command group pids'.split())
CommandDetails = namedtuple("CommandDetails", "cmd group pids".split())


class CidUuidStore(object):
    def __init__(self):
        self.cid_iter = itertools.count(1)
        self.uuid_to_cid = defaultdict(lambda : next(self.cid_iter))
        self.cid_to_uuid = {}

    def to_cid(self, uuid):
        cid = self.uuid_to_cid[uuid]
        self.cid_to_uuid[cid] = uuid
        return cid

    def to_uuid(self, cid):
        return self.cid_to_uuid[cid]

class Controller(object):
    def __init__(self):
        self.store = CidUuidStore()
        self.lock = threading.Lock()
        self.commands = []

    def __enter__(self):
        self.acquire_lock()
        return self

    def __exit__(self, type, value, traceback):
        self.lock.release()
        return False

    def acquire_lock(self):
        self.lock.acquire()

    def release_lock(self):
        self.lock.release()

    def register(self, command, group):
        c = Command(str(uuid.uuid4()), command, group, tuple())
        self.commands.append(c)
        return self.store.to_cid(c.uuid), c

    def unregister_all(self):
        for command in self.get_actual():
            self.stop(command)
        self.commands = []

    def unregister(self, cid):
        command = self.get_by_cid(cid)
        self.stop(command)
        self.commands = [i for i in self.commands if i.uuid != command.uuid]

    def run(self, command):
        cid, c = self.register(command, 'run')
        self.start(c)
        return cid

    def start_cid(self, cid):
        self.start(self.get_by_cid(cid))

    def start(self, command):
        if len(command.pids) == 0:
            env = dict(os.environ)
            env[UUID_NAME] = command.uuid
            subprocess.Popen(command.command, env=env, shell=True)

    def stop(self, command):
        while len(command.pids) > 0:
            for pid in command.pids:
               kill_pid(pid)
            command = self.get_updated(command)

    def stop_cid(self, cid):
       self.stop(self.get_by_cid(cid))

    def get_by_cid(self, cid):
        uuid = self.store.to_uuid(cid)
        for command in self.get_actual():
            if command.uuid == uuid:
                return command
        raise KeyError(str(cid))

    def get_by_group(self, group):
        for command in self.get_actual():
            if command.group == group:
                yield command

    def start_group(self, group):
        for command in self.get_by_group(group):
            self.start(command)

    def stop_group(self, group):
        for command in self.get_by_group(group):
            self.stop(command)

    def get_updated(self, target):
        for command in self.get_actual():
            if command.uuid == target.uuid:
                return command

    def get_actual(self):
        actual_commands = [Command(i.uuid, i.command, i.group, []) for i in self.commands]
        uuid_map = dict((i.uuid, i) for i in actual_commands)
        for pid in list_pids():
            try:
                cmd, env = get_pid_info(pid)
            except Exception:
                continue
            if UUID_NAME in env:
                uuid = env[UUID_NAME]
                if uuid in uuid_map:
                    uuid_map[uuid].pids.append(pid)
                else:
                    c = Command(uuid, cmd, 'UNKNOWN', [pid])
                    uuid_map[uuid] = c
                    actual_commands.append(c)
        return actual_commands

    def get_info(self):
        result = []
        for command in self.get_actual():
            result.append([self.store.to_cid(command.uuid), command.command, command.group, command.pids])
        return result

NODE_SERVER_PORT = 54131

class RemoteCommandServer(paramiko.ServerInterface):
    HOST_KEY_FILENAME  = 'host_rsa.key'
    AUTHORIZED_KEYS_FILENAME = 'authorized_keys'

    def __init__(self):
        self.host_key = self.get_host_key_create_if_missing()
        self.authorized_keys = frozenset(self.load_authorized_keys())
        self.ctrl = Controller()

    def get_host_key_create_if_missing(self):
        if os.path.exists(RemoteCommandServer.HOST_KEY_FILENAME):
            key = paramiko.RSAKey(filename=RemoteCommandServer.HOST_KEY_FILENAME)
        else:
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(RemoteCommandServer.HOST_KEY_FILENAME)
        return key

    def load_authorized_keys(self):
        pubkeys = []
        for line in open(RemoteCommandServer.AUTHORIZED_KEYS_FILENAME):
            if not line.strip() or line.startswith('#'):
                continue
            kind, b64pubkey = line.split()[:2]
            if kind == 'ssh-dss':
                pubkeys.append(paramiko.DSSKey(data=base64.decodestring(b64pubkey)))
            elif kind == 'ssh-rsa':
                pubkeys.append(paramiko.RSAKey(data=base64.decodestring(b64pubkey)))
            else:
                raise ValueError('unknown key type - ' + kind)
        if len(pubkeys) == 0:
            raise ValueError("didn't find any public keys in " + RemoteCommandServer.AUTHORIZED_KEYS_FILENAME)
        return pubkeys

    def check_channel_request(self, kind, chanid):
        if kind == 'exec' or kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        try:
            message = list(json.loads(command))
            threading.Thread(target=self.handle, args=[channel] + message).start()
            return True
        except:
            return False

    def handle(self, channel, *args):
        try:
            command = args[0]
            if command == 'read':
                # Special path for 'read' as it just returns raw bytes not json
                filename, offset, numbytes = args[1:]
                f = open(filename, 'rb')
                if offset < 0:
                    f.seek(offset, 2)
                elif offset > 0:
                    f.seek(offset)
                channel.sendall(f.read(numbytes))
                f.close()
            else:
                # Handle using handle_command methods
                with self.ctrl:
                    resp = getattr(self, 'handle_' + command)(*args[1:])
                    channel.sendall(json.dumps(resp))
            channel.send_exit_status(0)
        except:
            channel.sendall_stderr(traceback.format_exc())
            channel.send_exit_status(1)

    def handle_info(self):
        return self.ctrl.get_info()

    def handle_register(self, command, group):
        return self.ctrl.register(command, group)[0]

    def handle_unregister(self, cid):
        return self.ctrl.unregister(cid)

    def handle_unregister_all(self):
        return self.ctrl.unregister_all()

    def handle_start_group(self, group):
        self.ctrl.start_group(group)

    def handle_stop_group(self, group):
        self.ctrl.stop_group(group)

    def handle_run(self, command):
        return self.ctrl.run(command)

    def handle_start(self, cid):
        self.ctrl.start_cid(cid)

    def handle_stop(self, cid):
        self.ctrl.stop_cid(cid)

    def check_auth_publickey(self, username, key):
        if key in self.authorized_keys:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'publickey'

    def run(self, interface='0.0.0.0', port=NODE_SERVER_PORT):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print "Listening on %s:%d" % (interface, port)
        sock.bind((interface, port))
        sock.listen(10)
        while True:
            try:
                client, addr = sock.accept()
                print "Connection from %s:%d" % addr
                transport = paramiko.Transport(client)
                try:
                    transport.add_server_key(self.host_key)
                    print "Starting Server"
                    transport.start_server(server=self)
                    print "Started Server"
                except KeyboardInterrupt:
                    transport.close()
                    break
            except KeyboardInterrupt:
                break
        print "Closed"

class RemoteCommandError(Exception):
    pass

class RemoteCommandClient(object):
    _DEFAULT_BUFSIZE = 8192

    def __init__(self, hostname, key_filename=('private_rc.key',), look_for_keys=False):
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(hostname=hostname, port=NODE_SERVER_PORT, key_filename=list(key_filename), look_for_keys=look_for_keys)

    def register(self, command, group='default'):
        """Register a new process in a group

        """
        return self._command('register', command, group)

    def start_group(self, group='default'):
        """Bring everyone in the group to a running state

        """
        return self._command('start_group', group)

    def stop_group(self, group='default'):
        """Stop the group

        """
        return self._command('stop_group', group)

    def stop(self, cid):
        """Stop the cid

        """
        return self._command('stop', cid)

    def unregister(self, cid):
        """For cids not in the 'default' group stop and move to 'default'
        for any other stop and remove registration.

        """
        return self._command('unregister', cid)

    def unregister_all(self):
        """Unregister all commands

        """
        return self._command('unregister_all')

    def run(self, command):
        """Immediatly run a command.

        The command will be created in the 'run' group and immediatly started.
        """
        return self._command('run', command)

    def close(self):
        """Close the connection, after calling this the client is unusable.

        """
        self._client.close()

    def is_active(self):
        """Is the client still connected.

        """
        return (self._client.get_transport() is not None
                and self._client.get_transport().is_active() == True)

    def start(self, cid):
        """Bring the cid to running.

        """
        return self._command('start', cid)

    def info(self):
        info = self._command('info')
        return {cid: CommandDetails(cmd, group, pids)
                for cid, cmd, group, pids in info}

    def read_gen(self, filename, offset, numbytes):
        for data in self._exec_command_yielding_stdout_raw_bytes(
            'read',
            filename,
            offset,
            numbytes):
            yield data

    def read(self, filename, offset, numbytes):
        return ''.join(self.read_gen(filename, offset, numbytes))

    def read_end(self, filename, numbytes):
        return self.read(filename, -numbytes, numbytes)

    def get_remote_file_to_disk(self, filename, out=None, offset=0):
        """Reads the remote file on a pyras client and dumps it to disk

        out should be an open filelike object.
        Returns: bytes read
        """
        if out is None:
            out = open(filename,'wb')
        chunk_size = 8192
        while True:
            data = self.read(filename, offset, chunk_size)
            if data == '':
                return offset
            else:
                out.write(data)
                offset += len(data)

    def wait_for(self, cid):
        """ Wait for the command with the given cid to terminate. """
        while self.info()[cid].pids:
            time.sleep(0.1)

    def wait_for_group(self, group):
        """ Wait for the commands in the given group to terminate. """
        while any([command_details.pids for command_details
                   in self.info().values() if command_details.group == group]):
            time.sleep(0.1)

    def _command(self, *args):
        reply = ''.join(self._exec_command_yielding_stdout_raw_bytes(*args))
        return json.loads(reply)

    def _exec_command_yielding_stdout_raw_bytes(self, *args):
        channel = self._client.get_transport().open_channel('exec')
        channel.exec_command(json.dumps(args))
        stderr_buffer = []
        bufsize = RemoteCommandClient._DEFAULT_BUFSIZE
        while not channel.exit_status_ready() or channel.recv_stderr_ready() or channel.recv_ready():
            if channel.recv_stderr_ready():
                data = channel.recv_stderr(bufsize)
                stderr_buffer.append(data)
            if channel.recv_ready():
                yield channel.recv(bufsize)
        exit_status = channel.recv_exit_status()
        if exit_status != 0 or len(stderr_buffer) > 0:
            raise RemoteCommandError('Exit Status ' + str(exit_status) + '\n' + ''.join(stderr_buffer))
        channel.close()

def genauth_main():
    """Usage: pyras-genauth

    """
    opts = docopt(genauth_main.__doc__)
    PRIVATE_KEY = "private_rc.key"
    sys.stdout.write("Generating Remote Control access key into %s and %s ." % (PRIVATE_KEY, RemoteCommandServer.AUTHORIZED_KEYS_FILENAME))
    sys.stdout.flush()
    def progress(*args):
        sys.stdout.write(' .')
        sys.stdout.flush()
    key = paramiko.RSAKey.generate(2048, progress)
    key.write_private_key_file(PRIVATE_KEY)
    open(RemoteCommandServer.AUTHORIZED_KEYS_FILENAME,'w').write("ssh-rsa %s\n" % (key.get_base64(),))
    print " DONE"


def serve_main():
    """Usage: pyras-serve [-p PORT] [-i IP]

    Options:
      -p PORT --port=PORT       port to listen on [default: 54131]
      -i IP --interface-ip=IP   interface to listen on [default: 0.0.0.0]


    """
    opts = docopt(serve_main.__doc__)
    RemoteCommandServer().run(opts['--interface-ip'], int(opts['--port']))
