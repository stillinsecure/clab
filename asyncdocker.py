from aiohttp import ClientSession, UnixConnector

STATUS_CONTAINERS_NO_ERROR = 200
STATUS_NO_ERROR = 204
STATUS_CONTAINER_ALREADY_STARTED = 304
STATUS_CONTAINER_ALREADY_STOPPED = 304
STATUS_NO_SUCH_CONTAINER = 404
STATUS_SERVER_ERROR = 500

API_CONTAINER_URL = 'http://{}/containers/{}/{}'
API_CONTAINERS_URL = 'http://{}/containers/{}'

API_VERSION = 'v1.24'
API_CMD_START_CONTAINER = 'start'
API_CMD_STOP_CONTAINER = 'stop'
API_CMD_LIST_CONTAINERS = 'json?all=1'

UNIX_SOCKET = '/var/run/docker.sock'


class AsyncDocker:

    def __init__(self):
        self.dockerd = ClientSession(connector=UnixConnector(UNIX_SOCKET))

    def close(self):
        self.dockerd.close()

    async def list_containers(self):
        url = API_CONTAINERS_URL.format(API_VERSION, API_CMD_LIST_CONTAINERS)

        async with self.dockerd.get(url) as response:
            if response.status == STATUS_CONTAINERS_NO_ERROR:
                return response.content

    async def start_container(self, name):
        url = API_CONTAINER_URL.format(API_VERSION, name, API_CMD_START_CONTAINER)

        async with self.dockerd.post(url) as response:
            if response.status == STATUS_NO_ERROR or response.status == STATUS_CONTAINER_ALREADY_STARTED:
                return True
            return False

    async def stop_container(self, name):
        url = API_CONTAINER_URL.format(API_VERSION, name, API_CMD_STOP_CONTAINER)

        async with self.dockerd.post(url) as response:
            if response.status == STATUS_NO_ERROR or response.status == STATUS_CONTAINER_ALREADY_STOPPED:
                return True