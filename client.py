import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import random
from utils import ProtoAlgorithm, AVAILABLE_CIPHERS, AVAILABLE_HASHES, AVAILABLE_MODES, DH_parameters, encryption, unpacking, length_by_cipher, key_derivation
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_KEY = 4
STATE_ALGORITHM_NEGOTIATION = 5
STATE_DH_EXCHANGE_KEYS = 6


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """
    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks

        self.current_algorithm = None
        self.DH_private_key = None
        self.DH_public_key = None
        self.shared_key = None

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')

        #ALGORITHMS NEGOTIATION
        self.send_algorithm()

        #message = {'type': 'OPEN', 'file_name': self.file_name}
        #self._send(message)

        #self.state = STATE_OPEN

    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug('Received: {}'.format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[
                idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer
               ) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer to large')
            self.buffer = ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        #logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_ALGORITHM_NEGOTIATION:
                logger.info("Algorithm acepted from server")
                self.process_DH()

            elif self.state == STATE_OPEN:
                self.send_file(self.file_name)

            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == 'DH_PUBLIC_KEY':
            if self.state == STATE_DH_EXCHANGE_KEYS:
                self.get_server_DH_key(message)
                return
            else:
                logger.warning("Invalid state")

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(
                message.get('data', None)))
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def get_server_DH_key(self, message):

        key = message.get('key', None)
        if key is not None:
            logger.debug(f"Server DH_public_key : {key}")

            self.shared_key = key_derivation(
                "SHA512", length_by_cipher[self.current_algorithm.cipher],
                self.DH_private_key.exchange(
                    load_pem_public_key(key.encode(), default_backend())))

            logger.info(f"Shared Key with DH : {self.shared_key}")

        self.send_fileName(self.file_name)

        self.state = STATE_OPEN  #Ready To send

    def process_DH(self):

        logger.info("Initializating DH")

        parameters = DH_parameters()

        self.DH_private_key = parameters.generate_private_key()
        self.DH_public_key = self.DH_private_key.public_key()

        message = {
            'type': 'PARAMETERS_AND_DH_PUBLIC_KEY',
            'data': {
                'p':
                parameters.parameter_numbers().p,
                'g':
                parameters.parameter_numbers().g,
                'key':
                self.DH_public_key.public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
            }
        }

        self._send(message)

        self.state = STATE_DH_EXCHANGE_KEYS

    def send_fileName(self, fileName):
        message = {'type': 'OPEN', 'file_name': self.file_name}
        self._send(message)
        self.state = STATE_OPEN

    def send_algorithm(self):
        """
        Client choose a algorithm
        :param exc:
        :return:
        """
        if self.state != STATE_CONNECT:
            logger.debug("Invalid state")
            self.transport.close()
            self.loop.stop()

        self.state = STATE_ALGORITHM_NEGOTIATION

        self.current_algorithm = ProtoAlgorithm(
            random.choice(AVAILABLE_CIPHERS), random.choice(AVAILABLE_MODES),
            random.choice(AVAILABLE_HASHES))

        message = {
            'type': "ALGORITHM_NEGOTIATION",
            'data': self.current_algorithm.packing()
        }

        logger.debug("Sending to server Algorithm Choice")
        logger.info(f"Choosen algorithm: {message['data']}")

        self._send(message)

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)
                
                algorithm, chiper, mode, synthesis_algorithm = unpacking(
                    self.current_algorithm.packing())

                encrypted_data, padding_length, iv = encryption(
                    data, self.shared_key, chiper, mode)

                message['data'] = base64.b64encode(encrypted_data).decode()
                message['padding_length'] = padding_length
                
                message['iv'] = base64.b64encode(iv).decode()
                
                self._send(message)
                print(encrypted_data)
                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + '\r\n').encode()
        self.transport.write(message_b)


def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v',
                        action='count',
                        dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s',
                        type=str,
                        nargs=1,
                        dest='server',
                        default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p',
                        type=int,
                        nargs=1,
                        dest='port',
                        default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(
        file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()


if __name__ == '__main__':
    main()