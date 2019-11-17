import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import random
from utils import ProtoAlgorithm, DH_parameters, encryption, unpacking, length_by_cipher, key_derivation, MAC
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
    def __init__(self, file_name, loop, random,cipher,mode,synthesis):
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
        self.AVAILABLE_CIPHERS = [
            "ChaCha20", "AES", "TripleDES", "Blowfish", "ARC4"
        ]
        self.AVAILABLE_HASHES = ["SHA256", "SHA512", "MD5"]
        self.AVAILABLE_MODES = ["CBC", "GCM", "ECB"]
        self.random = random
        self.cipher = cipher
        self.mode = mode
        self.synthesis = synthesis

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
                message.get('message', None)))
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def get_server_DH_key(self, message):

        key = message.get('key', None)
        if key is not None:
            logger.debug(f"Server DH_public_key : {key}")

            self.shared_key = key_derivation(
                self.current_algorithm.synthesis_algorithm,
                length_by_cipher[self.current_algorithm.cipher],
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

        if self.random:
            self.current_algorithm = ProtoAlgorithm(
                random.SystemRandom().choice(self.AVAILABLE_CIPHERS),
                random.SystemRandom().choice(self.AVAILABLE_MODES),
                random.SystemRandom().choice(self.AVAILABLE_HASHES))
        else:
            self.current_algorithm = ProtoAlgorithm(self.cipher, self.mode,
                                                    self.synthesis)

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

                chiper, mode = self.current_algorithm.cipher, self.current_algorithm.mode

                encrypted_data, padding_length, iv, tag = encryption(
                    data, self.shared_key, chiper, mode)

                message['padding_length'] = padding_length

                message['iv'] = base64.b64encode(iv).decode()

                if tag is not None:
                    message['tag'] = base64.b64encode(tag).decode()

                h = MAC(self.shared_key,
                        self.current_algorithm.synthesis_algorithm)
                h.update(encrypted_data)

                message['MAC'] = base64.b64encode(h.finalize()).decode()

                #Testar o MAC
                #encrypted_data+="\x00".encode()

                message['data'] = base64.b64encode(encrypted_data).decode()

                self._send(message)

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
    parser.add_argument('-r',
                        dest='random',
                        default=False,
                        help='Random algorithm generator',
                        action='store_true')
    parser.add_argument('--cipher',
                        type=str,
                        dest='cipher',
                        default='TripleDES',
                        help="Cipher algorithm")
    parser.add_argument('--mode',
                        type=str,
                        dest='mode',
                        default='CBC',
                        help="Mode algorithm")
    parser.add_argument('--synthesis',
                        type=str,
                        dest='synthesis',
                        default='SHA512',
                        help="Synthesis algorithm")

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
    coro = loop.create_connection(
        lambda: ClientProtocol(file_name, loop, args.random, args.cipher, args.
                               mode, args.synthesis), server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()


if __name__ == '__main__':
    main()