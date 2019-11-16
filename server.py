import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
from aio_tcpserver import tcp_server
from utils import AVAILABLE_CIPHERS, AVAILABLE_HASHES, AVAILABLE_MODES, ProtoAlgorithm, unpacking, DH_parameters, DH_parametersNumbers,\
         key_derivation, length_by_cipher, decryption,MAC
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_KEY = 4
STATE_ALGORITHM_ACK = 5
STATE_DH_EXCHANGE_KEYS = 6

#GLOBAL
storage_dir = 'files'


class ClientHandler(asyncio.Protocol):
    def __init__(self, signal):
        """
		Default constructor
		"""
        self.signal = signal
        self.state = 0
        self.file = None
        self.file_name = None
        self.file_path = None
        self.storage_dir = storage_dir
        self.buffer = ''
        self.peername = ''
        self.current_algorithm = None
        self.DH_private_key = None
        self.DH_public_key = None
        self.shared_key = None
        self.salt = None

    def connection_made(self, transport) -> None:
        """
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
        self.peername = transport.get_extra_info('peername')
        logger.info('\n\nConnection from {}'.format(self.peername))
        self.transport = transport
        self.state = STATE_CONNECT

    def data_received(self, data: bytes) -> None:
        """
        Called when data is received from the client.
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
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
        #logger.debug("Frame: {}".format(frame))

        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode JSON message: {}".format(frame))
            self.transport.close()
            return

        mtype = message.get('type', "").upper()

        if mtype == 'OPEN':
            ret = self.process_open(message)
        elif mtype == 'DATA':
            ret = self.process_data(message)
        elif mtype == 'CLOSE':
            ret = self.process_close(message)
        elif mtype == 'ALGORITHM_NEGOTIATION':
            ret = self.process_algorithm_negotiation(message)
        elif mtype == 'PARAMETERS_AND_DH_PUBLIC_KEY':
            ret = self.process_DH_Public_Key(message)
        else:
            logger.warning("Invalid message type: {}".format(message['type']))
            ret = False

        if not ret:
            try:
                self._send({'type': 'ERROR', 'message': 'See server'})
            except:
                pass  # Silently ignore

            logger.info("Closing transport")
            if self.file is not None:
                self.file.close()
                self.file = None

            self.state = STATE_CLOSE
            self.transport.close()

    def process_DH_Public_Key(self, message: str) -> bool:
        """	
			Reads client DH_public_key,p and g parameters
			Also server creates their own DH_keys and sent public key to server
		"""

        if self.state != STATE_ALGORITHM_ACK:
            return False

        data = message.get('data', None)
        if data is None:
            return False

        logger.debug(f"Client DH_public_key : {data}")

        try:

            p = data.get('p', 'None')
            g = data.get('g', 'None')
            key = data.get('key')

            parameters = DH_parametersNumbers(p, g)

            self.DH_private_key = parameters.generate_private_key()
            self.DH_public_key = self.DH_private_key.public_key()

            message = {
                'type':
                'DH_PUBLIC_KEY',
                'key':
                self.DH_public_key.public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
            }

            self._send(message)

            self.state = STATE_DH_EXCHANGE_KEYS

            self.shared_key = key_derivation(
                "SHA512", length_by_cipher[self.current_algorithm.cipher],
                self.DH_private_key.exchange(
                    load_pem_public_key(key.encode(), default_backend())))

            logger.info(f"Shared_key with DH : {self.shared_key}")
        except Exception as e:
            logger.warning(e)
            return False

        return True

    def process_algorithm_negotiation(self, message: str) -> bool:
        """
		Processes an algorithm negotiation from the client

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""

        if self.state != STATE_CONNECT:
            logger.warning("Invalid state. Discarding")
            return False

        chosen_algorithm = message.get("data", None)
        status = True

        if chosen_algorithm is not None:
            algorithm, cipher, mode, synthesis_algorithm = unpacking(
                chosen_algorithm)

            if cipher in AVAILABLE_CIPHERS and mode in AVAILABLE_MODES and synthesis_algorithm in AVAILABLE_HASHES:
                self.current_algorithm = ProtoAlgorithm(
                    cipher, mode, synthesis_algorithm)

                logger.info(
                    f"Process algorithm negotiation: {message}\t Algorithm Accepted"
                )

                message = {'type': 'OK'}
                self.state = STATE_ALGORITHM_ACK

            else:
                message = {
                    'type':
                    'ERROR',
                    'message':
                    'Server does not implement algorithm requested by client'
                }
                status = False

            self._send(message)

            return status

        return False

    def process_open(self, message: str) -> bool:
        """
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug("Process Open: {}".format(message))

        if self.state != STATE_DH_EXCHANGE_KEYS:
            logger.warning("Invalid state. Discarding")
            return False

        if not 'file_name' in message:
            logger.warning("No filename in Open")
            return False

        # Only chars and letters in the filename
        file_name = re.sub(r'[^\w\.]', '', message['file_name'])
        file_path = os.path.join(self.storage_dir, file_name)
        if not os.path.exists("files"):
            try:
                os.mkdir("files")
            except:
                logger.exception("Unable to create storage directory")
                return False

        try:
            self.file = open(file_path, "wb")
            logger.info("File open")
        except Exception:
            logger.exception("Unable to open file")
            return False

        self._send({'type': 'OK'})

        self.file_name = file_name
        self.file_path = file_path
        self.state = STATE_OPEN
        return True

    def process_data(self, message: str) -> bool:
        """
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug("Process Data: {}".format(message))

        if self.state == STATE_OPEN:
            self.state = STATE_DATA

        elif self.state == STATE_DATA:
            # Next packets
            pass

        else:
            logger.warning("Invalid state. Discarding")
            return False

        try:
            data = message.get('data', None)
            if data is None:
                logger.debug("Invalid message. No data found")
                return False

            cipher = self.current_algorithm.cipher
            mode = self.current_algorithm.mode


            padding_length = message.get('padding_length', None)
            iv = message.get('iv',None)
            MAC_b64 = message.get('MAC',None)

            if padding_length is None or iv is None or MAC_b64 is None:
                return False

            
            iv = base64.b64decode(iv)
            encrypted_data = base64.b64decode(message['data'])
            received_MAC =  base64.b64decode(MAC_b64)
            
            h = MAC(self.shared_key,self.current_algorithm.synthesis_algorithm)
            h.update(encrypted_data)
            current_MAC = h.finalize()

            if received_MAC != current_MAC:
                logger.warning("MAC authentication Failed")
                return False


            decrypted_data = base64.b64encode(decryption(encrypted_data, self.shared_key, cipher, mode,padding_length,iv))
            
            bdata = base64.b64decode( decrypted_data )
        except:
            logger.exception(
                "Could not decode base64 content from message.data")
            return False

        try:
            self.file.write(bdata)
            self.file.flush()
        except:
            logger.exception("Could not write to file")
            return False

        return True

    def process_close(self, message: str) -> bool:
        """
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug("Process Close: {}".format(message))

        self.transport.close()
        if self.file is not None:
            self.file.close()
            self.file = None

        self.state = STATE_CLOSE

        return True

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
    global storage_dir

    parser = argparse.ArgumentParser(
        description='Receives files from clients.')
    parser.add_argument('-v',
                        action='count',
                        dest='verbose',
                        help='Shows debug messages (default=False)',
                        default=0)
    parser.add_argument('-p',
                        type=int,
                        nargs=1,
                        dest='port',
                        default=5000,
                        help='TCP Port to use (default=5000)')

    parser.add_argument('-d',
                        type=str,
                        required=False,
                        dest='storage_dir',
                        default='files',
                        help='Where to store files (default=./files)')

    args = parser.parse_args()
    storage_dir = os.path.abspath(args.storage_dir)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    if port <= 0 or port > 65535:
        logger.error("Invalid port")
        return

    if port < 1024 and not os.geteuid() == 0:
        logger.error("Ports below 1024 require eUID=0 (root)")
        return

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Port: {} LogLevel: {} Storage: {}".format(
        port, level, storage_dir))
    tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
    main()
