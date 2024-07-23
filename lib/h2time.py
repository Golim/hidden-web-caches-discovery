#!/usr/bin/env python3

'''
Slightly modified version of the h2time.py file from
https://github.com/DistriNet/timeless-timing-attacks
'''

from urllib.parse import urlparse

import h2.connection
import h2.events
import traceback
import certifi
import logging
import socket
import time
import six
import ssl


class H2Request:
    '''
    HTTP/2 request object.
    '''
    def __init__(self, method: str, url: str, headers: dict = None, data: str = ''):
        self.method = method
        self.url = self.scheme = self.host = self.port = self.path = self.query = None
        self.headers = headers if headers is not None else {}
        self.data = data
        self.set_url(url)

    def set_url(self, url: str):
        self.url = url
        parsed = urlparse(url)

        self.scheme = parsed.scheme
        self.host   = parsed.netloc
        self.port   = parsed.port or 443 if self.scheme == 'https' else 80
        self.path   = parsed.path
        self.query  = parsed.query

    def set_header(self, key: str, value: str):
        self.headers[key] = value

    def set_headers(self, headers: dict):
        [self.set_header(k, v) for k, v in headers.items()]

    def remove_header(self, key: str):
        del self.headers[key]

    def get_request_headers(self):
        path = self.path
        if self.query:
            path += '?' + self.query
        headers = {
            ':method': self.method,
            ':authority': self.host,
            ':scheme': self.scheme,
            ':path': path if path else '/'
        }
        for k, v in self.headers.items():
            headers[k] = v

        return headers


class H2Time:
    '''
    This class implements a method to perform
    Timeless Timing Attacks using HTTP/2
    '''
    def __init__(self, request1: H2Request, request2: H2Request, num_request_pairs=3, inter_request_time_ms=100, timeout=30):
        self.request1 = request1
        self.request2 = request2
        self.host = request1.host
        self.port = request1.port
        self.num_request_pairs = num_request_pairs
        self.inter_request_time_ms = inter_request_time_ms
        self.timeout = timeout
        self.connection_open = False
        self.sent_streams = {}

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.socket = None
        self.connection = None

    def __enter__(self):
        self.connect()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self):
        if self.connection_open:
            self.logger.info('Connection already open, skipping')
            return

        # Socket and ssl configuration
        socket.setdefaulttimeout(self.timeout)
        ctx = ssl.create_default_context(cafile=certifi.where())
        ctx.set_alpn_protocols(['h2'])

        # Open a socket to the server and initiate TLS/SSL
        self.socket = socket.create_connection((self.host, self.port))
        self.socket = ctx.wrap_socket(self.socket, server_hostname=self.host)

        self.connection = h2.connection.H2Connection()
        self.connection.initiate_connection()
        self.send_all()
        self.connection_open = True
        self.logger.debug(f'Connection to {self.host}:{self.port} established')

    def send_request(self, headers, end_stream=True):
        # Get the next available stream ID
        stream_id = self.connection.get_next_available_stream_id()

        _headers = [(k, v) for k, v in headers.items()]
        self.connection.send_headers(stream_id, _headers, end_stream=True)

        self.sent_streams[stream_id] = {
            'response_received': False,
            'response_headers': None,
            'response_time': None,
            'response_data': b''
        }

        return stream_id

    def send_request_pair(self):
        headers1 = self.request1.get_request_headers()
        headers2 = self.request2.get_request_headers()

        stream_id1 = self.send_request(headers1)
        stream_id2 = self.send_request(headers2)

        self.logger.info(f'Sending request 1: {dict(headers1)[":scheme"]}://{dict(headers1)[":authority"]}{dict(headers1)[":path"]} with stream ID {stream_id1}')
        self.logger.info(f'Sending request 2: {dict(headers2)[":scheme"]}://{dict(headers2)[":authority"]}{dict(headers2)[":path"]} with stream ID {stream_id2}')

        self.send_all()

        # Receive the responses
        while not (
                self.sent_streams[stream_id1]['response_received'] and
                self.sent_streams[stream_id2]['response_received']
                ):
            # read raw data from the socket
            data = self.socket.recv(65536 * 1024)
            if not data:
                self.logger.info('No data, breaking!')
                break

            # feed raw data into h2, and process resulting events
            events = self.connection.receive_data(data)
            for event in events:
                try:
                    # Check if the event is a RemoteSettingsChanged event
                    if isinstance(event, h2.events.RemoteSettingsChanged):
                        # Update the settings
                        new_settings = dict([(id, cs.new_value) for (id, cs) in six.iteritems(event.changed_settings)])
                        self.connection.update_settings(new_settings)

                        self.logger.debug(f'Settings changed')
                    elif isinstance(event, h2.events.ResponseReceived):
                        if event.stream_id not in self.sent_streams:
                            self.logger.error(f'Error: stream ID {event.stream_id} not found')
                            continue
                        stream_id = event.stream_id

                        # Merge headers with the same name into a single header
                        headers = {}
                        for k, v in event.headers:
                            if k in headers:
                                headers[k.decode()] += ', ' + v.decode()
                            else:
                                headers[k.decode()] = v.decode()

                        self.sent_streams[stream_id]['response_headers'] = headers
                        self.logger.info(f"Response received for stream {event.stream_id}: {headers[':status']}")

                        self.sent_streams[stream_id]['response_received'] = True
                        self.sent_streams[stream_id]['response_time'] = time.time_ns()
                    elif isinstance(event, h2.events.DataReceived):
                        if event.stream_id not in self.sent_streams:
                            self.logger.error(f'Error: stream ID {event.stream_id} not found')
                            continue
                        stream_id = event.stream_id

                        # Update flow control so the server doesn't starve us
                        self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                        # Update the body
                        self.sent_streams[stream_id]['response_data'] += event.data
                    elif isinstance(event, h2.events.StreamEnded):
                        self.logger.info(f'Stream ended: {event.stream_id}')
                except Exception as e:
                    self.logger.error(f'Error: {e} with event {event}')
                    traceback.print_exc()
                    self.close()
                    return None

            # Send any pending data to the server
            self.send_all()

        if not (
                self.sent_streams[stream_id1]['response_received'] and
                self.sent_streams[stream_id2]['response_received']
                ):
            self.logger.error(f'Error: one or more responses not received')
            return None

        time_diff = (self.sent_streams[stream_id2]['response_time'] - self.sent_streams[stream_id1]['response_time']) / 1_000_000
        return (time_diff,
                self.sent_streams[stream_id1]['response_headers'],
                self.sent_streams[stream_id2]['response_headers'],
                self.sent_streams[stream_id1]['response_data'].decode(),
                self.sent_streams[stream_id2]['response_data'].decode()
        )

    def send_all(self):
        if self.connection_open:
            self.socket.sendall(self.connection.data_to_send())

    def close(self):
        # tell the server we are closing the h2 connection
        self.connection.close_connection()
        self.send_all()

        # close the socket
        self.socket.close()
        self.connection_open = False

    def run_attack(self):
        results = []
        for _ in range(self.num_request_pairs):
            time.sleep(self.inter_request_time_ms / 1000)
            if not self.connection_open:
                self.connect()
            try:
                (
                    time_difference,
                    response_headers1,
                    resonse_headers2,
                    response_body1,
                    response_body2
                ) = self.send_request_pair()
            except Exception as e:
                self.logger.error(f'Error: {e}')
                # traceback.print_exc()
                self.close()
                continue

            results.append([time_difference, response_headers1, resonse_headers2, response_body1, response_body2])

            # Check if there is a redirect in the first response
            if 'location' in response_headers1:
                # Block the attack to follow the redirect.
                break

        return results
