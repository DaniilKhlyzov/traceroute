import unittest
from unittest.mock import patch, call
import traceroute


class TestSendPacket(unittest.TestCase):

    def test_send_packet_icmp(self):
        response = traceroute.send_packet("192.168.0.1", 80, 1, 2, "icmp", None, None)
        self.assertEqual(response, "192.168.0.1")

    def test_send_packet_tcp(self):
        response = traceroute.send_packet("192.168.0.1", 80, 1, 2, "tcp", None, None)
        self.assertEqual(response, "192.168.0.1")

    def test_send_packet_udp(self):
        response = traceroute.send_packet("192.168.0.1", 80, 1, 2, "udp", None, None)
        self.assertEqual(response, "192.168.0.1")

    def test_send_packet_icmp_with_payload(self):
        response = traceroute.send_packet("192.168.0.1", 80, 1, 2, "icmp", "payload", None)
        self.assertEqual(response, "192.168.0.1")

    def test_send_packet_tcp_with_payload(self):
        response = traceroute.send_packet("192.168.0.1", 80, 1, 2, "tcp", "payload", None)
        self.assertEqual(response, "192.168.0.1")

    def test_send_packet_udp_with_payload(self):
        response = traceroute.send_packet("192.168.0.1", 80, 1, 2, "udp", "payload", None)
        self.assertEqual(response, "192.168.0.1")


class TestTraceroute(unittest.TestCase):
    def test_traceroute(self):
        target = "192.168.0.1"

        protocol = "udp"
        timeout = 2
        port = 80
        max_hops = 5
        table = True
        int_ip = True
        source_address = None
        payload = None

        with patch("traceroute.send_packet") as mock_send_packet:
            mock_send_packet.return_value = None

        with patch("traceroute.send_packet") as mock_send_packet:
            mock_send_packet.return_value = None

            with patch("builtins.print") as mock_print:
                traceroute.traceroute(target, protocol, timeout, port, max_hops, table, int_ip, source_address, payload)

                expected_calls = [
                    call(target, port, 1, timeout, protocol, payload, source_address),
                    call(target, port, 1, timeout, protocol, payload, source_address),
                    call(target, port, 2, timeout, protocol, payload, source_address),
                    call(target, port, 2, timeout, protocol, payload, source_address),
                    call(target, port, 3, timeout, protocol, payload, source_address),
                    call(target, port, 3, timeout, protocol, payload, source_address),
                ]
                mock_send_packet.assert_has_calls(expected_calls)
                mock_print.assert_called()

