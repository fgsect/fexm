#!/usr/bin/env python3
"""
Reassemble connections from a given pcap file.
Thanks to @kcotsneb for the initial version of the parser
"""
import argparse
import datetime
import gzip
import json
import logging
import traceback
from socket import AF_INET6, inet_ntoa, inet_ntop
from typing import Union, Tuple, List, NamedTuple, Dict, AbstractSet, Optional, Set

import dpkt
import os
from dpkt.ip import IP
from dpkt.ip6 import IP6
from enum import Enum, unique
from sortedcontainers import SortedSet

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# When a session will be considered timed out
SESSION_TIMEOUT_MINS = 2

# These are typical file endings that would be supported. Good for pre-processing them
SUPPORTED_EXTENSIONS = ["cap", "pcap", "pcapng", "gz"]


@unique
class Direction(Enum):
    to_server = "TO_CLIENT"
    to_client = "TO_SERVER"


@unique
class Protocol(Enum):
    tcp = "TCP"
    udp = "UDP"
    icmp = "ICMP"


# Sort_by can be sequence number or timestamp according to protocol. It needs to be unique.
Packet = NamedTuple("Packet", [("sort_by", int), ("session", "Session"), ("timestamp", int), ("payload", bytes),
                               ("direction", Direction)])


class Backend:
    """
    Different backend may handle stored sessions differently.
    This Backend only outputs them to the console
    """

    def session_created(self, session: "Session") -> None:
        """
        Before the first package -> timestamp will still be undefined here.
        :param session:
        :return:
        """
        setattr(session, "session-id",
                "{}-{}-{}-{}".format(session.protocol, session.server_port, session.client_port, session.size))
        print("New session: {}".format(session))

    def packet_added(self, session: "Session", packet: Packet) -> None:
        if packet.payload:
            print("Added packet: {}".format(packet.payload))

    def store_packets(self, session: "Session", packets: Dict[Direction, AbstractSet[Packet]]) -> None:
        print("In Packets [{}...]\nOut packets: [{}...]".format(
            session,
            list(packets[Direction.to_server])[0:4],
            list(packets[Direction.to_client])[0:4]
        ))

    def session_finished(self, session: "Session") -> None:
        print("Finished session {}".format(session))


class FileBackend(Backend):
    """
    Backend that store the session contents to files
    """

    def __init__(self, outfolder: str) -> None:
        super().__init__()
        os.makedirs(outfolder, exist_ok=True)
        self.outfolder = outfolder

    def session_created(self, session: "Session") -> None:
        # setattr(session, "session-id",
        #        "{}-{}-{}-{}".format(session.protocol, str(session.start_time), session.server_port,
        #                             session.client_port, )
        print("New session: {}".format(session))

    def packet_added(self, session: "Session", packet: Packet) -> None:
        pass
        # if packet.payload:
        #    print("Added packet: {}".format(packet.payload))

    def store_packets(self, session: "Session", packets: Dict[Direction, AbstractSet[Packet]]) -> None:
        pass
        # print("In Packets [{}...]\nOut packets: [{}...]".format(
        #    session,
        #    list(packets[Direction.to_server])[0:4],
        #    list(packets[Direction.to_client])[0:4]
        # ))

    def session_finished(self, session: "Session") -> None:
        session_key = "{}-{}-{}".format(session.protocol, session.server_port, session.start_time.timestamp())
        for direction in [Direction.to_server, Direction.to_client]:
            if len(session.packets[direction]):
                with open(os.path.join(self.outfolder, "{}_{}.txt".format(session_key, direction.name)), "wb") as f:
                    for packet in session.packets[direction]:
                        f.write(packet.payload)
        print("Finished session {}".format(session))


class Session:
    def __init__(self, backend: Backend, timestamp: int,
                 server: str, server_port: int, client: str, client_port: int,
                 protocol: Protocol) -> None:
        """
        :param server:
        :param server_port:
        :param client:
        :param client_port:
        :param protocol:
        """
        self.server = server
        self.server_port = int(server_port)
        self.client = client
        self.client_port = int(client_port)
        self.protocol = protocol

        self.size = 0
        self.finished = False

        self._start_time = datetime.datetime.fromtimestamp(timestamp)
        self._end_time = self._start_time

        self.packets = {
            Direction.to_server: SortedSet(key=lambda x: x.sort_by),
            Direction.to_client: SortedSet(key=lambda x: x.sort_by)
        }

        self.backend = backend

        self.backend.session_created(self)

    def __str__(self):
        return "Session[{}]".format(json.dumps({
            "protocol": self.protocol.name,
            "server": self.server,
            "serverPort": self.server_port,
            "client": self.client,
            "clientPort": self.client_port,
            "startTime": str(self.start_time),
            "endTime": str(self.end_time),
            "finished": self.finished,
            "size": self.size
        }))

    def session_expired(self, timedelta: datetime.timedelta, current_time: datetime.datetime) -> bool:
        """
        determines if session has expired and should be dumped
        """
        if self.finished is True:
            return True

        if self.end_time is None:
            return False

        if current_time - self.end_time > timedelta:
            return True

        return False

    @property
    def time(self) -> datetime.datetime:
        return self.end_time

    @time.setter
    def time(self, val: datetime.datetime):
        self.start_time = val
        self.end_time = val

    @property
    def start_time(self) -> datetime.datetime:
        return self._start_time

    @start_time.setter
    def start_time(self, val: datetime.datetime) -> None:
        assert isinstance(val, datetime.datetime), "Wrong timestamp format %s" % type(val)
        if self._start_time is None or val < self._start_time:
            self._start_time = val

    @property
    def end_time(self) -> datetime.datetime:
        return self._end_time

    @end_time.setter
    def end_time(self, val: datetime.datetime) -> None:
        assert isinstance(val, datetime.datetime), "Wrong timestamp format %s" % type(val)
        if self.end_time is None or val > self.end_time:
            self._end_time = val

    def finish_session(self):  # TODO: Add filename?
        if self.size == 0:
            # return here, we are not interested in empty connections
            return

        self.backend.store_packets(self, self.packets)
        self.backend.session_finished(self)

    def append_packet(self, direction: Direction, timestamp: int, sequence_number: int, payload: bytes) -> None:
        """
        We throw each packet in here to get accurate information on the timing.
        Non-TCP should use the timestamp as sequence numbers
        """
        converted_timestamp = datetime.datetime.fromtimestamp(timestamp)
        self.time = converted_timestamp

        # ignore packets with empty payload
        if len(payload) == 0:
            return

        # do not store packets twice please
        packet = Packet(sort_by=sequence_number, session=self, direction=direction, timestamp=timestamp,
                        payload=payload)
        len_before = len(self.packets[direction])
        self.packets[direction].add(packet)
        if len(self.packets[direction]) > len_before:
            # Yeah, we added a new packet
            self.backend.packet_added(self, packet)
            self.size += len(payload)


class Overmind(object):
    def __init__(self, backend: Backend = Backend(), timeout_mins: int = SESSION_TIMEOUT_MINS) -> None:
        """
        The crawl pcap parser
        :param backend: a backend that will accept parsing results to write them to a db or file.
        """
        self.sessions = {}
        self.backend = backend
        self.timedelta = datetime.timedelta = datetime.timedelta(minutes=timeout_mins)
        self._time = None

    @property
    def time(self) -> datetime.datetime:
        return self._time

    @time.setter
    def time(self, val: datetime.datetime) -> None:
        if self._time is None or val > self._time:
            self._time = val

    def ip_to_str(self, ip_addr: str, v: int = 4) -> str:
        """ This converts the connection ID cid which is a tuple of (source_ip_address, source_tcp_port,
        destination_ip_address, destination_tcp_port) to a string.  v is either 4 for IPv4 or 6 for IPv6 """
        if v == 4:
            return inet_ntoa(ip_addr)
        elif v == 6:
            return inet_ntop(AF_INET6, ip_addr)
        else:
            raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

    def get_ip_version(self, ip_packet: Union[IP, IP6]) -> int:
        """
        Returns the ip version of a packet
        :param ip_packet: the packet
        :return: 4 or 6 for IP versions. Raies exception else.
        """
        if isinstance(ip_packet, IP):
            return 4
        elif isinstance(ip_packet, IP6):
            return 6
        raise Exception("Why are you getting the ip version of a non-IP Packet???")

    def get_ips_as_strings(self, ip_packet: Union[IP, IP6]) -> Tuple[str, str]:
        """
        :param ip_packet: The ip packet to stringify
        :return: Tuple[server, client] A tuple of (server, client)
        """
        ip_version = self.get_ip_version(ip_packet)
        return self.ip_to_str(ip_packet.src, ip_version), self.ip_to_str(ip_packet.dst, ip_version)

    def analyze_ip(self, ts: int, ip_data: Union[IP, IP6]) -> None:
        ip_packet = ip_data
        logger.debug("{}: Found IP-Packet".format(ts))
        src_ip, dst_ip = self.get_ips_as_strings(ip_packet)

        data = ip_packet.data
        if ip_packet.p == dpkt.ip.IP_PROTO_TCP:
            self.analyze_tcp(ts, data, src_ip, dst_ip)
        elif ip_packet.p == dpkt.ip.IP_PROTO_UDP:
            self.analyze_udp(ts, data, src_ip, dst_ip)
        # elif ip_packet.p == dpkt.ip.IP_PROTO_ICMP:
        # TODO: ICMP
        #    self.analyze_icmp(ts, data, src_ip, dst_ip)
        else:
            logger.debug("Unsupported ip packet: {}".format(ip_packet))

    def analyze_udp(self, ts: int, udp_data: dpkt.udp.UDP, src_ip: str, dst_ip: str) -> None:
        logger.debug("{}: Analyzing UDP packet".format(ts))
        # udp = dpkt.udp.UDP(str(udp_data))
        # udp = dpkt.udp.UDP(udp_data)
        udp = udp_data

        src_port = udp.sport
        dst_port = udp.dport

        source = "%s:%s" % (src_ip, src_port)
        dest = "%s:%s" % (dst_ip, dst_port)
        # U indicates UDP -> so that it doesn't share the same session with TCP sessions.
        session_sd = "U%s/%s" % (source, dest)
        session_ds = "U%s/%s" % (dest, source)
        payload = udp.data
        if session_sd in self.sessions:
            session_id = session_sd
        elif session_ds in self.sessions:
            session_id = session_ds
        else:
            # we have not seen a packet for that "session" yet, add it
            session_id = session_sd
            self.sessions[session_id] = Session(self.backend, ts, dst_ip, dst_port, src_ip, src_port, Protocol.udp)

        session = self.sessions[session_id]

        if src_ip == session.client and src_port == session.client_port:
            direction = Direction.to_server
        else:
            direction = Direction.to_client

        # UDP doesn't have sequence numbers. Use timestamp.
        session.append_packet(direction=direction, timestamp=ts, sequence_number=ts, payload=payload)

    def analyze_tcp(self, ts: int, tcp_data: dpkt.tcp.TCP, src_ip: str, dst_ip: str) -> None:
        logger.debug("{}: Analyzing TCP packet".format(ts))

        # tcp = dpkt.tcp.TCP(tcp_data)
        tcp = tcp_data
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = tcp.flags

        source = "%s:%s" % (src_ip, src_port)
        dest = "%s:%s" % (dst_ip, dst_port)
        session_sd = "%s/%s" % (source, dest)
        session_ds = "%s/%s" % (dest, source)
        payload = tcp.data
        if flags == 2:  # SYN
            # src is the client connecting to a server
            self.sessions[session_sd] = Session(self.backend, ts, dst_ip, dst_port, src_ip, src_port, Protocol.tcp)
        if flags == 18:  # SYN/ACK
            # this means, we found a SYN/ACK packet, so we can assign the
            # key for the session as dest->server
            # check if the reverse session is already in the dict
            if session_ds not in self.sessions:
                self.sessions[session_ds] = Session(self.backend, ts, src_ip, src_port, dst_ip, dst_port, Protocol.tcp)

        if session_sd in self.sessions:
            session_key = session_sd
        elif session_ds in self.sessions:
            session_key = session_ds
        else:
            if len(payload) > 0 and flags & 8 == 0:  # ensure that this is not a PUSH
                logger.debug(
                    "{}: This should not have happened, missing packets?".format(ts))  # , tcp_data))
                # sys.exit(1)
            return

        session = self.sessions[session_key]

        if src_ip == session.client and src_port == session.client_port:
            direction = Direction.to_server
        else:
            direction = Direction.to_client

        session.append_packet(direction=direction, timestamp=ts, sequence_number=tcp.seq, payload=payload)
        # FIN or RST, we can now dump the packet
        if flags & dpkt.tcp.TH_RST == 1 or flags & dpkt.tcp.TH_FIN == 1:
            session.done = True

    def analyze_packet(self, ts: int, buf: bytes) -> None:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            # type = eth.get_type(eth.type)#obsolete?
            if isinstance(eth.data, IP) or isinstance(eth.data, IP6):
                self.analyze_ip(ts, eth.data)
                return
        except KeyError as e:
            logger.debug("Invalid ethernet protocol found, assuming IP: {}".format(ts))

        # If it's not a valid ethernet packet we just assume we are listening
        # on a tunnel interface with raw IP packets
        try:
            self.analyze_ip(ts, dpkt.ip.IP(buf))
        except Exception as ex:
            # could be icmp or something
            # print("{}: Unknown packet type".format(ts))  # ts = timestamp
            logger.error("Analyze ip packet: {}".format(ex))

    def analyze(self, file: Union[str, List[str]], files_done: Optional[Set[str]] = None,
                handle_folder: bool = True, finish_analysis=False) -> "Overmind":
        """
        :param file: the pcap to analyze
        :param handle_folder: If the analysis should automatically scan folder contents if folder is found.
        :param files_done: A set of files that have already been worked on and should be ignored
        :param finish_analysis: If the analysis should close all connections. If false, call finish_analysis direclty.
        :raises FileNotFoundError if file could not be found or is a folder and handle folder is false.
        :return: Overmind for chaining
        """
        start = datetime.datetime.now()

        if isinstance(file, list):
            if len(file) == 0:
                logger.warning("No files are ought to be processed by current analyze() call.")
            files = file
            for file in files:
                self.analyze(file)
            return self

        if os.path.isdir(file):
            if not handle_folder:
                raise FileNotFoundError("The given file {} is a folder.".format(file))
            return self.analyze_folder(file, files_done)

        if not os.path.isfile(file):
            raise FileNotFoundError("File {} could not found".format(file))

        logger.info("Working on file {}".format(file))

        pcapreader = self._open_pcap(file)

        for ts, buf in pcapreader:  # ts = timestamp
            self.time = datetime.datetime.fromtimestamp(ts)
            try:
                self.analyze_packet(ts, buf)
            except Exception as e:
                logger.error("Exception while parsing. {}".format(e))
                traceback.print_exc()

        # pcapreader.__f.close()

        logger.info("Analyzing pcap (%s) took %.4fs" % (file, (datetime.datetime.now() - start).total_seconds()))
        if files_done is not None:
            files_done.add(self)

        # Session bookkeeping.
        for session_id, session in list(self.sessions.items()):
            if session.session_expired(self.timedelta, self.time):
                session.finish_session()  # TODO {"filename": file})
                del self.sessions[session_id]
                continue

        if finish_analysis:
            self.finish_analysis()

        return self

    def _open_pcap(self, file: str) -> Union[dpkt.pcap.Reader, dpkt.pcapng.Reader]:
        """
        Tries to open a pcap file, pcapng file or a gzipped version of the two.
        Does not support NetXRay or random other caputes.
        ::param file path of the (single) file to fuzz to load
        :return: An opened dpkt.pcap(ng) reader (or thows a ValueError)
        """
        f = None
        try:
            try:
                f = open(file, "rb")
                try:
                    return dpkt.pcap.Reader(f)
                except ValueError:
                    logger.debug("Trying to open [} as pcapng".format(file))
                    return dpkt.pcapng.Reader(f)
            except ValueError:
                try:
                    f.close()
                except:
                    logger.debug("No file to be closed - {} was never open.".format(file))
                logger.debug("Trying to open {} as gzip.".format(file))
                f = gzip.open(file, "rb")
                try:
                    return dpkt.pcap.Reader(f)
                except ValueError:
                    logger.debug("Trying to open {} as gzipped pcapng.".format(file))
                    return dpkt.pcapng.Reader(f)
        except Exception as ex:
            try:
                f.close()
            except:
                pass
            raise Exception("Could not load {}. Tried pcap, pcapng and gzipped versions thereof. ({})".format(file, ex))

    def finish_analysis(self) -> "Overmind":
        """
        Closes all sessions and finishes up.
        :return: Overmind for chaining
        """
        for session_id, session in list(self.sessions.items()):
            session.finish_session()

        self.sessions = {}
        return self

    def analyze_folder(self,
                       folder: str, files_done: Optional[Set[str]] = None, reverse: bool = False,
                       finish_analysis=True) -> 'Overmind':
        """
        Scans a folder forwards or backwards by name
        Will relist the contents every time
        :param files_done:  A set of files that have already been worked an and should be ignored in this analysis.
                            The newly worked files will be added to this set during execution.
        :param folder: the folder to analyze
        :param reverse: bool if True, files will be worked on in reverse alphabetical order, alphabetical otherwise.
        :param finish_analysis: If the analysis should finish automatically (will call self.finish_analysis)
        :return Overmind for chaining
        """
        logger.info("Scanning {} for files..".format(folder))
        if files_done is None:
            files_done = set()
        files = os.listdir(folder)
        files.sort(reverse=reverse)
        while len(files_done) < len(files):
            newfile = None
            for newfile in files:
                if not newfile in files_done:
                    break
            if newfile in files_done:
                logger.info("Done scanning files.")
                return self
            try:
                self.analyze(os.path.join(folder, newfile), files_done)
            except Exception as ex:
                logger.warning("An error occurred analyzing {} as pcap: {}".format(newfile, ex))
            files_done.add(newfile)
            # We need to do it this strang way to be able to look for new chances everytime
            files = os.listdir(folder)
            files.sort(reverse=reverse)

        if finish_analysis:
            self.finish_analysis()

        logger.info("Done scanning files in {}.".format(folder))
        return self


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description="Dump PCAP contents to text files")
    # arg_parser.add_argument("-f", "--filter",
    #                        default="port not 22 and host 10.7.14.2",
    #                        help="TCPdump style filter to use")
    arg_parser.add_argument("-o", "--outdir", default="./out", help="Folder to write output files to.")
    arg_parser.add_argument("input", nargs='+', help="Input file or folder")

    args = arg_parser.parse_args()
    mind = Overmind(FileBackend(outfolder=args.outdir)).analyze(file=args.input).finish_analysis()
