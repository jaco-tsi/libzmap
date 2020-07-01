class Dns(object):

    output_fields = (
        'saddr', 'saddr_raw', 'daddr', 'daddr_raw', 'ipid', 'ttl', 'classification', 'success', 'app_success', 'sport',
        'dport', 'udp_len', 'icmp_responder', 'icmp_type', 'icmp_code', 'icmp_unreach_str', 'dns_id', 'dns_rd',
        'dns_tc', 'dns_aa', 'dns_opcode', 'dns_qr', 'dns_rcode', 'dns_cd', 'dns_ad', 'dns_z', 'dns_ra', 'dns_qdcount',
        'dns_ancount', 'dns_nscount', 'dns_arcount', 'dns_questions', 'dns_answers', 'dns_authorities',
        'dns_additionals', 'dns_parse_err', 'dns_unconsumed_bytes', 'raw_data', 'repeat', 'cooldown', 'timestamp_str',
        'timestamp_ts', 'timestamp_us'
    )

    def __init__(self, saddr, saddr_raw, daddr, daddr_raw, ipid, ttl, classification, success, app_success, sport,
                 dport, udp_len, icmp_responder, icmp_type, icmp_code, icmp_unreach_str, dns_id, dns_rd, dns_tc,
                 dns_aa, dns_opcode, dns_qr, dns_rcode, dns_cd, dns_ad, dns_z, dns_ra, dns_qdcount, dns_ancount,
                 dns_nscount, dns_arcount, dns_questions, dns_answers, dns_authorities, dns_additionals, dns_parse_err,
                 dns_unconsumed_bytes, raw_data, repeat, cooldown, timestamp_str, timestamp_ts, timestamp_us):
        """
        :param saddr           string: source IP address of response
        :param saddr_raw          int: network order integer form of source IP address
        :param daddr           string: destination IP address of response
        :param daddr_raw          int: network order integer form of destination IP address
        :param ipid               int: IP identification number of response
        :param ttl                int: time-to-live of response packet
        :param classification  string: packet protocol
        :param success           bool: Are the validation bits and question correct
        :param app_success       bool: Is the RA bit set with no error code?
        :param sport              int: UDP source port
        :param dport              int: UDP destination port
        :param udp_len            int: UDP packet lenght
        :param icmp_responder  string: Source IP of ICMP_UNREACH message
        :param icmp_type          int: icmp message type
        :param icmp_code          int: icmp message sub type code
        :param icmp_unreach_str string: for icmp_unreach responses, the string version of icmp_code (e.g. network-unreach)
        :param dns_id             int: DNS transaction ID
        :param dns_rd             int: DNS recursion desired
        :param dns_tc             int: DNS packet truncated
        :param dns_aa             int: DNS authoritative answer
        :param dns_opcode         int: DNS opcode (query type)
        :param dns_qr             int: DNS query(0) or response (1)
        :param dns_rcode          int: DNS response code
        :param dns_cd             int: DNS checking disabled
        :param dns_ad             int: DNS authenticated data
        :param dns_z              int: DNS reserved
        :param dns_ra             int: DNS recursion available
        :param dns_qdcount        int: DNS number questions
        :param dns_ancount        int: DNS number answer RR's
        :param dns_nscount        int: DNS number NS RR's in authority section
        :param dns_arcount        int: DNS number additional RR's
        :param dns_questions   repeated: DNS question list
        :param dns_answers     repeated: DNS answer list
        :param dns_authorities repeated: DNS authority list
        :param dns_additionals repeated: DNS additional list
        :param dns_parse_err      int: Problem parsing the DNS response
        :param dns_unconsumed_bytes    int: Bytes left over when parsing the DNS response
        :param raw_data        binary: UDP payload
        :param repeat            bool: Is response a repeat response from host
        :param cooldown          bool: Was response received during the cooldown period
        :param timestamp_str   string: timestamp of when response arrived in ISO8601 format.
        :param timestamp_ts       int: timestamp of when response arrived in seconds since Epoch
        :param timestamp_us       int: microsecond part of timestamp (e.g. microseconds since 'timestamp-ts')
        """
        self.saddr = saddr
        self.saddr_raw = saddr_raw
        self.daddr = daddr
        self.daddr_raw = daddr_raw
        self.ipid = ipid
        self.ttl = ttl
        self.classification = classification
        self.success = success
        self.app_success = app_success
        self.sport = sport
        self.dport = dport
        self.udp_len = udp_len
        self.icmp_responder = icmp_responder
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        self.icmp_unreach_str = icmp_unreach_str
        self.dns_id = dns_id
        self.dns_rd = dns_rd
        self.dns_tc = dns_tc
        self.dns_aa = dns_aa
        self.dns_opcode = dns_opcode
        self.dns_qr = dns_qr
        self.dns_rcode = dns_rcode
        self.dns_cd = dns_cd
        self.dns_ad = dns_ad
        self.dns_z = dns_z
        self.dns_ra = dns_ra
        self.dns_qdcount = dns_qdcount
        self.dns_ancount = dns_ancount
        self.dns_nscount = dns_nscount
        self.dns_arcount = dns_arcount
        self.dns_questions = dns_questions
        self.dns_answers = dns_answers
        self.dns_authorities = dns_authorities
        self.dns_additionals = dns_additionals
        self.dns_parse_err = dns_parse_err
        self.dns_unconsumed_bytes = dns_unconsumed_bytes
        self.raw_data = raw_data
        self.repeat = repeat
        self.cooldown = cooldown
        self.timestamp_str = timestamp_str
        self.timestamp_ts = timestamp_ts
        self.timestamp_us = timestamp_us

    def __str__(self):
        return str(self.__dict__)
