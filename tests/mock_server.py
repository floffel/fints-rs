#!/usr/bin/env python3
"""
Standalone FinTS 3.0 mock server for integration testing.

Extracted and adapted from python-fints test suite (conftest.py).
https://github.com/raphaelm/python-fints/blob/master/tests/conftest.py

Speaks the real FinTS wire protocol over HTTP with base64 encoding.

Test credentials:
  BLZ:      12345678
  Username: test1
  PIN:      1234 (valid), 3938 (temp locked), anything else = invalid
  Accounts: DE11123456780000000001 (Girokonto), DE11123456780000000002 (Tagesgeld)

Usage:
  python3 mock_server.py [port]
  # Prints "READY:<port>" to stdout when listening
"""

import sys
import http.server
import base64
import uuid
import re
import random


def make_server(host="127.0.0.1", port=0):
    dialog_prefix = base64.b64encode(uuid.uuid4().bytes, altchars=b"_/").decode(
        "us-ascii"
    )
    system_prefix = base64.b64encode(uuid.uuid4().bytes, altchars=b"_/").decode(
        "us-ascii"
    )
    dialogs = {}
    systems = {}

    class FinTSHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # Suppress HTTP request logging
            pass

        def make_answer(self, dialog_id, message):
            datadict = dialogs[dialog_id]

            pin = None
            tan = None
            pinmatch = re.search(
                rb"HNSHA:\d+:\d+\+[^+]*\+[^+]*\+([^:+?']+)(?::([^:+?']+))?'", message
            )
            if pinmatch:
                pin = pinmatch.group(1).decode("us-ascii")
                if pinmatch.group(2):
                    tan = pinmatch.group(2).decode("us-ascii")

            if pin not in ("1234", "3938"):
                return b"HIRMG::2+9910::Pin ung\xc3\xbcltig'"

            result = []
            result.append(b"HIRMG::2+0010::Nachricht entgegengenommen'")

            hkvvb = re.search(rb"HKVVB:(\d+):3\+(\d+)\+(\d+)", message)
            if hkvvb:
                responses = [hkvvb.group(1)]
                segments = []

                if hkvvb.group(2) != b"78":
                    responses.append(
                        b"3050::BPD nicht mehr aktuell, aktuelle Version enthalten."
                    )
                    bpd = (
                        "HIBPA:6:3:4+78+280:12345678+Test Bank+1+1+300+500'"
                        "HIKOM:7:4:4+280:12345678+1+3:http?://{host}?:{port}/'"
                        "HIKAZS:10:7:4+1+1+1+365:J:N'"
                        "HISPAS:31:1:4+1+1+1+J:J:N:sepade?:xsd?:pain.001.003.03.xsd'"
                        "HISALS:19:7:4+1+1+1'"
                        "HITANS:53:7:4+1+1+1+N:N:0:942:2:MTAN2:mobileTAN::mobile TAN:6:1:SMS:3:1:J:1:0:N:0:2:N:J:00:1:1:962:2:HHD1.4:HHD:1.4:Smart-TAN plus manuell:6:1:Challenge:3:1:J:1:0:N:0:2:N:J:00:1:1'"
                        "HIPINS:54:1:4+1+1+1+5:20:6:Benutzer ID::HKSPA:N:HKKAZ:N:HKSAL:N:HKTAN:N'"
                    ).format(host=host, port=server.server_address[1])
                    segments.append(bpd.encode("us-ascii"))

                if hkvvb.group(3) != b"3":
                    responses.append(
                        b"3050::UPD nicht mehr aktuell, aktuelle Version enthalten."
                    )
                    segments.append(
                        b"HIUPA:57:4:4+test1+3+0'"
                        b"HIUPD:58:6:4+1::280:12345678+DE11123456780000000001+test1++EUR+Fullname++Girokonto++HKSAL:1+HKKAZ:1+HKSPA:1'"
                        b"HIUPD:59:6:4+2::280:12345678+DE11123456780000000002+test1++EUR+Fullname++Tagesgeld++HKSAL:1+HKKAZ:1+HKSPA:1'"
                    )

                if pin == "3938":
                    responses.append(
                        "3938::Ihr Zugang ist vorläufig gesperrt.".encode("utf-8")
                    )
                else:
                    responses.append(
                        b"3920::Zugelassene TAN-Verfahren fur den Benutzer:942"
                    )
                    responses.append(b"0901::*PIN gultig.")
                responses.append(b"0020::*Dialoginitialisierung erfolgreich")

                result.append(b"HIRMS::2:" + b"+".join(responses) + b"'")
                result.extend(segments)

            if b"HKSYN:" in message:
                system_id = "{};{:05d}".format(system_prefix, len(systems) + 1)
                systems[system_id] = {}
                result.append("HISYN::4:5+{}'".format(system_id).encode("us-ascii"))

            if b"HKSPA:" in message:
                result.append(
                    b"HISPA::1:4+J:DE11123456780000000001:GENODE23X42:00001::280:12345678'"
                )

            # HKSAL - Balance request (v5-7)
            hksal = re.search(rb"HKSAL:(\d+):(\d+)", message)
            if hksal:
                segno = hksal.group(1).decode("us-ascii")
                result.append(
                    "HIRMS::2:{segno}+0010::Saldo ermittelt'".format(
                        segno=segno
                    ).encode("us-ascii")
                )
                result.append(
                    "HISAL::7:{segno}+1::280:12345678+Girokonto+EUR+C:1523,42:EUR:20250115'".format(
                        segno=segno
                    ).encode("us-ascii")
                )

            # HKTAN - just acknowledge (ignore, mock doesn't need TAN handling)
            if b"HKTAN:" in message:
                pass  # silently accept

            # HKKAZ - Statement request (v5-7) with pagination
            hkkaz = re.search(
                rb"HKKAZ:(\d+):(\d+)\+[^+]+\+N(?:\+[^+]*\+[^+]*(?:\+[^+]*\+([^+']*))?)?'",
                message,
            )
            if hkkaz:
                segno = hkkaz.group(1).decode("us-ascii")
                if hkkaz.group(3):
                    startat = int(hkkaz.group(3).decode("us-ascii"), 10)
                else:
                    startat = 0

                transactions = [
                    [
                        b"-",
                        b":20:STARTUMS",
                        b":25:12345678/0000000001",
                        b":28C:0",
                        b":60F:C150101EUR1041,23",
                        b":61:150101C182,34NMSCNONREF",
                        b":86:051?00UEBERWEISG?10931?20Ihre Kontonummer 0000001234",
                        b"?21/Test Ueberweisung 1?22n WS EREF: 1100011011 IBAN:",
                        b"?23 DE1100000100000001234 BIC?24: GENODE11 ?1011010100",
                        b"?31?32Bank",
                        b":62F:C150101EUR1223,57",
                        b"-",
                    ],
                    [
                        b"-",
                        b":20:STARTUMS",
                        b":25:12345678/0000000001",
                        b":28C:0",
                        b":60F:C150301EUR1223,57",
                        b":61:150301C100,03NMSCNONREF",
                        b":86:051?00UEBERWEISG?10931?20Ihre Kontonummer 0000001234",
                        b"?21/Test Ueberweisung 2?22n WS EREF: 1100011011 IBAN:",
                        b"?23 DE1100000100000001234 BIC?24: GENODE11 ?1011010100",
                        b"?31?32Bank",
                        b":61:150301C100,00NMSCNONREF",
                        b":86:051?00UEBERWEISG?10931?20Ihre Kontonummer 0000001234",
                        b"?21/Test Ueberweisung 3?22n WS EREF: 1100011011 IBAN:",
                        b"?23 DE1100000100000001234 BIC?24: GENODE11 ?1011010100",
                        b"?31?32Bank",
                        b":62F:C150101EUR1423,60",
                        b"-",
                    ],
                ]

                if startat + 1 < len(transactions):
                    result.append(
                        "HIRMS::2:{segno}+3040::Es liegen weitere Informationen vor:{next}'".format(
                            segno=segno, next=startat + 1
                        ).encode("iso-8859-1")
                    )
                else:
                    result.append(
                        "HIRMS::2:{segno}+0010::Umsaetze geliefert'".format(
                            segno=segno
                        ).encode("us-ascii")
                    )

                tx = b"\r\n".join([b""] + transactions[startat] + [b""])
                result.append(
                    "HIKAZ::7:{segno}+@{len}@".format(segno=segno, len=len(tx)).encode(
                        "us-ascii"
                    )
                    + tx
                    + b"'"
                )

            # HKEND - Dialog end
            if b"HKEND:" in message:
                result.append(b"HIRMS::2+0010::Dialog beendet'")

            return b"".join(result)

        def process_message(self, message):
            incoming_dialog_id = re.match(rb"HNHBK:1:3\+\d+\+300\+([^+]+)", message)

            if incoming_dialog_id:
                dialog_id = incoming_dialog_id.group(1).decode("us-ascii")
                if dialog_id == "0":
                    dialog_id = "{};{:05d}".format(dialog_prefix, len(dialogs) + 1)
                    dialogs[dialog_id] = {"in_messages": []}

                datadict = dialogs[dialog_id]
                datadict["in_messages"].append(message)

                answer = self.make_answer(dialog_id, message)

                msg_num = len(datadict["in_messages"])

                # Build envelope: HNHBK + HNVSK + HNVSD(answer) + HNHBS
                # We build a simplified envelope manually (no python-fints dependency!)
                inner = answer
                inner_bin = "@{}@".format(len(inner)).encode("us-ascii") + inner

                hnvsk = (
                    "HNVSK:998:3+PIN:1+998+1+2::0+1+2:2:13:@8@\x00\x00\x00\x00\x00\x00\x00\x00:5:1"
                    "+280:12345678:0:S:0:0+0'"
                )
                hnvsd = "HNVSD:999:1+"
                hnhbs = "HNHBS:5:1+{}'".format(msg_num)

                # Build body (everything after HNHBK)
                body = (
                    hnvsk.encode("latin-1")
                    + hnvsd.encode("us-ascii")
                    + inner_bin
                    + b"'"
                    + hnhbs.encode("us-ascii")
                )

                # HNHBK with correct size
                # Header template: HNHBK:1:3+NNNNNNNNNNNN+300+dialog_id+msg_num'
                header_tpl = "HNHBK:1:3+{size:012d}+300+{did}+{num}'"
                # First compute with placeholder
                header_test = header_tpl.format(size=0, did=dialog_id, num=msg_num)
                total = len(header_test.encode("us-ascii")) + len(body)
                header = header_tpl.format(size=total, did=dialog_id, num=msg_num)

                return header.encode("us-ascii") + body

            return b""

        def do_POST(self):
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            message = base64.b64decode(post_data)

            response = self.process_message(message)

            content_data = base64.b64encode(response)
            self.send_response(200)
            self.send_header("Content-Length", str(len(content_data)))
            self.end_headers()
            self.wfile.write(content_data)

    server = http.server.HTTPServer((host, port), FinTSHandler)
    return server


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server = make_server(port=port)
    actual_port = server.server_address[1]

    # Signal to parent process that we're ready
    print("READY:{}".format(actual_port), flush=True)

    try:
        # Use a short poll interval so the process can be killed quickly
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
