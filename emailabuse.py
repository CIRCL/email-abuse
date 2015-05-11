#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#
# Copyright (C) 2015 Sascha Rommelfangen, Raphael Vinot, Alexandre Dulaunoy
# Copyright (C) 2015 CIRCL Computer Incident Response Center Luxembourg (SMILE gie)
#
# Description: analyse emails for malicious content
#
# Features:
# -----------------------------------------------------------
# extract URLs          spot phishing/malicious links
# VirusTotal            lookup of file hashes
# OLE (MS Office)       find Macros and inconsistencies
# OOXML (MS Office XML) find Macros
# PDF                   find active content
# Compressed files      find suspicious files


import argparse
from flanker import mime
from flanker.mime.message.errors import DecodingError
import sys
import os
import tempfile
import logging
from module import Payload, ExamineHeaders, ExtractURL, Tokenizer, ArchiveZip, \
    Archive7z, ArchiveRAR
from io import BytesIO
import re
import json


storepath = 'store'


def create_unique_file():
    if not os.path.exists(storepath):
        os.makedirs(storepath)
    fd, fn = tempfile.mkstemp(dir=storepath)
    return fn


def get_filename(path):
    p, fn = os.path.split(path)
    return fn


def logging_init(msg_file):
    logging.getLogger("requests").setLevel(logging.WARNING)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    msg_log_file = msg_file + ".log"
    logfile = os.path.join(storepath, msg_log_file)
    fh_formatter = logging.Formatter('%(asctime)s - %(message)s')
    fh = logging.FileHandler(logfile)
    fh.setFormatter(fh_formatter)
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    return logger


def store_msg(content, filename):
    if not os.path.exists(storepath):
        os.makedirs(storepath)
    path = os.path.join(storepath, filename)
    f = open(path, 'wb')
    content = str(content)
    f.write(content)
    f.close()


def init(msg):
    msg_file = get_filename(create_unique_file())
    logger = logging_init(msg_file)
    logger.info('Email abuse - inspecting new mail: %s' % msg_file)
    store_msg(msg, msg_file)
    return msg_file


archive_list = [ArchiveZip, Archive7z, ArchiveRAR]


def get_strings(payload):
    chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
    shortest_run = 4
    regexp = '[%s]{%d,}' % (chars, shortest_run)
    pattern = re.compile(regexp)
    return pattern.findall(payload)


def process_payload(filename, body, content_type, origin_domain, passwordlist):
    is_archive = False
    unpacked_files = {}
    results = {}
    indicators = 0
    if (content_type is not None
            and "Microsoft Word 2007+" not in content_type
            and "Microsoft Excel 2007+" not in content_type):
        # Maybe an archive
        for a in archive_list:
            try:
                filehandle = BytesIO(body)
            except:
                # broken document...
                filehandle = BytesIO(body.encode('utf-16'))
            archive = a(filehandle, passwordlist)
            unpacked_files = archive.processing()
            if unpacked_files is not None and len(unpacked_files) > 0:
                is_archive = True
                break
    if not is_archive:
        # Assume it is not an archive
        unpacked_files = {}
        try:
            unpacked_files[filename] = BytesIO(body)
        except:
            # broken document...
            unpacked_files[filename] = BytesIO(body.encode('utf-16'))

    for fn, filehandle in list(unpacked_files.items()):
        if filehandle is None:
            continue
        payload = Payload(fn, filehandle, origin_domain)
        results[fn] = list(payload.processing())
        indicators += payload.indicators
    return results, indicators


def process_attachement(attachment, origin_domain):
    global indicators
    global passwordlist
    global suspicious_urls
    try:
        mpart_attachment = mime.from_string(attachment.body)
        if mpart_attachment.content_type.is_multipart():
            for p in mpart_attachment.walk():
                process_attachement(p, origin_domain)
    except DecodingError:
        # Binary attachement
        pass
    extract_urls = ExtractURL(attachment.body, origin_domain)
    suspicious_urls |= set(extract_urls.processing())
    indicators += extract_urls.indicators
    content_type = attachment.detected_content_type
    filename = attachment.detected_file_name
    attachements.append((filename, content_type))
    if filename is not None and len(filename) > 0:
        passwordlist.append(filename)
        prefix, suffix = os.path.splitext(filename)
        passwordlist.append(prefix)
    passwordlist = [i for i in passwordlist if len(i) > 1]
    r, r_indicators = process_payload(filename, attachment.body, content_type, origin_domain, passwordlist)
    indicators += r_indicators
    payload_results.append(r)


if __name__ == '__main__':
    argParser = argparse.ArgumentParser(description='email_abuse parser')
    argParser.add_argument('-r', default='-', help='Filename of the raw email to read (default: stdin)')
    argParser.add_argument('-o', default='ascii', help='Output format: ascii or json (default: ascii)')
    args = argParser.parse_args()
    if args.r == '-':
        msg = mime.from_string(sys.stdin.read())
    else:
        fp = open(args.r, 'rb')
        msg = mime.from_string(fp.read())

    msg_file = init(msg)

    subject = msg.subject
    passwordlist = ["password", "passw0rd", "infected", "qwerty", "malicious",
                    "archive", "zip", "malware"]
    indicators = 0

    examine_headers = ExamineHeaders(msg)
    origin_ip, rbl_listed, rbl_comment, mailfrom, mailto, origin_domain = examine_headers.processing()
    indicators += examine_headers.indicators

    attachements = []
    payload_results = []
    suspicious_urls = set()

    if msg.content_type.is_multipart():
        for p in msg.walk():
            if p.is_body():
                extract_urls = ExtractURL(p.body, origin_domain)
                suspicious_urls |= set(extract_urls.processing())
                indicators += extract_urls.indicators
                content = p.body
                tok = Tokenizer(content)
                passwordlist += tok.processing()
                # TODO process that string
            elif p.is_attachment() or p.is_inline():
                process_attachement(p, origin_domain)
            else:
                # What do we do there? Is it possible?
                pass
    else:  # singlepart
        extract_urls = ExtractURL(msg.body, origin_domain)
        suspicious_urls |= set(extract_urls.processing())
        indicators += extract_urls.indicators

    if args.o == 'json':
        print((json.dumps((payload_results, suspicious_urls, indicators), indent=4)))
        sys.exit()

    print(("Email abuse - inspecting email object: %s\n" % msg_file))
    print("\tContent type:\tEmail info")
    print("\tIP Address:\t%s" % origin_ip)
    print("\tSubject:\t%s" % subject)
    print("\tFrom:\t\t%s" % mailfrom)
    print("\tTo:\t\t%s" % mailto)
    if rbl_comment is not None:
        print("\tSuspicious:\t%s" % rbl_comment)
    if len(attachements) > 0:
        print("\tAttachements:")
        for fn, content_type in attachements:
            print("\t\t%s:\t%s" % (fn, str(content_type)))
    print("\n")
    i = 0
    for results in payload_results:
        for filename, infos in list(results.items()):
            i += 1
            print("Inspected component #%i:" % i)
            print("\tMime-type:\t%s" % infos[2])
            print("\tFile name:\t%s - %s" % (filename, infos[1]))
            print("\tSHA1 hash:\t%s" % infos[3])
            for parser, values in list(infos[5].items()):
                if len(values) == 5 and values[4] is not None:
                    for name, detail in values[4]:
                        print("\t%s:\t%s" % (name, detail))
                if values[0] and values[2]:
                    # one of the parser worked, and the content is suspicious
                    print("\tSuspicious:\t%s" % values[3])
            if infos[6][0]:
                print("\tVirus Total:\t%i positive detections (total scans: %i)" % (int(infos[6][1]), int(infos[6][2])))
                print("\tVT Report\t%s" % str(infos[6][3].strip()))
            print("\n")
    if len(suspicious_urls) > 0:
        print("List of extracted suspicious URLs:")
        for url in suspicious_urls:
            print("\t%s" % url)
    print("\nLevel of suspiciousness:\t%i" % indicators)
