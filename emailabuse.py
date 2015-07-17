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


from flanker import mime
from flanker.mime.message.errors import DecodingError
import os
from module import Payload, ExamineHeaders, ExtractURL, Tokenizer, ArchiveZip, \
    Archive7z, ArchiveRAR
from io import BytesIO
import hashlib
from settings import REDIS_HOST, REDIS_PORT, REDIS_DB
import redis


redis_conn = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)


# Rq stuff
from rq.decorators import job


def hash_mail(mail):
    sha = hashlib.sha1()
    sha.update(mail)
    return sha.hexdigest()


def store_mail(store, mail):
    try:
        if not os.path.exists(store):
            os.makedirs(store)
        sha = hash_mail(mail)
        filename = os.path.join(store, sha)
        if not os.path.exists(filename):
            with open(filename, 'wb') as f:
                f.write(mail)
        return True, sha, None
    except Exception as e:
        return False, None, str(e)


def process_headers(sha, store):
    mailpath = os.path.join(store, sha)
    if os.path.exists(mailpath):
        with open(mailpath, 'rb') as f:
            mail = mime.from_string(f.read())
            examine_headers = ExamineHeaders(mail, sha)
            origin_ip, rbl_listed, rbl_comment, mailfrom, mailto, origin_domain = examine_headers.processing()
            return (mail.subject, origin_ip, rbl_listed, rbl_comment, mailfrom,
                    mailto, origin_domain, examine_headers.indicators)


archive_list = [ArchiveZip, Archive7z, ArchiveRAR]


def process_payload(filename, body, content_type, origin_domain, passwordlist, sha):
    print passwordlist
    is_archive = False
    results = {}
    indicators = 0

    # Initial file
    payloads = {}
    try:
        payloads[filename] = BytesIO(body)
    except:
        # broken document...
        payloads[filename] = BytesIO(body.encode('utf-16'))

    # TODO: check original attachement on VT
    # Maybe an archive
    for a in archive_list:
        archive = a(payloads[filename], passwordlist, sha)
        unpacked_files = archive.processing()
        if unpacked_files is not None and len(unpacked_files) > 0:
            is_archive = True
            payloads.update(unpacked_files)
            break
    if not is_archive:
        # Assume it is not an archive
        pass

    for fn, filehandle in list(payloads.items()):
        if filehandle is None:
            continue
        payload = Payload(fn, filehandle, origin_domain, sha)
        result = payload.processing()
        if result is not None:
            results[fn] = list(result)
        else:
            results[fn] = []
        indicators += payload.indicators
    return indicators, is_archive, results


@job('high', connection=redis_conn, timeout=120)
def process_attachement(attachment, detected_content_type, detected_file_name, origin_domain, passwordlist, sha):
    indicators = 0
    payload_results = []
    suspicious_urls = set()
    try:
        mpart_attachment = mime.from_string(attachment)
        if mpart_attachment.content_type.is_multipart():
            for p in mpart_attachment.walk():
                detected_content_type = str(p.detected_content_type)
                filename = detected_file_name
                ind, s_urls, payload_r = process_attachement(p.body, detected_content_type, filename, origin_domain, passwordlist, sha)
                indicators += ind
                suspicious_urls |= set(s_urls)
                payload_results += payload_r
    except DecodingError:
        # Binary attachement
        pass
    extract_urls = ExtractURL(attachment, origin_domain, sha)
    suspicious_urls |= set(extract_urls.processing())
    indicators += extract_urls.indicators
    content_type = detected_content_type
    filename = detected_file_name
    if filename is not None and len(filename) > 0:
        passwordlist.append(filename)
        prefix, suffix = os.path.splitext(filename)
        passwordlist.append(prefix)
    passwordlist = [i for i in passwordlist if len(i) > 1]
    r_indicators, is_archive, r = process_payload(filename, attachment, content_type, origin_domain, passwordlist, sha)
    r['filename'] = filename
    r['content_type'] = content_type
    indicators += r_indicators
    payload_results.append(r)
    return indicators, list(suspicious_urls), is_archive, payload_results


def process_text(body, origin_domain, sha):
    extract_urls = ExtractURL(body, origin_domain, sha)
    suspicious_urls = set(extract_urls.processing())
    indicators = extract_urls.indicators
    tok = Tokenizer(body, sha)
    passwordlist = tok.processing()
    return indicators, list(suspicious_urls), passwordlist


def process_content(sha, origin_domain, store):
    mailpath = os.path.join(store, sha)
    jids = []
    indicators = 0
    suspicious_urls = []
    passwordlist = []
    if os.path.exists(mailpath):
        with open(mailpath, 'rb') as f:
            msg = mime.from_string(f.read())
            if msg.content_type.is_multipart():
                for p in msg.walk():
                    if p.is_body():
                        ind, urls, pwlist = process_text(p.body, origin_domain, sha)
                        indicators += ind
                        suspicious_urls += urls
                        passwordlist += pwlist
                    else:
                        detected_content_type = str(p.detected_content_type)
                        detected_file_name = p.detected_file_name
                        j = process_attachement.delay(p.body, detected_content_type, detected_file_name, origin_domain, passwordlist, sha)
                        jids.append(j.get_id())
            else:
                indicators, suspicious_urls, passwordlist = process_text(msg.body, origin_domain, sha)
    return indicators, suspicious_urls, jids
