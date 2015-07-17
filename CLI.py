#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import sys
from flanker import mime
from settings import REDIS_HOST, REDIS_PORT, REDIS_DB
import redis
import time

from rq import Queue
from rq.job import Job

from emailabuse import store_mail, process_headers, process_content


def print_payload_details(details):
    if len(details) == 0:
        return
    if details[0]:
        print("\t%s" % details[1])
    print("\tType detail:\t%s" % details[2])
    if details[3] == "da39a3ee5e6b4b0d3255bfef95601890afd80709":
        # Empty file
        print("\n")
        return

    print("\tSHA1 hash:\t%s" % details[3])
    # parsers informations (*office + PDF)
    for parser, values in list(details[5].items()):
        if values is None:
            continue
        if len(values) == 5 and values[4] is not None:
            for name, detail in values[4]:
                print("\t%s:\t%s" % (name, detail))
        if values[0] and values[2]:
            # one of the parser worked, and the content is suspicious
            print("\tSuspicious:\t%s" % values[3])
    # VT information
    if details[6] is not None and details[6][0]:
        print("\tVirus Total:\t%i positive detections (total scans: %i)" % (int(details[6][1]), int(details[6][2])))
        print("\tVT Report\t%s" % str(details[6][3].strip()))
    print("\n")


if __name__ == '__main__':
    argParser = argparse.ArgumentParser(description='email_abuse parser')
    argParser.add_argument('-s', '--store_path', default='store', help='Path where to store the mails and the logs')
    argParser.add_argument('-r', default='-', help='Filename of the raw email to read (default: stdin)')
    argParser.add_argument('-o', default='ascii', help='Output format: ascii or json (default: ascii)')
    args = argParser.parse_args()
    if args.r == '-':
        msg = mime.from_string(sys.stdin.read())
    else:
        fp = open(args.r, 'rb')
        msg = mime.from_string(fp.read())

    redis_conn = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
    q = Queue(connection=redis_conn)
    result, sha, errormsg = store_mail(args.store_path, msg.to_string())

    subject = msg.subject
    indicators = 0

    subject, origin_ip, rbl_listed, rbl_comment, mailfrom, mailto, origin_domain, ind = process_headers(sha, args.store_path)
    indicators += ind
    ind, suspicious_urls, pending_jobs = process_content(sha, origin_domain, args.store_path)
    indicators += ind

    print(("Email abuse - inspecting email object: %s\n" % sha))
    print("\tContent type:\tEmail info")
    print("\tIP Address:\t%s" % origin_ip)
    print("\tSubject:\t%s" % subject)
    print("\tFrom:\t\t%s" % mailfrom)
    print("\tTo:\t\t%s" % mailto)
    if rbl_comment is not None:
        print("\tSuspicious:\t%s" % rbl_comment)
    print("\n")

    output = {jid: None for jid in pending_jobs}

    while len(pending_jobs) > 0:
        cur_jobs = pending_jobs
        pending_jobs = []

        for j in cur_jobs:
            job = Job.fetch(j, connection=redis_conn)
            if not job.is_finished:
                pending_jobs.append(j)
                time.sleep(.1)
                continue
            output[j] = job.result

    payload_results = []
    for j, result in output.items():
        # FIXME: use is_archive
        ind, urls, is_archive, r = result
        indicators += ind
        suspicious_urls += urls
        payload_results.append(r)

    i = 0
    for results in payload_results:
        for payload in results:
            i += 1
            print("Inspected component #%i:" % i)
            print("\tMime-type:\t%s" % payload['content_type'])
            print("\tFile name:\t%s" % payload['filename'])
            print_payload_details(payload[payload['filename']])
            for key, value in payload.items():
                if key in ['content_type', 'filename', payload['filename']]:
                    continue
                if key != payload['filename']:
                    print("\t%s is an archive, contains: %s" % (payload['filename'], key))
                print_payload_details(value)
    if len(suspicious_urls) > 0:
        print("List of extracted suspicious URLs:")
        for url in suspicious_urls:
            print("\t%s" % url)
    print("\nLevel of suspiciousness:\t%i" % indicators)
