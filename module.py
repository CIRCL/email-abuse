#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pyfaup.faup import Faup
import re
import py7zlib
import os
import logging
import email
import StringIO
import zipfile
import olefile
from oletools import oleid
import tempfile
import pdfid_PL
import xml.etree.ElementTree as ET
import base64
import zlib
import hashlib
import nltk
import requests
import magic
from rblwatch import RBLSearch
from flanker.addresslib import address
import rarfile


# We do not want to initialize it twice.
f = Faup()


class EmailAbuseError(Exception):
    def __init__(self, message):
        super(EmailAbuseError, self).__init__(message)
        self.message = message


class ImplementationRequired(EmailAbuseError):
    pass


class DecodeError(EmailAbuseError):
    pass


class ArchiveError(EmailAbuseError):
    pass


class TokenizeError(EmailAbuseError):
    pass


class VirusTotalError(EmailAbuseError):
    pass


class ExamineHeaderError(EmailAbuseError):
    pass


class Module(object):

    def __init__(self, name, logname, logpath='store'):
        self.name = name
        self.logname = logname
        self.indicators = 0
        self.loginit(logname, logpath)
        logging.info("{}: initializing".format(self.name))

    def loginit(self, logname, logpath):
        logfile = os.path.join(logpath, logname + '.log')
        logformat = '%(asctime)s - %(message)s'
        logging.basicConfig(format=logformat, filename=logfile, level=logging.DEBUG)
        logging.getLogger(logname)

    def _processing(self):
        raise ImplementationRequired('You have to implement the processing method in the module {}'.format(self.name))

    def finished(self):
        logging.info("{}: exiting".format(self.name))

    def result(self):
        raise ImplementationRequired('You have to implement the result method in the module {}'.format(self.name))

    def processing(self):
        failed = False
        try:
            self._processing()
        except Exception as e:
            failed = True
            logging.exception(e)
        finally:
            self.finished()
            if failed:
                return None
            return self.result()


class VirusTotal(Module):

    def __init__(self, payload_hash, logname):
        super(VirusTotal, self).__init__('VirusTotal', logname)
        self.vturl = "https://www.virustotal.com/vtapi/v2/file/report"
        self.vtkey = open('virustotal.key', 'r').readline().strip()
        self.vtparameter = {"resource": None, "apikey": self.vtkey}
        self.payload_hash = payload_hash
        self.known = False
        self.positives = 0
        self.total = 0
        self.vtlink = None

    def result(self):
        return self.known, self.positives, self.total, self.vtlink

    def _processing(self):
        self.vtparameter['resource'] = self.payload_hash
        try:
            response = requests.post(url=self.vturl, data=self.vtparameter)
        except Exception as e:
            raise VirusTotalError(e)
        res = response.json()
        if res["response_code"] == 0:
            logging.info("%s: not in VirusTotal DB" % self.name)
            return
        self.known = True
        logging.info("%s: sample known in VirusTotal DB" % self.name)
        self.vtlink = res.get("permalink")
        self.positives = res.get("positives")
        self.total = res.get("total")
        if self.positives > 0:
            logging.info("%s: found positive match in VirusTotal DB" % self.name)
            self.indicators += 3
        else:
            logging.info("%s: found no positive matches in VirusTotal DB" % self.name)


class Tokenizer(Module):

    def __init__(self, content, logname):
        super(Tokenizer, self).__init__('Tokenizer', logname)
        self.content = content
        self.passwordlist = []

    def result(self):
        return self.passwordlist

    def _processing(self):
        try:
            self.passwordlist = nltk.word_tokenize(self.content)
            wlen = len(self.passwordlist)
            logging.info("%s: added words to wordlist (total: %i)" % (self.name, wlen))
        except Exception as e:
            TokenizeError(e)
        self.passwordlist = list(set(self.passwordlist))
        for word in self.passwordlist:
            if word is "'":
                self.passwordlist.remove(word)
            if word is "":
                self.passwordlist.remove(word)
            if word.startswith("'"):
                self.passwordlist.append(word[1:])


class ExtractURL(Module):

    def __init__(self, content, origin_domain, logname):
        super(ExtractURL, self).__init__('Extract-URLs', logname)
        self.content = content
        self.file_excludes = (".png", ".jpg", ".svg", ".gif")
        self.domain_excludes = ["w3.org", "akamai.net", "norton.com", "facebook.com",
                                "orange.fr", "rt", "microsoft.com", "amazon.com",
                                "amazon.de", "images-amazon.com", "adobe.com", "purl.org"]

        self.origin_domain = origin_domain
        self.suspicious_urls = []

    def result(self):
        return self.suspicious_urls

    def _processing(self):
        if self.content is not None:
            url_list = re.findall(r'(?P<url>https?://[^\s><\]\)"]+)', self.content)
            for url in list(set(url_list)):
                url = url.strip('\x00')
                f.decode(url)
                domain = f.get_domain()
                if (not url.endswith(self.file_excludes)
                        and domain != self.origin_domain
                        and domain not in self.domain_excludes):
                    self.suspicious_urls.append(url)
                    logging.info("%s: successfully extracted URLs" % self.name)
                else:
                    logging.info("%s: URL %s not suspicious" % (self.name, url))
            self.indicators = len(self.suspicious_urls)


class ExamineHeaders(Module):

    def __init__(self, message, logname):
        super(ExamineHeaders, self).__init__('Header-examination', logname)
        self.message = message
        self.origin_ip = None
        self.origin_domain = None
        self.rbl_listed = False
        self.rbl_comment = None

        self.mailfrom = None
        self.mailto = None
        self.origin_domain = None

    def result(self):
        return self.origin_ip, self.rbl_listed, self.rbl_comment, self.mailfrom, self.mailto, self.origin_domain

    def extract_ip(self, h):
        m = re.search('\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', h)
        if m:
            ip = m.group(1)
            logging.info("%s: found IP: %s" % (self.name, ip))
            return ip
        logging.info("%s: no IP found" % self.name)

    def rbl_lookup(self):
        searcher = RBLSearch(self.origin_ip)
        self.result_data = searcher.listed
        if self.result_data:
            for blacklist, value in self.result_data.iteritems():
                if isinstance(value, dict) and value.get('LISTED'):
                    self.rbl_listed = True
                    self.rbl_comment = 'is on SMTP blacklists'
        if self.rbl_listed:
            logging.info("%s: found a hit on blacklist for IP %s" % (self.name, self.origin_ip))
            self.indicators += 2
        else:
            logging.info("%s: IP %s not on blacklists" % (self.name, self.origin_ip))

    def _processing(self):
        recvd_header = []
        try:
            for x in self.message.headers.getall('Received'):
                recvd_header.append(x)
            ip = None
        except Exception as e:
            raise ExamineHeaderError(e)
        for h in reversed(recvd_header):
            ip = self.extract_ip(h)
            if ip is None:
                continue
            if not ip.startswith(("127.", "192.168.", "10.")) \
                    and not re.search('(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)', ip):
                self.origin = h
                self.origin_ip = ip
                break

        if self.origin_ip is not None:
            logging.info("%s: Found IP address (%s), passing to module RBL lookup" % (self.name, ip))
            self.rbl_lookup()

        self.mailfrom = self.message.headers.get('From')
        if email is not None:
            parsed = address.parse(self.mailfrom)
            if parsed is not None:
                f.decode(parsed.hostname)
                self.origin_domain = f.get_domain()

        self.mailto = self.message.headers.get('To')


class ParseOLE(Module):

    def __init__(self, content, logname):
        """
            content has to be a stream in memory
        """
        super(ParseOLE, self).__init__('Parse-OLE', logname)
        self.content = content
        self.is_ole = False
        self.has_parsed = False
        self.is_suspicious = False
        self.reason = None
        self.oleid_details = []

    def result(self):
        return self.is_ole, self.has_parsed, self.is_suspicious, self.reason, self.oleid_details

    def _processing(self):
        if self.content is None or len(self.content) == 0:
            # if self.content is None or len == 0, olefile.OleFileIO doesn't crash but will fail later
            return
        try:
            ole = olefile.OleFileIO(self.content, raise_defects=olefile.DEFECT_INCORRECT)
            self.is_ole = True
        except Exception as e:
            logging.info("%s: got error while opening file: %s" % (self.name, e))
            self.reason = 'Unable to open the OLE document'
            return
        if ole.parsing_issues:
            self.is_suspicious = True
            parsing_issues = []
            for exctype, msg in ole.parsing_issues:
                logging.info('%s: Parsing issue:  %s: %s' % (self.name, exctype.__name__, msg))
                parsing_issues.append(msg)
            if len(parsing_issues) == 0:
                self.reason = 'Unknown non-fatal parsing issue'
            else:
                self.reason = "Non-fatal parsing issue: " + ', '.join(parsing_issues)
            self.indicators += 1
            logging.info("%s: OLE file with parsing issues" % self.name)
        else:
            self.has_parsed = True
            logging.info("%s: OLE content: %s" % (self.name, ole.listdir()))
            if ole.exists('macros/vba') or ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                self.is_suspicious = True
                self.reason = "contains Macros"
                self.indicators += 3
                logging.info("%s: detected a Macro" % self.name)
            else:
                logging.info("%s: file appears clean" % self.name)
        try:
            oid = oleid.OleID(StringIO.StringIO(self.content))
            oindicators = oid.check()
            for i in oindicators:
                print i.value
                if i.value and i.description:
                    self.oleid_details.append((i.name, i.description))
        except Exception as e:
            # Invalid OLE file
            logging.info("%s: OleID Failed: %s" % (self.name, e))


class ParsePDF(Module):

    def __init__(self, content, logname):
        super(ParsePDF, self).__init__('Parse-PDF', logname)
        self.content = content
        self.is_pdf = False
        self.has_parsed = False
        self.is_suspicious = False
        self.reason = None

    def result(self):
        return self.is_pdf, self.has_parsed, self.is_suspicious, self.reason

    def _processing(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(self.content)
        try:
            fc, c = pdfid_PL.PDFiD(f.name, disarm=False, output_file='/tmp/cleaned.pdf',
                                   raise_exceptions=True, return_cleaned=True,
                                   active_keywords=('/JS', '/JavaScript', '/AA',
                                                    '/OpenAction', '/JBIG2Decode',
                                                    '/RichMedia', '/Launch', '/AcroForm'))
            # TODO: make sure we have a PDF and it parsed at this point.
            self.is_pdf = True
            self.has_parsed = True
            if c:
                self.indicators += 3
                logging.info("%s: found active content in PDF" % self.name)
                self.is_suspicious = True
                self.reason = "contains active content"
        except Exception as e:
            logging.info("%s: %s" % (self.name, e))
        if os.path.exists(f.name):
            os.unlink(f.name)


class ParseOOXML(Module):

    def __init__(self, content, logname):
        super(ParseOOXML, self).__init__('Parse-OOXML', logname)
        self.content = content
        self.is_xml = False
        self.has_parsed = False
        self.is_suspicious = False
        self.reason = None
        self.ole_parser = None

    def result(self):
        return self.is_xml, self.has_parsed, self.is_suspicious, self.reason, self.ole_parser

    def _processing(self):
        try:
            root = ET.fromstring(self.content)
            self.is_xml = True
        except Exception as e:
            logging.info(e)
            self.reason = 'Unable to open the (OO)XML document'
            return
        for elem in root.iter():
            if "binData" in elem.tag:
                logging.info("%s: binData element found" % self.name)
                if "editdata.mso" in elem.attrib['{http://schemas.microsoft.com/office/word/2003/wordml}name']:
                    encoded = elem.text
                try:
                    decoded = base64.b64decode(encoded)
                except:
                    logging.info("%s: Base64 decoding failed" % self.name)
                    self.indicators += 1
                    self.is_suspicious = True
                    self.reason = 'pretends to be XML embedded binary, but decoding failed'
                    # TODO: Do we want to continue going through the document?
                    return
                header = decoded[0:10]
                if "ActiveMime" in header:
                    try:
                        logging.info("%s: ActiveMime header found" % self.name)
                        logging.info("%s: Trying to decompress element" % self.name)
                        decompressed = zlib.decompress(decoded[0x32:])
                        logging.info("%s: zlib decompression succeeded" % self.name)
                        self.has_parsed = True
                    except:
                        logging.info("%s: zlib decompression failed" % self.name)
                        self.indicators += 1
                        self.is_suspicious = True
                        self.reason = 'pretends to be ActiveMime, but decompression failed'
                        # TODO: Do we want to continue going through the document?
                        return
                    ole = ParseOLE(decompressed)
                    self.ole_parser = ole._processing()


class Payload(Module):

    def __init__(self, filename, payload, origin_domain, logname):
        super(Payload, self).__init__('Payload', logname)
        self.filename = filename
        self.suspicious_extensions = (".exe", ".com", ".scr", ".cpl", ".docm",
                                      ".jar", ".pif", ".msi", ".hta", ".msc",
                                      ".bat", ".cmd", ".vbs", ".vbe", ".vb",
                                      ".wsf", ".ws", ".jse", ".js", ".wsc",
                                      ".wsh", ".ps1", ".ps1xml", ".ps2", ".pdf",
                                      ".ps2xml", ".psc1", ".psc2", ".msh",
                                      ".msh1", ".msh2", ".mshxml", ".msh1xml",
                                      ".msh2xml", ".scf", ".lnk", ".inf",
                                      ".reg", ".doc", ".xls", ".ppt", "dll",
                                      ".docm", ".dotm", ".xlsm", ".xltm",
                                      ".xlam", ".pptm", ".potm", ".ppam",
                                      ".ppsm", ".sldm", ".application", ".gadget")
        self.payload = payload
        self.origin_domain = origin_domain
        self.is_suspicious = False
        self.reason = None
        self.sha1 = None
        self.mimetype = None
        self.suspicious_urls = []
        self.parser_results = {}
        self.vt_result = []
        self.parser_list = [ParsePDF, ParseOLE, ParseOOXML]

    def test_suspicious_extension(self):
        if self.filename.endswith((self.suspicious_extensions)):
            logging.info("%s: Suspicious file detected: '%s'" % (self.name, self.filename))
            self.indicators += 3
            self.is_suspicious = True
            self.reason = "{} is a potentially dangerous file".format(self.filename)
        else:
            logging.info("%s: no suspicious filenames detected" % self.name)

    def result(self):
        return self.is_suspicious, self.reason, self.mimetype, self.sha1, self.suspicious_urls, self.parser_results, self.vt_result

    def _processing(self):
        self.test_suspicious_extension()
        h = hashlib.sha1()
        h.update(self.payload.getvalue())
        self.sha1 = h.hexdigest()
        self.mimetype = magic.from_buffer(self.payload.getvalue())
        extract_urls = ExtractURL(self.payload.getvalue(), self.origin_domain, self.logname)
        self.suspicious_urls = extract_urls.processing()
        self.indicators += extract_urls.indicators
        vt = VirusTotal(self.sha1, self.logname)
        self.vt_result = vt.processing()
        self.indicators += vt.indicators
        for parser in self.parser_list:
            p = parser(self.payload.getvalue(), self.logname)
            self.parser_results[type(p).__name__] = p.processing()
            self.indicators += p.indicators


class Archive(Module):

    def __init__(self, name, pseudofile, passwordlist, logname):
        super(Archive, self).__init__(name, logname)
        self.pseudofile = pseudofile
        self.archive = None
        self.password_protected = False
        self.password_found = False
        self.common_pass = ["password", "passw0rd", "infected", "qwerty", "malicious", "archive", "zip", "malware"]
        self.passwordlist = self.common_pass + list(set(passwordlist))
        self.unpacked_files = {}

    def result(self):
        return self.unpacked_files


class ArchiveZip(Archive):

    def __init__(self, pseudofile, passwordlist, logname):
        pseudofile = StringIO.StringIO(pseudofile.getvalue())
        super(ArchiveZip, self).__init__('Archive-zip', pseudofile, passwordlist, logname)

    def _processing(self):
        self.archive = zipfile.ZipFile(self.pseudofile)
        if self.archive is not None and self.archive.namelist() is not None:
            logging.info("%s: Found a valid zip archive" % self.name)
            for subfile in self.archive.namelist():
                self.unpacked_files[subfile] = None
                if self.password_protected and not self.password_found:
                    logging.info("%s: encrypted file '%s' and unable to find the password." % (self.name, subfile))
                    break
                try:
                    logging.info("%s: Trying to extract %s from archive" % (self.name, subfile))
                    self.unpacked_files[subfile] = StringIO.StringIO(self.archive.open(subfile).read())
                    logging.info("%s: successfully unpacked file '%s'" % (self.name, subfile))
                except Exception as e:
                    if "encrypted" in str(e):
                        self.password_protected = True
                        logging.info("%s: encrypted file '%s' found in archive" % (self.name, subfile))
                    else:
                        raise ArchiveError(e)
                    for pw in self.passwordlist:
                        self.archive.setpassword(pw)
                        try:
                            self.unpacked_files[subfile] = StringIO.StringIO(self.archive.open(subfile).read())
                            self.password_found = True
                            logging.info("%s: found password: %s" % (self.name, pw))
                            break
                        except Exception as e:
                            if "Bad password" in str(e):
                                logging.info("%s: error: %s while trying password '%s'" % (self.name, e, pw))
                            elif "encrypted" in str(e):
                                # Empty password...
                                continue
                            elif "invalid distance too far back" in str(e):
                                # Password seen as correct but is not...
                                continue
                            else:
                                raise ArchiveError(e)
            self.archive.close()
            self.pseudofile.close()


class Archive7z(Archive):

    def __init__(self, pseudofile, passwordlist, logname):
        # Note: lzma has 2 possibilities for the encryption: listing encrypted or not
        # if the listing is encrypted, we get a NoPasswordGivenError when calling the class,
        # If not, we get the NoPasswordGivenError when reading the file.
        pseudofile = StringIO.StringIO(pseudofile.getvalue())
        super(Archive7z, self).__init__('Archive-7z', pseudofile, passwordlist, logname)

    def _processing(self):
        try:
            self.archive = py7zlib.Archive7z(self.pseudofile)
        except py7zlib.NoPasswordGivenError:
            # File listing encrypted
            self.password_protected = True
            logging.info("%s: Archive is password protected" % self.name)
            for pw in self.passwordlist:
                try:
                    self.pseudofile.seek(0)
                    self.archive = py7zlib.Archive7z(self.pseudofile, password=pw)
                    # self.unpacked_files[subfile] = self.archive.getmember(subfile).read()
                    self.password_found = True
                    logging.info("%s: found password: %s" % (self.name, pw))
                    break
                except py7zlib.WrongPasswordError as e:
                    logging.info("%s: error: %s while trying password '%s'" % (self.name, e, pw))
                except py7zlib.NoPasswordGivenError:
                    continue
                except Exception as e:
                    raise ArchiveError(e)
        if self.password_protected and not self.password_found:
            # Password not found
            logging.info("%s: encrypted file and unable to find the password." % (self.name))
        else:
            # File listing not password protected or password found, trying to unpack
            if self.archive is not None and self.archive.getnames() is not None:
                logging.info("%s: Found a valid 7z archive" % self.name)
                filenames = self.archive.getnames()
                for subfile in filenames:
                    self.unpacked_files[subfile] = None
                    if self.password_protected and not self.password_found:
                        continue
                    try:
                        logging.info("%s: Trying to extract %s from archive" % (self.name, subfile))
                        self.unpacked_files[subfile] = StringIO.StringIO(self.archive.getmember(subfile).read())
                        logging.info("%s: successfully unpacked file '%s'" % (self.name, subfile))
                    except py7zlib.NoPasswordGivenError:
                        # Files in the archive encrypted
                        self.password_protected = True
                        for pw in self.passwordlist:
                            try:
                                self.pseudofile.seek(0)
                                self.archive = py7zlib.Archive7z(self.pseudofile, password=pw)
                                self.unpacked_files[subfile] = StringIO.StringIO(self.archive.getmember(subfile).read())
                                self.password_found = True
                                logging.info("%s: found password: %s" % (self.name, pw))
                                break
                            except py7zlib.WrongPasswordError as e:
                                logging.info("%s: error: %s while trying password '%s'" % (self.name, e, pw))
                            except py7zlib.NoPasswordGivenError:
                                continue
                            except Exception as e:
                                raise ArchiveError(e)
        self.pseudofile.close()


class ArchiveRAR(Archive):

    def __init__(self, pseudofile, passwordlist, logname):
        super(ArchiveRAR, self).__init__('Archive-rar', pseudofile, passwordlist, logname)

    def _processing(self):
        # rarfile.RarFile requires an actual file tu unpack (it uses unrar in a shell)
        fd, filepath = tempfile.mkstemp()
        os.write(fd, self.pseudofile.getvalue())
        os.close(fd)
        self.pseudofile.close()

        self.archive = rarfile.RarFile(filepath)
        if self.archive is not None:
            if self.archive.needs_password():
                self.password_protected = True
                logging.info("%s: Archive is password protected" % self.name)
                for pw in self.passwordlist:
                    try:
                        self.archive.setpassword(pw)
                        if len(self.archive.namelist()) == 0:
                            # Wrong password...
                            raise rarfile.BadRarFile('Still wrong password...')
                        self.password_found = True
                        logging.info("%s: found password: %s" % (self.name, pw))
                        break
                    except rarfile.BadRarFile as e:
                        if "wrong password" in str(e):
                            logging.info("%s: error: %s while trying password '%s'" % (self.name, e, pw))
                            # This is somehow needed.
                            self.archive.close()
                            self.archive = rarfile.RarFile(filepath)
                        else:
                            raise ArchiveError(e)
                    except Exception as e:
                        raise ArchiveError(e)

            if self.password_protected and not self.password_found:
                # Have to change the messsage: the file list is unknown, so no subfile
                logging.info("%s: encrypted file and unable to find the password." % (self.name))
                return
            for f in self.archive.infolist():
                subfile = f.filename
                self.unpacked_files[subfile] = None
                try:
                    logging.info("%s: Trying to extract %s from archive" % (self.name, subfile))
                    self.unpacked_files[subfile] = StringIO.StringIO(self.archive.open(f).read())
                    logging.info("%s: successfully unpacked file '%s'" % (self.name, subfile))
                except Exception as e:
                    raise ArchiveError(e)
            self.archive.close()
            os.remove(filepath)
