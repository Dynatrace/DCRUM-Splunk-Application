import os
from splunklib.modularinput import *

__author__ = 'Kris Hoja'

import logging
import ConfigParser
import urllib2
import time


class CASStateFile(object):
    def __init__(self):
        self.logger = logging.getLogger('dcrum.cas.input')
        self.FILE_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cas.cfg")
        self.config = ConfigParser.SafeConfigParser()
        try:
            self.config.readfp(open(self.FILE_NAME))
            self.logger.info('Read configuration from %s' % self.FILE_NAME)
        except StandardError:
            try:
                with open(self.FILE_NAME, 'wb') as configfile:
                    self.config.write(configfile)
            except StandardError:
                self.logger.info('Could not create configuration file %s' % self.FILE_NAME)

    def read_state(self, id1, ft):
        if not self.config.has_section(id1):
            return 0
        if not self.config.has_option(id1, ft):
            return 0
        return self.config.getint(id1, ft)

    def save_state(self, id1, ft, ts):
        if not self.config.has_section(id1):
            self.config.add_section(id1)
        self.config.set(id1, ft, str(ts))
        try:
            with open(self.FILE_NAME, 'wb') as configfile:
                self.config.write(configfile)
        except StandardError:
            self.logger.error('could not create configuration file')


class FileName(object):
    def __init__(self, filename):
        parts = filename.split("_")
        tmpParts = parts[0:-3]
        self.file_type = '_'.join(map(str, tmpParts))
        self.timestamp = int(parts[-3], 16)
        self.interval = parts[-2].strip()
        self.content_type = parts[-1].strip()

    def __repr__(self):
        return '%s_%s_%s_%s' % (self.file_type, format(self.timestamp, 'x'), self.interval, self.content_type)

    def __cmp__(self, other):
        td = self.timestamp - other.timestamp
        if td != 0:
            return td
        if self.file_type > other.file_type:
            return 1
        if self.file_type < other.file_type:
            return -1
        return 0


class FileObject(object):
    def __init__(self, filename1, cas_processor1):
        self.filename = filename1
        self.cas_processor = cas_processor1

    def __cmp__(self, other):
        c = self.filename.__cmp__(other.filename)
        if c != 0:
            return c
        return self.cas_processor.__cmp__(other.cas_processor)

    def __repr__(self):
        return '[%s %s]\n' % (self.filename, self.cas_processor)


class CASProcessor(object):
    def __init__(self, id1, ip1, port1, secure1, login1, password1, reportsList1):
        self.logger = logging.getLogger('dcrum.cas.input')
        self.id = id1
        self.reportsList = list(reportsList1)
        self.top_level_url = ip1 + ":" + str(port1) + "/"
        if secure1:
            self.top_level_url = "https://" + self.top_level_url
        else:
            self.top_level_url = "http://" + self.top_level_url

        # TODO temporary tomcat solution
        if port1 == 8080:
            self.top_level_url += "servletApp/"
        self.logger.info('Adding CAS %s:%s to a list of known CASes' % (ip1, port1))
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, self.top_level_url, login1, password1)

        handler = urllib2.HTTPBasicAuthHandler(password_mgr)
        # create "opener" (OpenerDirector instance)
        self.opener = urllib2.build_opener(handler)
        urllib2.install_opener(self.opener)
        self.state = None
        self.ew = None

        self.files = {}
        self.omitted = 0

    def __repr__(self):
        return '%s (%s) %s' % (self.id, self.top_level_url, self.files.__repr__())

    def __cmp__(self, other):
        return self.top_level_url < other.top_level_url

    def use_with_splunk(self, ew):
        self.ew = ew

    def set_file_type(self, ft):
        if self.state is None:
            self.files[ft] = 0
        else:
            self.files[ft] = self.state.read_state(self.id, ft)

    def set_state_file(self, state1):
        self.state = state1
        for ft in self.files:
            self.files[ft] = self.state.read_state(self.id, ft)

    def process_file(self, filename):
        self.omitted = 0
        try:
            self.files[filename.file_type] = filename.timestamp
            #process file
            linecount = self.get_file(filename)
            #save processing state
            self.state.save_state(self.id, filename.file_type, filename.timestamp)
            if self.omitted != 0:
                self.logger.warn('Omitted %s incorrect lines' % self.omitted)
            return linecount
        except StandardError as e:
            self.logger.error('Cannot process file content %s from %s (%s) -> %s'
                              % (filename, self.id, self.top_level_url, e))
            # error reading file - skip the file for next runs
            return -1

    def get_current_dir(self):
        ll = []

        # for timestamp in self.files.iteritems():

        self.logger.info('Getting directory from %s (%s)' % (self.id, self.top_level_url))
        l = self.get_dir()
        for f in l:
            ll.append(FileObject(f, self))
        ll.sort()

        self.logger.info('%s files found on %s (%s)' % (len(ll), self.id, self.top_level_url))
        return ll

    def get_dir(self):
        # use the opener to fetch a URL
        try:

            url = "%sRtmDataAPIServlet?cmd=get_dir" % (self.top_level_url)
            self.logger.info('URL IS: %s' % (url))

            response = self.opener.open(url)
            # response = urllib2.urlopen(url)
            file_list = []
            for line in response:
                file_list.append(FileName(line))
            file_list.sort()
            return file_list
        except urllib2.HTTPError as e:
            self.logger.error('HTTP error %s while downloading directory content to %s (%s)'
                              % (e.code, self.id, self.top_level_url))
            return []
        except StandardError as e:
            self.logger.error('Cannot download directory content to %s (%s) -> %s' % (self.id, self.top_level_url, e))
            return []

    def process_record(self, header, record, filename):

        if len(header) != len(record) and len(header) != len(record) - 1:
            self.omitted += 1
            return
        event = str(1000 * filename.timestamp)
        event += ", model=" + filename.file_type

        for i in range(len(header)):
            parts = header[i].split(':')
            if not record[i] is "-" and "timestamp" not in parts[0]:
                event = event + " " + parts[0] + "=" + record[i]

        if self.ew is not None:
            e = Event()
            e.stanza = self.id
            e.data = event
            self.ew.write_event(e)
            # else - TCP input

    def get_file(self, file_name):
        filename = str(file_name)
        url = "%sRtmDataAPIServlet?cmd=get_entry&entry=%s" % (self.top_level_url, filename)
        try:
            self.logger.info('Getting file: %s' % url)
            #get file from server
            response = self.opener.open(url)
        except urllib2.HTTPError as e:
            self.logger.error('HTTP error %s while getting file %s from %s (%s)'
                              % (e.code, filename, self.id, self.top_level_url))
            return -1
        except StandardError as e:
            self.logger.error('Cannot get file %s from %s (%s) -> %s' % (filename, self.id, self.top_level_url, e))
            return -1
        headers = {}
        # line count
        processed_data_lines = 0
        # ignored lines
        processed_header_lines = 0

        prefix = "# Fields:"
        type_prefix = "type="
        for line in response:

            if line.startswith(prefix):
                line = line[len(prefix):].strip()
                header = line.split(' ')
                if len(header) > 0 and header[0].startswith(type_prefix):
                    headers[header[0][len(type_prefix):]] = header
                    header[0] = type_prefix[:-1]
                else:
                    headers[""] = header
            elif line.startswith('#'):
                processed_header_lines += 1
            else:
                processed_data_lines += 1
                record = line.split(' ')
                recordtype = record[0]
                if recordtype in headers:
                    header = headers.get(recordtype, [])
                    self.process_record(header, record, file_name)
                elif "" in headers:
                    record = line.split(' ')
                    self.process_record(headers[""], record, file_name)
        logging.getLogger('dcrum.cas.input').info('Amount of ignored lines: %d ' % processed_header_lines)
        return processed_data_lines


class CASManager(object):
    def __init__(self):
        self.state_file = CASStateFile()
        self.cas_list = {}

    def add_cas(self, cas_processor):
        cas_processor.set_state_file(self.state_file)
        self.cas_list[cas_processor.id] = cas_processor

    def process_files(self):
        files_to_process = []
        for cas_id, cas in self.cas_list.iteritems():
            cas_dir_content = cas.get_current_dir()
            files_to_process.extend(cas_dir_content)
        files_to_process.sort()
        for file_to_process in files_to_process:
            res = self.state_file.read_state(file_to_process.cas_processor.id, file_to_process.filename.file_type)
            configuredReportNames = list(file_to_process.cas_processor.reportsList)
            if file_to_process.filename.file_type in configuredReportNames and file_to_process.filename.timestamp > res:
                processed_lines = file_to_process.cas_processor.process_file(file_to_process.filename)
                if processed_lines > 0:
                    logging.getLogger('dcrum.cas.input').info('Processed %s records from %s on %s' % (processed_lines, file_to_process.filename, file_to_process.cas_processor.id))
                else:
                    return processed_lines

        #nothing was done. Return -1 so that script can sleep for a while
        logging.getLogger('dcrum.cas.input').info('No data files to process...')
        return -1

    def run(self):
        loopCounter = 0
        while True:
            logging.getLogger('dcrum.cas.input').debug('Loop no.: %s' % loopCounter)
            processed_lines = self.process_files()
            loopCounter += 1
            if processed_lines <= 0:
                logging.getLogger('dcrum.cas.input').info('Sleeping')
                time.sleep(60)
