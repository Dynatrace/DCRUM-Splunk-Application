#!/usr/bin/env python
#
# Copyright 2013 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import os

import sys
import logging
import logging.handlers

from dynatrace.dcrum import splunk
from splunklib.modularinput import *

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

def isgoodipv4(s):
    pieces = s.split('.')
    if len(pieces) != 4: return False
    try: return all(0<=int(p)<256 for p in pieces)
    except ValueError: return False
	
	
class MyScript(Script):

    def get_scheme(self):
        scheme = Scheme("Dynatrace DC-RUM CAS Input")

        scheme.description = "Streams events from Dynatrace DC-RUM CAS's."
        scheme.use_external_validation = True
        scheme.use_single_instance = True

        ip_argument = Argument("ip")
        ip_argument.data_type = Argument.data_type_string
        ip_argument.description = "CAS's IP address"
        ip_argument.required_on_create = True
        scheme.add_argument(ip_argument)

        port_argument = Argument("port")
        port_argument.data_type = Argument.data_type_number
        port_argument.description = "CAS's TCP port number"
        port_argument.required_on_create = True
        scheme.add_argument(port_argument)

        secure_argument = Argument("secure")
        secure_argument.data_type = Argument.data_type_boolean
        secure_argument.description = "Is connection over SSL (0|1)?"
        secure_argument.required_on_create = True
        scheme.add_argument(secure_argument)
        
        login_argument = Argument("login")
        login_argument.data_type = Argument.data_type_string
        login_argument.description = "Login to CAS"
        login_argument.required_on_create = False
        scheme.add_argument(login_argument)

        password_argument = Argument("password")
        password_argument.data_type = Argument.data_type_string
        password_argument.description = "And corresponding password"
        password_argument.required_on_create = False
        scheme.add_argument(password_argument)

        defaultReport_argument = Argument("defaultReport")
        defaultReport_argument.data_type = Argument.data_type_boolean
        defaultReport_argument.description ="Enable default report?"
        defaultReport_argument.required_on_create = True
        scheme.add_argument(defaultReport_argument)

        customReports_argument = Argument("customReports")
        customReports_argument.data_type = Argument.data_type_boolean
        customReports_argument.description ="Enable custom reports?"
        customReports_argument.required_on_create = True
        scheme.add_argument(customReports_argument)

        custom_reports_list_argument = Argument("customReportsList")
        custom_reports_list_argument.data_type = Argument.data_type_string
        custom_reports_list_argument.description ="Enter report names (separated by comma)"
        custom_reports_list_argument.required_on_create = False
        scheme.add_argument(custom_reports_list_argument)

        return scheme

        
    def validate_input(self, validation_definition):
        ip = validation_definition.parameters["ip"]
        # if not isgoodipv4(ip): raise ValueError("%s is not valid IP address" % ip)
        
        port = validation_definition.parameters["port"]
        try:
            if not 0<=int(port)<65000: raise ValueError("%s is not valid TCP port number" % port)   
        except ValueError: raise ValueError("%s is not valid TCP port number" % port)   

        secure = validation_definition.parameters["secure"]
        try:
            if not 0<=int(secure)<=1: raise ValueError("\"secure\" flag should be 0 or 1")   
        except ValueError: raise ValueError("\"secure\" flag should be 0 or 1 (%s)" % secure)   
        
        defaultReport = validation_definition.parameters["defaultReport"]
        try:
            if not 0<=int(defaultReport)<=1: raise ValueError("\"defaultReport\" flag should be 0 or 1")
        except ValueError: raise ValueError("\"defaultReport\" flag should be 0 or 1 (%s)" % secure)

        customReports = validation_definition.parameters["customReports"]
        try:
            if not 0<=int(customReports)<=1: raise ValueError("\"customReports\" flag should be 0 or 1")
        except ValueError: raise ValueError("\"customReports\" flag should be 0 or 1 (%s)" % secure)
		
    def stream_events(self, inputs, ew):
        self.create_logger()
        manager = splunk.CASManager()

        for input_name, input_item in inputs.inputs.iteritems():
            ip = input_item["ip"]
            sec = bool(int(input_item["secure"]))
            port = int(input_item["port"])
            login = input_item["login"]
            password = input_item["password"]

            defaultReportVal = "Splunk_Analysis_by_Tier"
            defaultReport = bool(int(input_item["defaultReport"]))
            customReports = bool(int(input_item["customReports"]))


            reportsList = []

            if customReports:
                customReportsList = input_item["customReportsList"]
                 #Splitting reports by ;
                reportsList = customReportsList.split(";")
            if defaultReport:
                reportsList.append(defaultReportVal)

            #Make list distinct
            reportsList = list(set(reportsList))

            cas = splunk.CASProcessor(input_name, ip, port, sec, login, password, reportsList)
            cas.use_with_splunk(ew)

            manager.add_cas(cas)

        manager.run()

    def create_logger(self):
        fmt = '%(levelname)s %(asctime)-15s %(message)s'
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "processor.log")

        logger = logging.getLogger('dcrum.cas.input')
        logger.setLevel(logging.INFO)

        file_handler = logging.handlers.RotatingFileHandler(path, 10485760, 20)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter(fmt))

        logger.addHandler(file_handler)

        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter(fmt))
        logger.addHandler(console)		

if __name__ == "__main__":
    sys.exit(MyScript().run(sys.argv))
