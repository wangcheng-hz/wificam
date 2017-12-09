#!/usr/bin/env python

import syslog

def debug(s):
    syslog.syslog(syslog.LOG_DEBUG, s)

def info(s):
    syslog.syslog(syslog.LOG_INFO, s)

def warn(s):
    syslog.syslog(syslog.LOG_WARNING, s)

def err(s):
    syslog.syslog(syslog.LOG_ERR, s)