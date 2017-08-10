#!/usr/bin/env python

import argparse
import pymemcache
import time
from pymemcache.client.hash import HashClient
from easysnmp import snmp_get, snmp_walk, Session
from random import randint

__author__ = "Dan Walker"
__license__ = "MIT"
__version__ = "0.1.1"
__email__ = "code@danwalker.com"

# OID references
OID_IFTABLE         = '1.3.6.1.2.1.2.2.1.'
OID_IFINDEX         = OID_IFTABLE + '1.'
OID_IFDESCR         = OID_IFTABLE + '2.'
OID_IFSPEED         = OID_IFTABLE + '5.'
OID_IFADMINSTATUS   = OID_IFTABLE + '7.'
OID_IFOPERSTATUS    = OID_IFTABLE + '8.'
OID_IFINOCTET       = OID_IFTABLE + '10.' # 32-bit
OID_IFOUTOCTET      = OID_IFTABLE + '16.' # 32-bit
OID_IFHCINOCTET     = '1.3.6.1.2.1.31.1.1.1.6.'   # 64-bit ifInOctet
OID_IFHCOUTOCTET    = '1.3.6.1.2.1.31.1.1.1.10.'  # 64-bit ifOutOctet
OID_IFHIGHSPEED     = '1.3.6.1.2.1.31.1.1.1.15.'  # 64-bit ifSpeed

# convert ifDescr to ifIndex
def descrToIndex(ifDescr):
    # try and find in memcached
    try:
        ifIndex = memcacheClient.get(str(args.host) + "." + ifDescr)
        debug('ifIndex was in memcached: ' + ifIndex)
        return ifIndex
    except:
        ifIndex = None
        
    if ifIndex is None:
        debug('Could not find ifIndex in memcached for key: ' + str(args.host) + "." + ifDescr)
        
        # build the memcached friendly key
        key = str(args.host) + "." + str(cleanIfDescr(ifDescr))
        
        # try to fetch over SNMP instead      
        try:
            debug('Fetching ifDescr table over SNMP and storing in memcached')
            walk = session.walk('1.3.6.1.2.1.2.2.1.2')
        except:
            exitMessage('Could not walk remote host ifTable', 3)
                
        # for each interface returned
        for item in walk:
            # build a memcached friendly key
            new_key = str(args.host) + "." + str(cleanIfDescr(item.value))
            
            # add to memcached
            debug("Adding to memcached: " + new_key + " = " + item.oid_index)
            
            #try:
            memcacheClient.set(new_key, item.oid_index, (86400 + randint(0,1800)))
            #except:
            #    exitMessage('Could not add key "' + new_key + '" with value "' + item.oid_index + '"', 3)
                        
        # now we have all indexes stored, fetch our index from our key (which contains ifDescr)
        ifIndex = memcacheClient.get(key)
        
        if ifIndex is None:
            exitMessage('Interface not found: ' + ifDescr, 3)
                    
    debug('descrToIndex - Returning ifIndex (' + ifIndex + ') for ifDescr (' + key + ')')
    return ifIndex

# debug output 
def debug(message):
    if debugEnabled:
        print 'Debug: ' + str(message)

# exit out and display a message, default is clean exit
def exitMessage(message, code=0):
    exitCode = ['Ok', 'Warning', 'Critical', 'Unknown']
    print exitCode[code] + ' - ' + str(message)
    exit(code)

# stackoverflow 354038
def isNumber(s):
    if s is None:
        return False
    else:
        try:
            float(s)
            return True
        except ValueError:
            return False

# do math for counter wraps
def calculateWrap(previous, current, hc):
    # 32-bit vs 64-bit
    if hc is '1':
        # 64-bit max
        max = 18446744073709551616
        
        # check for fake 64-bit counters 
        # some devices pretend and give 32-bit back for 64-bit OIDs
        if previous < 4294967295:
            # we can presume this is a 32-bit counter
            debug('Set to 64-bit mode, but based on counters, presuming actually 32-bit')
            debug('Calculating wrap with 32-bit counters')
            
            max =  4294967295 # 32-bit max
    else:
        max = 4294967295 # 32-bit max
    
    return (long(max) - long(previous)) + long(current)
    
# convert bytes/octets to a nice value
def bytesToNiceValue(valBytes):
    valBits = long(valBytes * 8)
    
    # if under 1Mbps
    if valBits < 1000000:
        # return Mbps
        return str(valBits) + 'bps'
        
    # if under 1Gbps (and over 1Mbps)
    elif valBytes < 125000000:
        # return Mbps
        return str(round( float(valBits / 1000000), 2) ) + 'Mbps'
    else:
        # return Gbps
        return str(round( float(valBits / 1000) / 1000000, 2)) + 'Gbps'
        
# wrapper for getting a single OID
def sessionGet(oid):
    debug('Fetch OID: ' + str(oid))
    try:
        get = session.get(oid)
    except:
        return None
    return get.value
        
# stackoverflow 3411771
def cleanIfDescr(ifDescr):
    for ch in [' ','(', ')', '.']:
        if ch in ifDescr:
            ifDescr = ifDescr.replace(ch,'-')
    return ifDescr.rstrip(' \t\r\n\0')

# THE PROGRAM
def main():
    # pointer to memcache
    global memcacheClient
    memcacheClient = HashClient([('127.0.0.1', 11211)])
    
    # create argparser
    parser = argparse.ArgumentParser(description='Fetch statistics about a network interface over SNMP (uses hardcoded memcached)')
    
    # debug mode
    parser.add_argument('--debug', dest='debug', action='store_true')
    
    # args - host specific
    parser.add_argument('--host', dest='host', required=True)
    parser.add_argument('--interface', dest='interface', required=True)
    parser.add_argument('--community', dest='community', required=True)
    parser.add_argument('--snmp_port', dest='snmp_port')
    
    # args - thresholds
    parser.add_argument('--bandwidth', dest='bandwidth')
    parser.add_argument('--bandwidth_unit', dest='bandwidth_unit')
    parser.add_argument('--warn_percent', dest='warn_percent')
    parser.add_argument('--crit_percent', dest='crit_percent')
    
    # oper/admin status check
    parser.add_argument('--check_status', dest='check_status', action='store_true')
    
    # parse arguments, make global for function use
    global args
    args = parser.parse_args()
    
    # debug mode
    global debugEnabled
    debugEnabled = 1 if args.debug else 0
    
    # memcache unique host identifier
    global memcachedPrefix
    memcachedPrefix = str(args.host) + "." + cleanIfDescr(args.interface)
    
    # connection to host
    global session
    session = Session(  hostname=str(args.host).replace(' ', ''), 
                        community=str(args.community).replace(' ', ''), version=2)
    
    ### THRESHOLDS ###
    
    # see if warn and crit thresholds are set
    if args.warn_percent is None and args.crit_percent is not None:
        exitMessage('--crit_percent was supplied, but no --warn_percent', 3)
    elif args.warn_percent is not None and args.crit_percent is None:
        exitMessage('--warn_percent was supplied, but no --crit_percent', 3)
    elif args.warn_percent is None and args.crit_percent is None:
        debug('No thresholds supplied, alerting disabled')
        alertEnabled = 0
    else:
        # validate warning percentage
        if isNumber(args.warn_percent):
            if int(args.warn_percent) < 0 or int(args.warn_percent) > 99:
                exitMessage('--warn_percent must be a valid percentage (without %)', 3)
            else:
                warn_percent = int(args.warn_percent)
        
        # validate critical percentage     
        if isNumber(args.crit_percent):
            if int(args.crit_percent) < 0 or int(args.crit_percent) > 99:
                exitMessage('--crit_percent must be a valid percentage (without %)', 3)
            else:
                crit_percent = int(args.crit_percent)
                
        if warn_percent > crit_percent:
            exitMessage('--warn_percent must be less than --crit_percent', 3)
            
        alertEnabled = 1
    
    # get index of interface
    ifIndex         = descrToIndex(cleanIfDescr(args.interface))
    debug('Converted descr "' + cleanIfDescr(args.interface) + '" to index "' + ifIndex + '"')
    timeFetched     = time.time()
    
    # see if the supports hc boolean is in memcached    
    supportsHC      = memcacheClient.get(memcachedPrefix + '.hc')
    
    # if we're unsure about HC support (HC = 64-bit counters)
    if supportsHC is None:
        debug('Not sure if 64-bit counters are enabled, checking now')
        
        # try to fetch 64-bit counters
        ifHCInOctet      = sessionGet(OID_IFHCINOCTET + ifIndex)
        ifHCOutOctet     = sessionGet(OID_IFHCOUTOCTET + ifIndex)
        
        # did we get a number or an error string
        if isNumber(ifHCInOctet):
            debug('64-bit counters enabled')
            memcacheClient.set(memcachedPrefix + '.hc', '1', 86400)
            supportsHC = '1'
            
            # set the counters we'll use to have the 64-bit values
            ifInOctet = ifHCInOctet
            ifOutOctet = ifHCOutOctet
        else:
            # we didn't get a number, fetch 32-bit values
            debug('64-bit counter did not return a number, presuming 32-bit counters')
            memcacheClient.set(memcachedPrefix + '.hc', '0', 86400)
            
            # 32-bit
            ifInOctet   = sessionGet(OID_IFINOCTET + ifIndex)
            ifOutOctet  = sessionGet(OID_IFOUTOCTET + ifIndex)
            supportsHC = '0'   
                     
    elif supportsHC is '1':
        # we already have the 64-bit values 
        debug('Interface known to support 64-bit counters')
        ifInOctet  = sessionGet(OID_IFHCINOCTET + ifIndex)
        ifOutOctet = sessionGet(OID_IFHCOUTOCTET + ifIndex)        
    else:
        # we only support 32-bit, fetch it
        debug('Interface known to support only 32-bit counters')
        ifInOctet   = sessionGet(OID_IFINOCTET + ifIndex)
        ifOutOctet  = sessionGet(OID_IFOUTOCTET + ifIndex)
        supportsHC    = '0' 
    
    # if we are also checking for int status    
    if args.check_status is True:
        # fetch stats over SNMP from remote host
        ifAdminStatus  = sessionGet(OID_IFADMINSTATUS + ifIndex)
        ifOperStatus   = sessionGet(OID_IFOPERSTATUS + ifIndex)
        
        # check admin/oper status
        if ifAdminStatus is not '1':
            exitMessage('Interface is not admin up', 2)
        if ifOperStatus is not '1':
            exitMessage('Interface is not operational', 2)
        
    # check max bandwidth
    if args.bandwidth is None:
        # don't know max, see if it's in memcached
        maxBandwidth = memcacheClient.get(memcachedPrefix + '.max')
        
        if maxBandwidth is None:
            # we don't know the max bw
            debug('Maximum bandwidth for interface not specified, or known in memcached')
            
            #  fetch ifSpeed from host (ifSpeed is in bits, not octets)
            if supportsHC:
                debug('Fetching ifHighSpeed (64-bit)')
                ifSpeed = long(sessionGet(OID_IFHIGHSPEED + ifIndex)) * 1000000
            else:
                debug('Fetching ifSpeed (32-bit)')
                ifSpeed = sessionGet(OID_IFSPEED + ifIndex)
            
            debug ('Maximum bandwidth obtained from ifSpeed')
            memcacheClient.set(memcachedPrefix + '.max', ifSpeed, 86400)
            maxBandwidth = ifSpeed
            
        else:
            # maxBandwidth was in memcached
            debug('Maximum bandwidth for interface found in memcached')
        
    else:
        debug('Max bandwidth was specified at runtime')
        
        if args.bandwidth_unit is None:
            debug('--bandwidth_unit (b/M/G) was not specified, defaulting to M')
            # Mbps -> bits
            maxBandwidth = (long(args.bandwidth) * 1000000)
        elif args.bandwidth_unit is 'b':
            # bits
            maxBandwidth = args.bandwidth
        elif args.bandwidth_unit is 'M':
            # Mbps -> bits
            maxBandwidth = (long(args.bandwidth) * 1000000)
        elif args.bandwidth_unit is 'G':
            # Mbps -> bits
            maxBandwidth = ((long(args.bandwidth) * 1000000) * 1000) 
    
    # convert maxBandwidth to long for maths later on
    maxBandwidth = long(maxBandwidth)
    
    # give a default BW of 1GB if we still haven't got one
    if maxBandwidth == 0:
        maxBandwidth = (1000000 * 1000)
    
    # show nice debug of max value
    debug('Max bandwidth is ' + bytesToNiceValue(maxBandwidth / 8) + ' (' + str(maxBandwidth) + ')')
    
    # grab previous interface values from memcached
    prevTime     = memcacheClient.get(memcachedPrefix + '.last')
    prevInOctet  = memcacheClient.get(memcachedPrefix + '.inOctet')
    prevOutOctet = memcacheClient.get(memcachedPrefix + '.outOctet')
    
    # store fetched values in memcache (for the next run)
    memcacheClient.set(memcachedPrefix + '.last', timeFetched, 3600)
    memcacheClient.set(memcachedPrefix + '.inOctet', ifInOctet, 3600)
    memcacheClient.set(memcachedPrefix + '.outOctet', ifOutOctet, 3600)
    
    # check for historic data
    if prevTime is None:
        # exit with OK status to ensure bulk adding new hosts doesn't alert
        debug('No historical data in memcached, adding values')
        exitMessage('Had no previous data, waiting for next run', 0)

    # calculate overall differences (not per-second)
    elapsed      = float(timeFetched) - float(prevTime)
    diffInOctet  = long(ifInOctet) - long(prevInOctet)
    diffOutOctet = long(ifOutOctet) - long(prevOutOctet)
    
    # check for wrap inbound
    if diffInOctet < 0:
        debug('----------')
        debug('In octets wrapped')
        diffInOctet = calculateWrap(prevInOctet, ifInOctet, supportsHC)
        
    # check for wrap outbound
    if diffOutOctet < 0:
        debug('----------')
        debug('Out octets wrapped')
        diffOutOctet = calculateWrap(prevOutOctet, ifOutOctet, supportsHC)
    
    # calculate averaged values over elapsed time
    diffInOctetBits  = (diffInOctet / elapsed) * 8
    diffOutOctetBits = (diffOutOctet / elapsed) * 8
    diffInOctetMbps  = round(diffInOctetBits / 1000000, 2)
    diffOutOctetMbps = round(diffOutOctetBits / 1000000, 2)
    diffInOctetGbps  = round(diffInOctetMbps / 1000, 5)
    diffOutOctetGbps = round(diffOutOctetMbps / 1000, 5)        
        
    # debug output about known data
    debug('----------')
    debug('Time elapsed since last fetch: ' + str(round(elapsed, 2)) + ' seconds')
    debug('In Before  = ' + str(prevInOctet))
    debug('In Now     = ' + str(ifInOctet))
    debug('Out Before = ' + str(prevOutOctet))
    debug('Out Now    = ' + str(ifOutOctet))
    debug('----------')
    debug('inAbsolut  = ' + ifInOctet)
    debug('outAbsolut  = ' + ifOutOctet)
    debug('----------')
    debug('In octets since last fetch:    ' + str(diffInOctet) + ' bits')
    debug('Out octets since last fetch:   ' + str(diffOutOctet) + ' bits')        
    debug('----------')
    debug('Octets (bytes) in per second on average:  ' + str(diffInOctet / elapsed))
    debug('Octets (bytes) out per second on average: ' + str(diffOutOctet / elapsed))
    debug('Bits per second in on average:            ' + str(diffInOctetBits))
    debug('Bits per second out on average:           ' + str(diffOutOctetBits))
    debug('Megabits per second in on average:        ' + str(diffInOctetMbps))
    debug('Megabits per second out on average:       ' + str(diffOutOctetMbps))
    debug('Gigabits per second in on average:        ' + str(diffInOctetGbps))
    debug('Gigabits per second out on average:       ' + str(diffOutOctetGbps))
    
    # calculate percentages
    percentIn = diffInOctetBits / ( maxBandwidth / 100 )
    percentOut = diffOutOctetBits / ( maxBandwidth / 100 )
    
    # output + perfdata
    output    = 'In: ' + bytesToNiceValue(diffInOctet / elapsed) + ' (' + str(round(percentIn, 1)) + '%), '
    output   += 'Out: ' + bytesToNiceValue(diffOutOctet / elapsed) + ' (' + str(round(percentOut, 1)) + '%) '
    perfdata  = '|inBandwidth='  + bytesToNiceValue(diffInOctet / elapsed)[:-2]
    perfdata += ' outBandwidth=' + bytesToNiceValue(diffOutOctet / elapsed)[:-2]
    perfdata += ' inAbsolut='    + ifInOctet + 'B' # B = Bytes/octets
    perfdata += ' OutAbsolut='   + ifOutOctet + 'B' # B = Bytes/octets
    output   += perfdata
    
    # alerting
    if alertEnabled:
        exitCode = 0
        if percentIn > warn_percent or percentOut > warn_percent:
            exitCode = 1
            
        if percentIn > crit_percent or percentOut > crit_percent:
            exitCode = 2
            
        exitMessage(output, exitCode)
    else:
        # Fin.
        exitMessage(output)

if __name__ == "__main__":
    main()
