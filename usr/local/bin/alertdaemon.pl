#!/usr/bin/perl

######################################################################
######################################################################
## alertdaemon.pl: Generic Alert daemon for managing and queuing 
## alerts to the shadow in the kinethesia framework. 
## 
## Written by Kai Rigby - 12/03/2014
##
## v1:          First implementation of an alert Daemon for the 
##                      Kinethesia SW/HW framework.

use strict;
use warnings;
use Data::Dumper;
use Socket;
use XML::LibXML;
use POE qw(
        Wheel::SocketFactory
        Wheel::ReadWrite
        Driver::SysRW
        Filter::SSL
        Filter::Stackable
        Filter::Stream
);

# Set up default values or the below. All values are overridable in the config file. 
my $DAEMON = 0;
my $DEBUG = 0;
my $DAEMONPORT = 2001;
my $BINDADDRESS = "127.0.0.1";
my $SERVERKEY = "/etc/kinethesia/certs/server.key";
my $SERVERCRT = "/etc/kinethesia/certs/server.crt";
my $CACRT = "/etc/kinethesia/certs/ca.crt";
my $CLIENTCRT = "/etc/kinethesia/certs/client1.crt";
my $CLIENTKEY = "/etc/kinethesia/certs/client1.key";
my $CONFIGFILE = "/etc/kinethesia/alertdaemon.xml";
# create an XML parser engine for the program.
my $parser = XML::LibXML->new();

print "\n*** Starting Kinethesia Alert Daemon  ***\n\n";
print "= I = Reading in config file: $CONFIGFILE\n";
my $cfg = loadAndParseConfig();
print "\n= I = Config file read\n";

sub loadAndParseConfig {

	my $cfgref = $parser->parse_file($CONFIGFILE);
	my $xml = $cfgref -> getDocumentElement();
	
	if ($xml->findvalue("AlertDaemon/debug")) {
        	$DEBUG = $xml->findvalue("AlertDaemon/debug");
        	print "\n= I = Loading Debug Setting from config file: $DEBUG\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("AlertDaemon/daemonport")) {
	        $DAEMONPORT = $xml->findvalue("AlertDaemon/daemonport");
	        print "= I = Loading daemon port from config file: $DAEMONPORT\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("AlertDaemon/bindaddress")) {
	        $BINDADDRESS = $xml->findvalue("AlertDaemon/bindaddress");
	        print "= I = Loading bind address from config file: $BINDADDRESS\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("AlertDaemon/serverkey")) {
	        $SERVERKEY = $xml->findvalue("AlertDaemon/serverkey");
	        print "= I = Loading Server Key from config file: $SERVERKEY\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("AlertDaemon/servercrt")) {
	        $SERVERCRT = $xml->findvalue("AlertDaemon/servercrt");
	        print "= I = Loading Server Certificate from config file: $SERVERCRT\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("AlertDaemon/cacrt")) {
	        $CACRT = $xml->findvalue("AlertDaemon/cacrt");
	        print "= I = Loading CA Certificate from config file: $CACRT\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("AlertDaemon/clientkey")) {
	        $CLIENTKEY = $xml->findvalue("AlertDaemon/clientkey");
	        print "= I = Loading Client Key from config file: $CLIENTKEY\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("AlertDaemon/clientcrt")) {
	        $CACRT = $xml->findvalue("AlertDaemon/clientcrt");
	        print "= I = Loading Client Certificate from config file: $CLIENTCRT\n" if ($DEBUG == 1);
	}
	return $xml;

}
	
