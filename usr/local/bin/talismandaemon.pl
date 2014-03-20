#!/usr/bin/pperl

######################################################################
######################################################################
## talismandaemon.pl: Talisman daemon for managing and interfacing 
## to fetishes daemonsin the kinethesia framework. 
## 
## Written by Kai Rigby - 25/02/2014
##
## v1:          First implementation of a Talsiman Daemon for the 
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
        Component::Client::TCP
);

my $DAEMON = 0;
my $DEBUG = 1;
my $DAEMONPORT = 1974;
my $BINDADDRESS = "127.0.0.1";
my $POLLPERIOD = 30; # How often to poll all the fetish Daemons or their values to store.
my $KEEPALIVE = 10; # How often to end a kepalive to each fetishdaemon to make sure they are working.
my $SERVERKEY = "/etc/kinethesia/certs/server.key";
my $SERVERCRT = "/etc/kinethesia/certs/server.crt";
my $CLIENTCRT = "/etc/kinethesia/certs/client1.crt";
my $CLIENTKEY = "/etc/kinethesia/certs/client1.key";
my $CACRT = "/etc/kinethesia/certs/ca.crt";
my $CONFIGFILE = "/etc/kinethesia/talismandaemon.xml";
my $ALERTDAEMONADDR = "127.0.0.1";
my $ALERTDAEMONPORT = "1975";
my $SHADOWADDR = "127.0.0.1";
my $SHADOWPORT = 1970;
# Create an XML parser engine for the program.
my $parser = XML::LibXML->new();
# Global hash for storing the env details returned by fetish Daemons.
my %ENV;

# Start the Daemon and load in the config file.
print "\n*** Starting Kinethesia Fetish Daemon ***\n\n";
print "= I = Reading in config file: $CONFIGFILE\n";
my $cfg = loadAndParseConfig();
print "\n= I = Config file read\n";

# Set to run as a Daemon or not for debug. 
if ($DAEMON) {
        fork and exit;
}

# set print to flush immediatly, this is for the when debug is set high 
# and needs to print to term.
$| = 1;






#### Non POE subs below this line #####

sub loadAndParseConfig {

        my $cfgref = $parser->parse_file($CONFIGFILE);
        my $xml = $cfgref -> getDocumentElement();

        if ($xml->findvalue("TDConfig/debug")) {
                $DEBUG = $xml->findvalue("TDConfig/debug");
                print "\n= I = Loading Debug Setting from config file: $DEBUG\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/bindaddress")) {
                $BINDADDRESS = $xml->findvalue("TDConfig/bindaddress");
                print "= I = Loading bind address from config file: $BINDADDRESS\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/port")) {
                $DAEMONPORT = $xml->findvalue("TDConfig/port");
                print "= I = Loading daemon port from config file: $DAEMONPORT\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/alertdaemon")) {
                $ALERTDAEMONADDR = $xml->findvalue("TDConfig/alertdaemon");
                print "= I = Loading Alert Daemon address from config file: $ALERTDAEMONADDR\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/alertdaemonport")) {
                $ALERTDAEMONPORT = $xml->findvalue("TDConfig/alertdaemonport");
                print "= I = Loading Alert Daemon port from config file: $ALERTDAEMONPORT\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/shadow")) {
                $SHADOWADDR = $xml->findvalue("TDConfig/shadow");
                print "= I = Loading Shadow address from config file: $SHADOWADDR\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/shadowport")) {
                $SHADOWPORT = $xml->findvalue("TDConfig/shadowport");
                print "= I = Loading Shadow port from config file: $SHADOWPORT\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/serverkey")) {
                $SERVERKEY = $xml->findvalue("TDConfig/serverkey");
                print "= I = Loading Server Key from config file: $SERVERKEY\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/servercrt")) {
                $SERVERCRT = $xml->findvalue("TDConfig/servercrt");
                print "= I = Loading Server Certificate from config file: $SERVERCRT\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/cacrt")) {
                $CACRT = $xml->findvalue("TDConfig/cacrt");
                print "= I = Loading CA Certificate from config file: $CACRT\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/clientkey")) {
                $CLIENTKEY = $xml->findvalue("TDConfig/clientkey");
                print "= I = Loading Client Key from config file: $CLIENTKEY\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/clientcrt")) {
                $CACRT = $xml->findvalue("TDConfig/clientcrt");
                print "= I = Loading Client Certificate from config file: $CLIENTCRT\n" if ($DEBUG >= 1);
        }
        return $xml;

}



