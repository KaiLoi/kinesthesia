#!/usr/bin/pperl

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
my $DEBUG = 1;
my $DAEMONPORT = 1975;
my $BINDADDRESS = "127.0.0.1";
my $SERVERKEY = "/etc/kinethesia/certs/server.key";
my $SERVERCRT = "/etc/kinethesia/certs/server.crt";
my $CACRT = "/etc/kinethesia/certs/ca.crt";
my $CLIENTCRT = "/etc/kinethesia/certs/client1.crt";
my $CLIENTKEY = "/etc/kinethesia/certs/client1.key";
my $CONFIGFILE = "/etc/kinethesia/alertdaemon.xml";
# create an XML parser engine for the program.
my $parser = XML::LibXML->new();

my %CRITQUEUE;
my %WARNQUEUE;
my %INFOQUEUE;

print "\n*** Starting Kinethesia Alert Daemon  ***\n\n";
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

# POE session for the SSL TCP server to listen for client queries and respond with the appropreate values. 
POE::Session->create(
        inline_states => {
                _start => \&parent_start,
                _stop  => \&parent_stop,

                socket_birth => \&socket_birth,
                socket_death => \&socket_death,
        }
);

### Sub to kick off a listening port on the configured listening address. Leave it running and ready for connections from clients. 
sub parent_start {
        my $heap = $_[HEAP];

        print "\n= I = Starting  Alert Daemon session and initialising socket\n" if ($DEBUG >= 1);
        $heap->{listener} = POE::Wheel::SocketFactory->new(
                BindAddress  => $BINDADDRESS,
                BindPort     => $DAEMONPORT,
                Reuse        => 'yes',
                SuccessEvent => 'socket_birth',
                FailureEvent => 'socket_death',
        );
        print "= I = Socket initialised on $BINDADDRESS:$DAEMONPORT Listening for Connections.\n" if ($DEBUG >= 1);
}

### Sub to clean up if we shut down the server
sub parent_stop {
        my $heap = $_[HEAP];
        delete $heap->{listener};
        delete $heap->{session};
        print "= I = Listener Death!\n" if ($DEBUG >= 1);
}

### Sub to open the socket for the remote session.
sub socket_birth {
        my ($socket, $address, $port) = @_[ARG0, ARG1, ARG2];

        $address = inet_ntoa($address);
        print "\n= I = Socket birth client connecting\n" if ($DEBUG >= 1);
        # Create a POE session to deal with input/output on this socket. 
        POE::Session->create(
                inline_states => {
                        _start => \&socket_success,
                        _stop  => \&socket_death,

                        socket_input => \&socket_input,
                        socket_death => \&socket_death,
                },
                args => [$socket, $address, $port],
        );
}

### Sub to close the socket session when the user exits.
sub socket_death {
        my $heap = $_[HEAP];
        if ($heap->{socket_wheel}) {
                print "= I = Socket death, client disconnected\n" if ($DEBUG >= 1);
                delete $heap->{socket_wheel};
        }
}

### Sub to take a sucessfully set up socket and configure it for SSL and read/write.
sub socket_success {
        my ($heap, $kernel, $connected_socket, $address, $port) = @_[HEAP, KERNEL, ARG0, ARG1, ARG2];

        print "= I = CONNECTION from $address : $port \n" if ($DEBUG >= 1);
        print "= SSL = Creating SSL Object\n" if ($DEBUG >= 1);
        $heap->{sslfilter} = POE::Filter::SSL->new(
                crt    => $SERVERCRT,
                key    => $SERVERKEY,
                cacrt  => $CACRT,
                cipher => 'DHE-RSA-AES256-GCM-SHA384:AES256-SHA',
                debug  => 1,
                clientcert => 1
        );
        $heap->{socket_wheel} = POE::Wheel::ReadWrite->new(
                Handle => $connected_socket,
                Driver => POE::Driver::SysRW->new(),
                Filter => POE::Filter::Stackable->new(Filters => [
                        $heap->{sslfilter},
                        POE::Filter::Stream->new(),
                ]),
                InputEvent => 'socket_input',
                ErrorEvent => 'socket_death',
        );
        print "= SSL = SSL Socket Created\n" if ($DEBUG >= 1);
}

### Sub to process input to the listening Alert Daemon
sub socket_input {
	my ($heap, $kernel, $buf) = @_[HEAP, KERNEL, ARG0];
	my $response = "";
        my $xml;
	my $msg;
	my $indexhash;

	# First lets verify that the command is from a legitimate client. 
	print "= SSL = Authing Client Command\n" if ($DEBUG >= 1);
	if ($heap->{sslfilter}->clientCertValid()) {
		# Client is valid. 
		# Take the XML Alert received and create an new XML object from it. 
		$xml = XML::LibXML->load_xml(string => $buf);
		print "\n= I = Alert received" if ($DEBUG >= 1);
		print ": \n\n" if ($DEBUG >= 2);
                print "\n" if ($DEBUG >= 1);
		print $xml->toString(1) if ($DEBUG >= 2);
		print "\n" if ($DEBUG >= 2);
		# ACK the client. Atthe moment this is ignored by the client. 
		my $msg = "OK";
		my $response = ackAlert($msg);
		print "= I = Responding to Client with OK ACK" if ($DEBUG >= 1);
		print ": \n\n" if ($DEBUG >= 2);
		print "\n\n" if ($DEBUG >= 1);
                print $response->toString(1) if ($DEBUG >= 2);
                print "\n\n" if ($DEBUG >= 2);
		$heap->{socket_wheel}->put($response);
		# process the alert.
		processAlert($xml);	
		print "CRITQUEUE: \n";
		print Dumper(%CRITQUEUE);
		print "\n\nWARNQUEUE: \n";
		print Dumper(%WARNQUEUE);
	} else {
		# The Client Certificate failed authentication. Drop the packet on the floor and move on. 
		print "= SSL = Client Certificate Invalid! Rejecting command and disconnecting!\n" if ($DEBUG >= 1);
		$kernel->delay(socket_death => 1);
	}

}

# Start the POE Kernel and run all configured services. 
$poe_kernel->run();

#### Non POE subs below this line #####

sub loadAndParseConfig {

	my $cfgref = $parser->parse_file($CONFIGFILE);
	my $xml = $cfgref -> getDocumentElement();
	
	if ($xml->findvalue("AlertDaemon/debug")) {
        	$DEBUG = $xml->findvalue("AlertDaemon/debug");
        	print "\n= I = Loading Debug Setting from config file: $DEBUG\n" if ($DEBUG >= 1);
	}
	if ($xml->findvalue("AlertDaemon/daemonport")) {
	        $DAEMONPORT = $xml->findvalue("AlertDaemon/daemonport");
	        print "= I = Loading daemon port from config file: $DAEMONPORT\n" if ($DEBUG >= 1);
	}
	if ($xml->findvalue("AlertDaemon/bindaddress")) {
	        $BINDADDRESS = $xml->findvalue("AlertDaemon/bindaddress");
	        print "= I = Loading bind address from config file: $BINDADDRESS\n" if ($DEBUG >= 1);
	}
	if ($xml->findvalue("AlertDaemon/serverkey")) {
	        $SERVERKEY = $xml->findvalue("AlertDaemon/serverkey");
	        print "= I = Loading Server Key from config file: $SERVERKEY\n" if ($DEBUG >= 1);
	}
	if ($xml->findvalue("AlertDaemon/servercrt")) {
	        $SERVERCRT = $xml->findvalue("AlertDaemon/servercrt");
	        print "= I = Loading Server Certificate from config file: $SERVERCRT\n" if ($DEBUG >= 1);
	}
	if ($xml->findvalue("AlertDaemon/cacrt")) {
	        $CACRT = $xml->findvalue("AlertDaemon/cacrt");
	        print "= I = Loading CA Certificate from config file: $CACRT\n" if ($DEBUG >= 1);
	}
	if ($xml->findvalue("AlertDaemon/clientkey")) {
	        $CLIENTKEY = $xml->findvalue("AlertDaemon/clientkey");
	        print "= I = Loading Client Key from config file: $CLIENTKEY\n" if ($DEBUG >= 1);
	}
	if ($xml->findvalue("AlertDaemon/clientcrt")) {
	        $CACRT = $xml->findvalue("AlertDaemon/clientcrt");
	        print "= I = Loading Client Certificate from config file: $CLIENTCRT\n" if ($DEBUG >= 1);
	}
	return $xml;

}

### Sub to ACK an alert. 
sub ackAlert {
	my $msg = shift;
        my $response;
        my $root;
        my $typetag;
        my $responsetag;
        my $valuetag;
        my $msgtag;

        my $xml = XML::LibXML::Document->new('1.0', 'utf-8');;
        $root = $xml->createElement("AlertDaemon");
        $xml->addChild($root);
        $typetag = $xml->createElement('msgtype');
        $typetag->addChild($xml->createTextNode("ALERTACK"));
        $root->addChild($typetag);
        $responsetag = $xml->createElement('ACK');
        $root->addChild($responsetag);
        $valuetag = $xml->createElement('value');
        $responsetag->addChild($valuetag);
        $valuetag->addChild($xml->createTextNode("$msg"));
        return $xml;
}

sub processAlert {
	my $xml = shift;
	my $environmental;
	my $level;
	my $msg;
	my $alerter;
	my $root;
	my $env;

	# Find out what Raised this alert used to classify the alert.
	$root = $xml->documentElement();
	$alerter = $root->nodeName();
	print "= I = Taking received alert and classifying it into it's correct queue\n" if ($DEBUG >= 1);
	# Find out which queue each Alert goes into.
	foreach ($xml->findnodes("$alerter/alert")) {
		$level = $_->findvalue("./level");
		$msg = $_->findvalue("./msg");
		$env = $_->findvalue("./environmental");
		# Add the alert to it's alert queue.
		addAlert($level, $alerter, $env, $msg);
	}
	$alerter = "";
	$level = "";
	$msg = "";
	$env = "";
	print "= I = All Alerts in this packet processed.\n\n" if ($DEBUG >= 1);
	return(1);
}

sub addAlert {
	my $level = shift;
	my $alerter = shift;
	my $env = shift;
	my $msg = shift;
	my $time = time;

	# Lets put the alerts in their correct queue. Split up in case we want to handle them differently later.
	# also , this way Critical alerts always flow throguh first. 
	if ($level eq "CRITICAL") {
		# put in critical queue
		print "    = I = Putting Alert in the Critical queue.\n" if ($DEBUG >= 1);
		if ($CRITQUEUE{$alerter}{$env}) {
			print "    = I = We already have an alert for this, updating with time $time.\n" if ($DEBUG >= 1);
			$CRITQUEUE{$alerter}{$env}{'lastseen'} = $time;
		} else {
			print "    = I = This is a new Alert, adding to queue.\n" if ($DEBUG >= 1);
			$CRITQUEUE{$alerter}{$env}{'msg'} = $msg;
			$CRITQUEUE{$alerter}{$env}{'lastseen'} = $time;
		}
	} elsif ($level eq "WARNING") {
		# put in warning queue
		print "    = I = Putting Alert in the Warning queue.\n" if ($DEBUG >= 1);
		if ($WARNQUEUE{$alerter}{$env}) {
                        print "    = I = We already have an alert for this, updating with time $time.\n" if ($DEBUG >= 1);
			$WARNQUEUE{$alerter}{$env}{'lastseen'} = $time;
                } else {
                        print "    = I = This is a new Alert, adding to queue.\n" if ($DEBUG >= 1);
                        $WARNQUEUE{$alerter}{$env}{'msg'} = $msg;
			$WARNQUEUE{$alerter}{$env}{'lastseen'} = $time;
                }
	} elsif ($level eq "INFO") {
		# put in info queue
		print "    = I = Putting Alert in the Info queue.\n" if ($DEBUG >= 1);
		if ($INFOQUEUE{$alerter}{$env}) {
                        print "    = I = We already have an alert for this, updating with time $time.\n" if ($DEBUG >= 1);
                        $INFOQUEUE{$alerter}{$env}{'lastseen'} = $time;
                } else {
                        print "    = I = This is a new Alert, adding to queue.\n" if ($DEBUG >= 1);
                        $INFOQUEUE{$alerter}{$env}{'msg'} = $msg;
                        $INFOQUEUE{$alerter}{$env}{'lastseen'} = $time;
                }
	} else {
		# some weird value received we can't put this alert in a queue
		print "    = I = Unable to correctly catagorise Alert with level $level.\n" if ($DEBUG >= 1);
		return(0);
	}
}

