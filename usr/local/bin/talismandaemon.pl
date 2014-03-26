#!/usr/bin/perl

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
use XML::Simple;
use POE qw(
        Wheel::SocketFactory
        Wheel::ReadWrite
        Driver::SysRW
        Filter::SSL
        Filter::Stackable
        Filter::Stream
        Component::Client::TCP
);

my $NAME = "SETMEINCONFIG";
my $DAEMON = 0;
my $DEBUG = 1;
my $DAEMONPORT = 1972;
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
# Global hash for storing conigured fetishes and their current state. 
my %FETISHES;

# Start the Daemon and load in the config file.
print "\n*** Starting Kinethesia Talisman Daemon ***\n\n";
print "= I = Reading in config file: $CONFIGFILE\n";
my $cfg = loadAndParseConfig();
# parse the fetish config out of the CFG tree and store it in it's own variable for tracking and state.
loadAndStoreFetishes();
print "\n= I = Config file read\n";

# Set to run as a Daemon or not for debug. 
if ($DAEMON) {
        fork and exit;
}

# set print to flush immediatly, this is for the when debug is set high 
# and needs to print to term.
$| = 1;

# First thing to do is start all it's configured Fetish Daemons. 
#startFetishDaemons()

# Then lets start our configured peristent connections for communication to each.
connectToFetishDaemons();

# POE session for the SSL TCP server to listen for client queries and respond with the appropreate values. 
POE::Session->create(
        inline_states => {
                _start => \&parent_start,
                _stop  => \&parent_stop,

                socket_birth => \&socket_birth,
                socket_death => \&socket_death,
        }
);


# Create a POE Session to run through the fetishes list and see if all fetishes configured
# are connected, and if they aren't, reconnect them. 
POE::Session->create(
        inline_states => {
                _start => sub {
                        $_[HEAP]->{next_alarm_time} = int(time()) + $KEEPALIVE;
                        $_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
                },

                tick => sub {

			my $key;
			my $name;
			my $addr;
			my $port; 

                        print "\n= I = Checking that all Fetishes are connected and running.\n" if ($DEBUG >= 1);
			foreach $key (keys %FETISHES) {
				if (!$FETISHES{$key}{'connected'}) {
					$name = $FETISHES{$key}{'name'};
			                $addr = $FETISHES{$key}{'addr'};
                			$port = $FETISHES{$key}{'port'};
                			print "    = I = Attempting reconnect to disconected Fetish Daemon for $name on $addr:$port\n" if ($DEBUG >= 1);
                			connectFetishDaemon($name, $addr, $port);

				}
			}
                        $_[HEAP]->{next_alarm_time} = $_[HEAP]->{next_alarm_time} + $KEEPALIVE;
                        $_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
                },
        },
);

### Sub to kick off a listening port on the configured listening address. Leave it running and ready for connections from clients. 
sub parent_start {
        my $heap = $_[HEAP];

        print "\n= I = Starting POE session and initialising socket\n" if ($DEBUG == 1);
        $heap->{listener} = POE::Wheel::SocketFactory->new(
                BindAddress  => $BINDADDRESS,
                BindPort     => $DAEMONPORT,
                Reuse        => 'yes',
                SuccessEvent => 'socket_birth',
                FailureEvent => 'socket_death',
        );
        print "= I = Socket initialised on $BINDADDRESS:$DAEMONPORT Waiting for connections\n" if ($DEBUG == 1);
}

### Sub to clean up if we shut down the server
sub parent_stop {
        my $heap = $_[HEAP];
        delete $heap->{listener};
        delete $heap->{session};
        print "= I = Listener Death!\n" if ($DEBUG == 1);
}


### Sub to open the socket for the remote session.
sub socket_birth {
        my ($socket, $address, $port) = @_[ARG0, ARG1, ARG2];

        $address = inet_ntoa($address);
        print "\n= S = Socket birth client connecting\n" if ($DEBUG == 1);
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
                print "= S = Socket death, client disconnected\n" if ($DEBUG == 1);
                delete $heap->{socket_wheel};
        }
}

### Sub to take a sucessfully set up socket and configure it for SSL and read/write.
sub socket_success {
        my ($heap, $kernel, $connected_socket, $address, $port) = @_[HEAP, KERNEL, ARG0, ARG1, ARG2];

        print "= I = CONNECTION from $address : $port \n" if ($DEBUG == 1);
        print "= SSL = Creating SSL Object\n" if ($DEBUG == 1);
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
        print "= SSL = SSL Socket Created\n" if ($DEBUG == 1);
}

### Sub to process input to the listening Talisman daemon from the Shadow or other client. 
sub socket_input {
        my ($heap, $kernel, $buf) = @_[HEAP, KERNEL, ARG0];
        my $response = "";
        my $sub;
        my $command = "";
        my $immediate = 0;
        my $refresh;
        my $ref;
        my $xml;

        # Take the XML received and create an new XML object from it. 
        $xml = XML::LibXML->load_xml(string => $buf);
        $command = $xml->findvalue("/query/command");
        print "= I = Client command received :\n\n$buf\n" if ($DEBUG == 1);
        print "= SSL = Authing Client Command\n" if ($DEBUG == 1);
        if ($heap->{sslfilter}->clientCertValid()) {
                print "= SSL = Client Certificate Valid, Authorised\n" if ($DEBUG == 1);
#                # The option is available here to query the Fetish Daemon for only specific values.
#                # the decision at this time is to only ask for everything it has and filter to the 
#                # shadow at the talisman daemon level. But this can be changed at a later time for 
#                # additional filtering and traffic efficiency on low bandwidth links.
#                if ($command eq "all") {
#                        # Send the client all environmntals, values and quality levels currently stored in the global hash.
#                        $response = allresponse();
#                } elsif ($command eq "poll") {
#                        # if the client sends a "poll" type query, respond. Acts as a kepalive, if needed, from the client. 
#                        $response = pollreponse();
#                } else {
#                        # We don't know what they asked for, inform them with an error type message.
#                        $response = errresponse("Unknown query command sent to fetish daemon $FETISH");
#                }
#                if ($DEBUG == 1) {
#                        print "= I = Sending Client Result:\n\n";
#                        print $response->toString(1);
#                        print "\n";
#                }
#                # Send the client the actual XML.
#                $heap->{socket_wheel}->put($response);
        } else {
                # The Client Certificate failed authentication. Be nice and tell them so then kick them off the server. 
                print "= SSL = Client Certificate Invalid! Rejecting command and disconnecting!\n" if ($DEBUG == 1);
#                $response = errresponse("INVALID CERT! Connection rejected!");
                print "= I = Sending Client Result:\n$response\n" if ($DEBUG == 1);
                $heap->{socket_wheel}->put($response);
                $kernel->delay(socket_death => 1);
        }
}

# Start the POE Kernel and run all configured services. 
$poe_kernel->run();

#### Non POE subs below this line #####

sub loadAndParseConfig {

        my $cfgref = $parser->parse_file($CONFIGFILE);
        my $xml = $cfgref -> getDocumentElement();

	if ($xml->findvalue("TDConfig/name")) {
		$NAME = $xml->findvalue("TDConfig/name");
		print "\n    = I = Loading Talsiman Name from config file: $NAME\n" if ($DEBUG >= 1);
	} else { 
		print "\n    = C = Name not defined in config. This MUST be set! Exiting\n";
		die;
	}
        if ($xml->findvalue("TDConfig/debug")) {
                $DEBUG = $xml->findvalue("TDConfig/debug");
                print "    = I = Loading Debug Setting from config file: $DEBUG\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/bindaddress")) {
                $BINDADDRESS = $xml->findvalue("TDConfig/bindaddress");
                print "    = I = Loading bind address from config file: $BINDADDRESS\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/port")) {
                $DAEMONPORT = $xml->findvalue("TDConfig/port");
                print "    = I = Loading daemon port from config file: $DAEMONPORT\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/alertdaemon")) {
                $ALERTDAEMONADDR = $xml->findvalue("TDConfig/alertdaemon");
                print "    = I = Loading Alert Daemon address from config file: $ALERTDAEMONADDR\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/alertdaemonport")) {
                $ALERTDAEMONPORT = $xml->findvalue("TDConfig/alertdaemonport");
                print "    = I = Loading Alert Daemon port from config file: $ALERTDAEMONPORT\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/shadow")) {
                $SHADOWADDR = $xml->findvalue("TDConfig/shadow");
                print "    = I = Loading Shadow address from config file: $SHADOWADDR\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/shadowport")) {
                $SHADOWPORT = $xml->findvalue("TDConfig/shadowport");
                print "    = I = Loading Shadow port from config file: $SHADOWPORT\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/serverkey")) {
                $SERVERKEY = $xml->findvalue("TDConfig/serverkey");
                print "    = I = Loading Server Key from config file: $SERVERKEY\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/servercrt")) {
                $SERVERCRT = $xml->findvalue("TDConfig/servercrt");
                print "    = I = Loading Server Certificate from config file: $SERVERCRT\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/cacrt")) {
                $CACRT = $xml->findvalue("TDConfig/cacrt");
                print "    = I = Loading CA Certificate from config file: $CACRT\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/clientkey")) {
                $CLIENTKEY = $xml->findvalue("TDConfig/clientkey");
                print "    = I = Loading Client Key from config file: $CLIENTKEY\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/clientcrt")) {
                $CACRT = $xml->findvalue("TDConfig/clientcrt");
                print "    = I = Loading Client Certificate from config file: $CLIENTCRT\n" if ($DEBUG >= 1);
        }
        return $xml;

}

sub startFetishDaemons {
	my @nodes;
	my $name;
	my $fetishname;
	my @temp;

	print "\n= I = Starting Fetish Daemons configured in $CONFIGFILE\n\n" if ($DEBUG >= 1);
	@nodes = returnConfiguredFetishes();
	for $name (@nodes) {
		@temp = split(/-/, $name);
		$fetishname = $temp[1];
		print "    = I = Starting Fetish Daemon $fetishname..." if ($DEBUG >= 1);
		system("/usr/local/bin/fetishdaemon.pl $fetishname 2> /dev/null");
		print "[OK]\n" if ($DEBUG >= 1);
	}
	print "\n= I = All configured Fetish Daemons Started\n" if ($DEBUG >= 1);
}


### Sub to connect to the configured fetish daemons and initate a polling loop to each. 
sub connectToFetishDaemons {
	my @nodes;
	my $node;
	my $addr;
	my $port;
	my $name;
	my $fetishdaemon;
	my $xml;
	my $command;
	my %query;

	print "\n= I = Connecting to all Configured Fetish Daemons and initating automated querying.\n\n" if ($DEBUG >= 1);
	# Get the list of expected fetishes.
	@nodes = returnConfiguredFetishes();
	# Run throguh them and spin off a persistent client connection to each.
	foreach $node (@nodes) {
		$name = $FETISHES{$node}{'name'};
		$addr = $FETISHES{$node}{'addr'};
		$port = $FETISHES{$node}{'port'};
		print "    = I = Connecting to Fetish Daemon for $name on $addr:$port\n" if ($DEBUG >= 1);
		if (connectFetishDaemon($name, $addr, $port)) {
			# if we sucessfully connect to the FD proceed;
		} else { 
			print "    = C = Failed to connect to Fetish Daemon $name\n" if ($DEBUG >= 1);
		}
		
	}
	print "\n= I = Finished Connecting to all Daemons and initiated querying\n"  if ($DEBUG >= 1);
}

### Sub to initiate or reconnect to a fetish daemon.
sub connectFetishDaemon {

	my $name = shift;
	my $addr = shift;
	my $port = shift;
	my $xml;
	

	POE::Component::Client::TCP->new(
		RemoteAddress => $addr,
		RemotePort    => $port,
		Filter        => [ "POE::Filter::SSL", crt => '/etc/kinethesia/certs/client1.crt', key => '/etc/kinethesia/certs/client1.key', client => 1 ],
		Connected     => sub {
			# set the connected flag for this fetish daemon so we know we're currently connected and exchanging data.
			# used to reconnect if connection is lost. 
			$FETISHES{"fd-$name"}{'connected'} = 1;
			print "    = I = Sucessfully connected to $name\n" if ($DEBUG >= 1);
			# set up a polling alarm and kick one off right away. 
			$_[HEAP]->{$name}->{next_alarm_time} = int(time());   # Immediately trigger an alarm
			$_[KERNEL]->alarm(tick => $_[HEAP]->{$name}->{next_alarm_time});
		},
		# received input back from the server and move on. 
		ServerInput   => sub {
			$xml = XML::LibXML->load_xml(string => $_[ARG0]);
			print "= I = Response received from Server\n"  if ($DEBUG >= 2);
			print "\n" . $xml->toString(1) . "\n\n" if ($DEBUG >= 2);
		},
		# inline state to send query to server, then receive response and set a new timer for +Pollperiod. 
		InlineStates => {
			tick => sub {
					my $xml;
					print "= I = Sending query to $name for environmentals\n" if ($DEBUG >= 1);
					$xml = createQuery("all", 0);
					print "\n" . $xml->toString(1) . "\n\n" if ($DEBUG >= 2);
					# make sure we're connected to the remote end. Some states leave this sub running or a sudden drop right 
					# before query causes a SW crash. 
					if ($_[HEAP]{connected}) {
						$_[HEAP]{server}->put($xml);
					} else { 
						"= W = Not currently connected to $name, waiting for reconnect\n" if ($DEBUG >= 1);
					}
					# reset the timer and goround the wheel again
					$_[HEAP]->{$name}->{next_alarm_time}+=$POLLPERIOD;
					$_[KERNEL]->alarm(tick => $_[HEAP]->{$name}->{next_alarm_time});
			},
		},
		# what to do if the connection drops. 
		Disconnected => sub {
			my $key;

			print "= W = Lost connection to $name, marking disconnected for retry.\n" if ($DEBUG >= 1);
			# set the connected flag to 0 so the fetish monitor knows to attempt restart/reconnect. We aren't usingthe in-built POE 
			# reconnect function becuase it only tries once after delay time and gives up. Not good. 
			$FETISHES{"fd-$name"}{'connected'} = 0;
			# remove the alarm timer for next iteration. Not doing this causes the sever to continue going around the wheel even after 
			# the connection has dropped. 
			$_[KERNEL]->alarm_remove_all();
			# clear variables we have set from the heap and shut down the client. 
			delete $_[HEAP]->{$name};
			$_[KERNEL]->yield('shutdown');
			$_[KERNEL]->call('shutdown');
		},
	);
}


### A Sub to craft a query for polling connected fetishes. 
sub createQuery {
	# Takes a type (all, temp, etc) and if the reuqest being crafted requires an immediate update of the value. 
	my $type = shift;
	my $immediate = shift;
	my $xml;
	my $root;
	my $typetag;
	my $querytag;
	my $valuetag;
	my $immediatetag;
	
	$xml = XML::LibXML::Document->new('1.0', 'utf-8');
	$root = $xml->createElement("$NAME");
	$xml->addChild($root);
	$typetag = $xml->createElement('msgtype');
	$typetag->addChild($xml->createTextNode("QUERY"));
	$root->addChild($typetag);
	$querytag = $xml->createElement('query');
	$root->addChild($querytag);
	$valuetag = $xml->createElement('value');
	$querytag->addChild($valuetag);
	$valuetag->addChild($xml->createTextNode("$type"));
	$immediatetag = $xml->createElement('immediate');
	$querytag->addChild($immediatetag);
	$immediatetag->addChild($xml->createTextNode("$immediate"));
	return($xml);

}

### Sub to run through the loaded config and reurn the name of all locally configured
### fetishes for any sub that requires them.
sub returnConfiguredFetishes {
	my $node;
	my @nodes;
	my $nodename;
	my $subnode;
	my $name;

	# run through the config and fill an array with nodes that match fd-*
	for $node ($cfg->findnodes('/cfg')) {
		for $subnode ($node->findnodes('./*')) {
			$name = $subnode->nodeName();
			if ($name =~ m/^fd-.+/) {
				push(@nodes, $name);
			}
		}
	}
			
	return(@nodes);
}

sub loadAndStoreFetishes {
	my @nodes;
	my $node;
	my $name;
	my $addr;
	my $port;

	@nodes = returnConfiguredFetishes();
	foreach $node (@nodes) {
		$name = (split(/-/, $node))[1];
		$addr = $cfg->findvalue("/cfg/$node/bindaddress");
		$port = $cfg->findvalue("/cfg/$node/daemonport");
		$FETISHES{$node}{'name'} = $name;
		$FETISHES{$node}{'addr'} = $addr;
		$FETISHES{$node}{'port'} = $port;
		# set a variable to track if the talisman daemon is currently connected to this fetish
		# for re-starting/reconnecting later.
		$FETISHES{$node}{'connected'} = 0;
	}
} 


### END OF LINE ###
