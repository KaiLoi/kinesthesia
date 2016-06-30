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

#sub POE::Kernel::TRACE_REFCNT () { 1 }

use strict;
use warnings;
use Data::Dumper;
use Socket;
use IO::Socket::INET;
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

my $TALSIMANNAME = "SETMEINCONFIG";
my $DAEMON = 0;
my $DEBUG = 1;
my $DAEMONPORT = 1972;
my $BINDADDRESS = "127.0.0.1";
my $POLLPERIOD = 30; # How often to poll all the fetish Daemons or their values to store.
my $KEEPALIVE = 10; # How often to end a kepalive to each fetishdaemon to make sure they are working.
my $ENVCLEANPERIOD = 30; # How often to clean out stale environmentals from the ENV hash. 
my $PROGRAMDIR = "/usr/local/bin/kinesthesia/";
my $SERVERKEY = "/etc/kinesthesia/certs/server.key";
my $SERVERCRT = "/etc/kinesthesia/certs/server.crt";
my $CLIENTCRT = "/etc/kinesthesia/certs/client1.crt";
my $CLIENTKEY = "/etc/kinesthesia/certs/client1.key";
my $CACRT = "/etc/kinesthesia/certs/ca.crt";
my $CONFIGFILE = "/etc/kinesthesia/talismandaemon.xml";
my $FDCONFIGDIR = "/etc/kinesthesia/plugins.d/";
my $ALERTDAEMONADDR = "127.0.0.1";
my $ALERTDAEMONPORT = "1975";
my $SHADOWADDR = "127.0.0.1";
my $SHADOWPORT = 1970;
# Create an XML parser engine for the program.
my $parser = XML::LibXML->new();
# Global hash for storing the env details returned by fetish Daemons.
my %ENV;
# Global hash for storing conigured fetishes and their current connectivity and reporting state. 
my %FETISHES;

# Start the Daemon and load in the config file.
print "\n*** Starting Kinethesia Talisman Daemon ***\n\n";
print "= TD - I = Reading in config file: $CONFIGFILE\n";
my $cfg = loadAndParseConfig();
# parse the fetish config out of the CFG tree and store it in it's own variable for tracking and state.
loadAndStoreFetishes();
print "\n= TD - I = Config files read\n";
# Set to run as a Daemon or not for debug. 
if ($DAEMON) {
        fork and exit;
}

# set print to flush immediatly, this is for the when debug is set high 
# and needs to print to term.
$| = 1;

# First thing to do is start all it's configured Fetish Daemons. 
startFetishDaemons();

# Then lets start our configured peristent connections for communication to each.
initialConnectToFetishDaemons();

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
			$_[KERNEL]->alias_set('FetishWatchdog');
                        $_[HEAP]->{next_alarm_time} = int(time()) + $KEEPALIVE;
                        $_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
                },

                tick => sub {

			my $key;
			my $name;
			my $addr;
			my $port; 

                        print "\n= TD - I = Checking that all Fetishes are connected and running.\n" if ($DEBUG >= 1);
			foreach $key (keys %FETISHES) {
				if (!$FETISHES{$key}{'connected'}) {
					$name = $FETISHES{$key}{'name'};
			                $addr = $FETISHES{$key}{'addr'};
                			$port = $FETISHES{$key}{'port'};
                			print "    = TD - I = Attempting reconnect to disconected Fetish Daemon for $name on $addr:$port\n" if ($DEBUG >= 1);
                			connectFetishDaemon($name, $addr, $port);

				}
			}
			print "= TD - I = Finished Checking all fetishes.\n"  if ($DEBUG >= 1);
                        $_[HEAP]->{next_alarm_time} = $_[HEAP]->{next_alarm_time} + $KEEPALIVE;
                        $_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
                },
        },
);

# Create POE session to keep the environmental  clean and relevent. 
# Basically this sub program fires every 5 min and cleans out any environmentals 
# that haven't reported in 5 min.  If we haven't heard from it in 5 min 
# we probably don't care about the value anymore as it's old 
# and stale.  Stops the memory from filling with
# old stale environemtnals and fetishes that are no longer reporting. Also
# prevents the Shadow from querying an environmental no longer in the hash.
POE::Session->create(
        inline_states => {
                _start => sub {
			$_[KERNEL]->alias_set('EnvCleaner');
                        $_[HEAP]->{next_alarm_time} = int(time()) + $ENVCLEANPERIOD;
                        $_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
                },

                tick => sub {
			my $envkey;
			my $fetkey;
			my $now = time();
			my $age;
			my $size;
	
                        print "\n= TD - I = Cleaning up Environmental DB\n" if ($DEBUG >= 1);
			# Run through the ENV hash and check each environmntal and subsequent fetish for the age of the last reported data. 
			foreach $envkey (keys $ENV{$TALSIMANNAME}) {
				foreach $fetkey (keys $ENV{$TALSIMANNAME}{$envkey}) {
					$age = $now - $ENV{$TALSIMANNAME}{$envkey}{$fetkey}{'age'};
					# If the stored fetish value is older than 5 min it's getting stale, lets clean it out until it reports again.
					if ($age > 30) {
						print "    = TD - I = Cleaning out old Environmental $envkey for fetish $fetkey\n" if ($DEBUG >= 1);
						delete $ENV{$TALSIMANNAME}{$envkey}{$fetkey};
					} else { 
						print "    = TD - I = Leaving Environmental $envkey for fetish $fetkey alone as it is still current\n"  if ($DEBUG >= 1);
					}
				}
				# lets make sure that there are still some reporting fetishes for this environmental. 
				$size = keys($ENV{$TALSIMANNAME}{$envkey});
				if ($size > 0) {
					# Still fetishes responding for this environmental do nothing.
				} else {
					# We've Deleted all reporting fetishes for this Environmental. Delete it from our DB so it's not reported in our capabilities and 
					# update any subscribed shadow with the info. 
					print "        = TD - I = We've Deleted all reporting fetishes for this Environmental. Deleting environmental from our DB.\n" if ($DEBUG >= 1);
					delete $ENV{$TALSIMANNAME}{$envkey};
					#FIXME!
					# notifyShadowOfCapabilityChange($envkey);
				}
			}
                        print "= TD - I = Finished cleaning up Environmental DB. Sleeping for $ENVCLEANPERIOD seconds.\n\n" if ($DEBUG >= 1);
                        $_[HEAP]->{next_alarm_time} = $_[HEAP]->{next_alarm_time} + $ENVCLEANPERIOD;
                        $_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
                },
        },
);

### Sub to kick off a listening port on the configured listening address. Leave it running and ready for connections from clients. 
sub parent_start {
        my $heap = $_[HEAP];

	$_[KERNEL]->alias_set('TalismanListener');
        print "\n= TD - I = Starting POE session and initialising socket\n" if ($DEBUG == 1);
        $heap->{listener} = POE::Wheel::SocketFactory->new(
                BindAddress  => $BINDADDRESS,
                BindPort     => $DAEMONPORT,
                Reuse        => 'yes',
                SuccessEvent => 'socket_birth',
                FailureEvent => 'socket_death',
        );
        print "= TD - I = Socket initialised on $BINDADDRESS:$DAEMONPORT Waiting for connections\n" if ($DEBUG == 1);
}

### Sub to clean up if we shut down the server
sub parent_stop {
        my $heap = $_[HEAP];
        delete $heap->{listener};
        delete $heap->{session};
        print "= TD - I = Listener Death!\n" if ($DEBUG == 1);
}


### Sub to open the socket for the remote session.
sub socket_birth {
        my ($socket, $address, $port) = @_[ARG0, ARG1, ARG2];

        $address = inet_ntoa($address);
        print "\n= TD - S = Socket birth client connecting\n" if ($DEBUG == 1);
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
                print "= TD - S = Socket death, client disconnected\n" if ($DEBUG == 1);
                delete $heap->{socket_wheel};
        }
}

### Sub to take a sucessfully set up socket and configure it for SSL and read/write.
sub socket_success {
        my ($heap, $kernel, $connected_socket, $address, $port) = @_[HEAP, KERNEL, ARG0, ARG1, ARG2];

	$_[KERNEL]->alias_set('SSLSession');
        print "= TD - I = CONNECTION from $address : $port \n" if ($DEBUG >= 3);
        print "= TD - SSL = Creating SSL Object\n" if ($DEBUG >= 3);
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
        print "= TD - SSL = SSL Socket Created\n" if ($DEBUG >= 3);
}

### Sub to process input to the listening Talisman daemon from the Shadow or other client. 
sub socket_input {
        my ($heap, $kernel, $buf) = @_[HEAP, KERNEL, ARG0];
        my $response = "";
        my $sub;
	my $root;
	my $sender;
	my $msgtype;
        my $command = "";
        my $immediate = 0;
        my $refresh;
        my $ref;
        my $xml;
	my $value;
	my @envavailable;
	my @invavailable;

	print "= TD - I = Client command received " if ($DEBUG >= 1);
        if ($DEBUG >= 2 ) {
                print ": \n\n$buf\n" if ($DEBUG >= 2);
        } elsif ($DEBUG >= 1) {
                print "\n";
        }
        print "= TD - SSL = Authing Client Packet\n" if ($DEBUG >= 3);
        if ($heap->{sslfilter}->clientCertValid()) {
                print "= TD - SSL = Client packet authenticated!\n" if ($DEBUG >= 3);
                # Take the XML received and create an new XML object from it. 
                $xml = XML::LibXML->load_xml(string => $buf);
                $root = $xml->documentElement();
		# get the name of the connected clint for analyzing their XML tree. 
                $sender = $root->nodeName();
                $msgtype = $xml->findvalue("/$sender/msgtype");
		# If the message type is a Query then get the type and respond wih the appropreate info. 
		if ($msgtype eq "QUERY") {
			# grab the query and lets do somthing with it.
			$value = $xml->findvalue("/$sender/query/value");
			if ($value eq "envcapability") {
				# get the list of environmentals currently stored/indexed by this talisman daemon for the query type. 
				@envavailable = getEnvironmentals();
				# return a list of currenrtly indexed and current Environmental values indexed by this TalsimanDaemon.
				$response = returnEnvCapbiliy(\@envavailable);
			} elsif ($value eq "invcapability") {
				# get the list of invocations currently stored/indexed by this talisman daemon for the query type. 
				@invavailable = getInvocations();
				# return a list of currenrtly indexed and current Invocation Daemons indexed by this TalsimanDaemon.
				$response = returnInvCapbiliy(\@invavailable);
			# if this is a query for an environmental we currently store, return it as queried. We only do this for 
			# environmentals because invocations are triggered by the CMD messgae type. Immediate realtime fetish queries are 
			# also handled by the CMD type. 
			} elsif ($value ~~ @envavailable) {
				$response = getAndReturnEnv($value);
			} else {
				$response = errresponse("Unknown query command sent to Talisman Daemon");
			}
		} elsif ($msgtype eq "CMD") { 
			# docommandy type stuff here, unefined so far. 
		} else {
			$response = errresponse("Unknown message type sent to Talisman Daemon");
		}
		# Send the response we have generated. 
		$heap->{socket_wheel}->put($response);
        } else {
		# The Client Certificate failed authentication. Be nice and tell them so then kick them off the server. 
		# might change this in the future to a clean disconnect with no response. At the momnt it's useful for
		# debugging.
                print "= TD - SSL = Client Certificate Invalid! Rejecting command and disconnecting!\n" if ($DEBUG == 3);
                $response = errresponse("INVALID CERT! Connection rejected!");
                print "= TD - I = Sending Client Result:\n$response\n" if ($DEBUG == 1);
                $heap->{socket_wheel}->put($response);
                $kernel->delay(socket_death => 1);
        }

}

# Start the POE Kernel and run all configured services. 
$poe_kernel->run();

#### Non POE subs below this line #####

### Sub to load and parse the config from disk. 
sub loadAndParseConfig {

        my $cfgref = $parser->parse_file($CONFIGFILE);
        my $xml = $cfgref -> getDocumentElement();

	if ($xml->findvalue("TDConfig/name")) {
		$TALSIMANNAME = $xml->findvalue("TDConfig/name");
		print "\n    = TD - I = Loading Talsiman Name from config file: $TALSIMANNAME\n" if ($DEBUG >= 1);
	} else { 
		print "\n    = TD - C = Name not defined in config. This MUST be set! Exiting\n";
		die;
	}
        if ($xml->findvalue("TDConfig/debug")) {
                $DEBUG = $xml->findvalue("TDConfig/debug");
                print "    = TD - I = Loading Debug Setting from config file: $DEBUG\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/bindaddress")) {
                $BINDADDRESS = $xml->findvalue("TDConfig/bindaddress");
                print "    = TD - I = Loading bind address from config file: $BINDADDRESS\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/port")) {
                $DAEMONPORT = $xml->findvalue("TDConfig/port");
                print "    = TD - I = Loading daemon port from config file: $DAEMONPORT\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/alertdaemon")) {
                $ALERTDAEMONADDR = $xml->findvalue("TDConfig/alertdaemon");
                print "     = TD - I = Loading Alert Daemon address from config file: $ALERTDAEMONADDR\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/alertdaemonport")) {
                $ALERTDAEMONPORT = $xml->findvalue("TDConfig/alertdaemonport");
                print "     = TD - I = Loading Alert Daemon port from config file: $ALERTDAEMONPORT\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/shadow")) {
                $SHADOWADDR = $xml->findvalue("TDConfig/shadow");
                print "     = TD - I = Loading Shadow address from config file: $SHADOWADDR\n" if ($DEBUG >= 1);
        }
	if ($xml->findvalue("TDConfig/shadowport")) {
                $SHADOWPORT = $xml->findvalue("TDConfig/shadowport");
                print "     = TD - I = Loading Shadow port from config file: $SHADOWPORT\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/serverkey")) {
                $SERVERKEY = $xml->findvalue("TDConfig/serverkey");
                print "     = TD - I = Loading Server Key from config file: $SERVERKEY\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/servercrt")) {
                $SERVERCRT = $xml->findvalue("TDConfig/servercrt");
                print "     = TD - I = Loading Server Certificate from config file: $SERVERCRT\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/cacrt")) {
                $CACRT = $xml->findvalue("TDConfig/cacrt");
                print "     = TD - I = Loading CA Certificate from config file: $CACRT\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/clientkey")) {
                $CLIENTKEY = $xml->findvalue("TDConfig/clientkey");
                print "     = TD - I = Loading Client Key from config file: $CLIENTKEY\n" if ($DEBUG >= 1);
        }
        if ($xml->findvalue("TDConfig/clientcrt")) {
                $CACRT = $xml->findvalue("TDConfig/clientcrt");
                print "     = TD - I = Loading Client Certificate from config file: $CLIENTCRT\n" if ($DEBUG >= 1);
        }
        return $xml;

}

### Sub to run through the list of configured feitshes and start them. Using ugly system call for now. Will move to nicer 
### forking soon. 
sub startFetishDaemons {
	my @nodes;
	my $name;
	my $fetishname;
	my $port;
	my $addr;
	my $connected = 0;
	my $socket;
	my $count = 0;

	print "\n = TD - I = Starting Fetish Daemons configured in $CONFIGFILE\n\n" if ($DEBUG >= 1);
	# Find all the fetishes configured in the config and put them in an array.
	@nodes = returnConfiguredFetishes();
	# Run through the array and attemp to start each Fetish Daemon defiend. 
	for $fetishname (@nodes) {
		$port = $FETISHES{$fetishname}{'port'};
		$addr = $FETISHES{$fetishname}{'addr'};
		print "     = TD - I = Starting Fetish Daemon $fetishname " if ($DEBUG >= 1);
		system("$PROGRAMDIR/fetishdaemon.pl $fetishname 2> /dev/null &");
		print "\n       = TD - I = Checking if fetish started on $addr:$port : " if ($DEBUG >= 1);
		# give the fetsih 10 secondsto start up. If it doesn't give up on this fetish and move on. Remove it from the fetishes list or we will keep trying to connect to it erroniously. 
		while (!$connected) {
			$socket = IO::Socket::INET->new(PeerAddr => "$addr",
                                 PeerPort => "$port",
                                 Proto    => 'tcp');

			if ($socket) {
				$connected = 1;
			}
			print ".";
			$count++;
			if ($count == 10) {
				last;
			}
			sleep 1;
		}
		if ($count < 10) { 
			print " [OK]\n" if ($DEBUG >= 1);
		} elsif ($count == 10) {
			print " [FAILED] - Check config or binary, continuing with fetish removed\n" if ($DEBUG >= 1);
			delete $FETISHES{$fetishname};		
		} 
		$count = 0;
		$connected = 0;
		close($socket) if ($socket);
	}
	print "\n = TD - I = Fetish Daemons Started\n" if ($DEBUG >= 1);
}


### Sub to start the initial connect to the configured fetish daemons and initate a polling loop to each. 
sub initialConnectToFetishDaemons {
	my @nodes;
	my $node;
	my $addr;
	my $port;
	my $name;
	my $fetishdaemon;
	my $xml;
	my $command;
	my %query;

	print "\n = TD - I = Connecting to all Configured Fetish Daemons and initating automated querying.\n\n" if ($DEBUG >= 1);
	# Get the list of expected fetishes.
	@nodes = returnConfiguredFetishes();
	# Run throguh them and spin off a persistent client connection to each.
	foreach $node (@nodes) {
		$name = $FETISHES{$node}{'name'};
		$addr = $FETISHES{$node}{'addr'};
		$port = $FETISHES{$node}{'port'};
		print "     = TD - I = Connecting to Fetish Daemon for $name on $addr:$port\n" if ($DEBUG >= 1);
		if (connectFetishDaemon($name, $addr, $port)) {
			# if we sucessfully connect to the FD proceed;
		} else { 
			print "     = TD - C = Failed to connect to Fetish Daemon $name\n" if ($DEBUG >= 1);
		}
		
	}
	print "\n = TD - I = Finished Connecting to all Daemons and initiated querying\n"  if ($DEBUG >= 1);
}

### Sub to initiate or reconnect to a fetish daemon.
sub connectFetishDaemon {

	my $name = shift;
	my $addr = shift;
	my $port = shift;
	my $xml;
	

	POE::Component::Client::TCP->new(
		Alias => $name,
		RemoteAddress => $addr,
		RemotePort    => $port,
		###### FIXME! WHY ARE THE CLIENT CERTS HARD CODED????
		Filter        => [ "POE::Filter::SSL", crt => "$CLIENTCRT", key => "$CLIENTKEY", client => 1 ],
		Connected     => sub {
			# set the connected flag for this fetish daemon so we know we're currently connected and exchanging data.
			# used to reconnect if connection is lost. 
			$FETISHES{"$name"}{'connected'} = 1;
			print "     = TD - I = Sucessfully connected to $name\n" if ($DEBUG >= 1);
			# set up a polling alarm and kick one off right away. 
			$_[HEAP]->{$name}->{next_alarm_time} = int(time());   # Immediately trigger an alarm
			$_[KERNEL]->alarm(tick => $_[HEAP]->{$name}->{next_alarm_time});
		},
		ConnectError => sub {
			# Specify to capture connection refused and surpress STDERR and clean up shutdown correctly.

			$_[KERNEL]->alarm_remove_all();
                        $_[KERNEL]->alias_remove($name);
                        delete $_[HEAP]->{wheel};
                        # clear variables we have set from the heap and shut down the client. 
                        delete $_[HEAP]->{$name};
                        $_[KERNEL]->yield('shutdown');
                        $_[KERNEL]->call('shutdown');			
			print "     = TD - W = Connection refused, waiting $KEEPALIVE seconds and trying again\n" if ($DEBUG >= 1);
		}, 
		# received input back from the server and move on. 
		ServerInput   => sub {
			$xml = XML::LibXML->load_xml(string => $_[ARG0]);
			print " = TD - I = Response received from Server\n"  if ($DEBUG >= 2);
			print "\n" . $xml->toString(1) . "\n\n" if ($DEBUG >= 2);
			processFetishResponse($name, $xml);
		},
		# inline state to send query to server, then receive response and set a new timer for +Pollperiod. 
		InlineStates => {
			tick => sub {
					my $xml;
					print " = TD - I = Sending query to $name for environmentals\n" if ($DEBUG >= 1);
					$xml = createQuery("all", 0);
					print "\n" . $xml->toString(1) . "\n\n" if ($DEBUG >= 2);
					# make sure we're connected to the remote end. Some states leave this sub running or a sudden drop right 
					# before query causes a SW crash withou this check. 
					if ($_[HEAP]{connected}) {
						$_[HEAP]{server}->put($xml);
					} else { 
						print " = TD - W = Not currently connected to $name, waiting for reconnect\n" if ($DEBUG >= 1);
					}
					# reset the timer and go round the wheel again
					$_[HEAP]->{$name}->{next_alarm_time}+=$POLLPERIOD;
					$_[KERNEL]->alarm(tick => $_[HEAP]->{$name}->{next_alarm_time});
			},
		},
		# what to do if the connection drops. 
		Disconnected => sub {
			my $key;

			print " = TD - W = Lost connection to $name, marking disconnected for retry.\n" if ($DEBUG >= 1);
			# set the connected flag to 0 so the fetish monitor knows to attempt restart/reconnect. We aren't usingthe in-built POE 
			# reconnect function becuase it only tries once after delay time and gives up. Not good. 
			$FETISHES{"$name"}{'connected'} = 0;
			# remove the alarm timer for next iteration. Not doing this causes the sever to continue going around the wheel even after 
			# the connection has dropped. It prvents this instance of this sub from exiting. 
			$_[KERNEL]->alarm_remove_all();
			$_[KERNEL]->alias_remove($name);
			delete $_[HEAP]->{wheel};
			# clear variables we have set from the heap and shut down the client. 
			delete $_[HEAP]->{$name};
			$_[KERNEL]->yield('shutdown');
			$_[KERNEL]->call('shutdown');
		},
		ServerError => sub {
			
			#do nothing, quieter.
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
	
	# Buold an XML repsonse and retun it. 
	$xml = XML::LibXML::Document->new('1.0', 'utf-8');
	$root = $xml->createElement("$TALSIMANNAME");
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
	my @nodes;
	
	@nodes = keys %FETISHES;
	return(@nodes);
}

### Sub to create the global HASH containing all the configutred fetishes and their current connecton state.
sub loadAndStoreFetishes {
	my $file;
	my @nodes;
	my $node;
	my $name;
	my $addr;
	my $port;
        my $cfgref;
        my $xml;


	# Grab conigured fetishes from config plugin.d directory.
	opendir(DIR, $FDCONFIGDIR) or die $!;

	# Grab a list of all the plugins that have config files.	
 	while (my $file = readdir(DIR)) {
		# We only want files
        	next unless (-f "$FDCONFIGDIR/$file");
		# Use a regular expression to find files ending in .txt
        	next unless ($file =~ m/\.xml$/);
		# split it down to just the fetish name.
		$file = (split(/-/, $file))[1];
		$file = (split(/\./, $file))[0];
		
		#create a list of all fetsihes found. 
		push (@nodes, $file);
    	}

    	closedir(DIR);

	foreach $node (@nodes) {

		$cfgref = $parser->parse_file("$FDCONFIGDIR/f-$node.xml");
        	$xml = $cfgref -> getDocumentElement();

		# grab the fetishes name, port and IP and store them. 
#		print "looking for node fd-$node\n";
		$addr = $xml->findvalue("fd-$node/bindaddress");
		$port = $xml->findvalue("fd-$node/daemonport");
		$FETISHES{$node}{'name'} = $node;
		$FETISHES{$node}{'addr'} = $addr;
		$FETISHES{$node}{'port'} = $port;
		# set a variable to track if the talisman daemon is currently connected to this fetish
		# for re-starting/reconnecting later.
		$FETISHES{$node}{'connected'} = 0;
	}
#	print Dumper(%FETISHES);
} 

### Sub to take the reponse from a fetish and parse it's data into the Environmental hash/DB
sub processFetishResponse {
	my $envname = shift;
	my $xml = shift;
	my $root;
	my $alerter;
	my $envtype;

	# initially we'll store this data in a memory hash. But this can easily be replaced
	# by some kind of SQL DB or any other storage method. 
	print "     = TD - I = Storing response from Fetish $envname in memory DB\n" if ($DEBUG >= 1);
	# Find out what fetish this response is from.
        $root = $xml->documentElement();
        $alerter = $root->nodeName();
	if ($alerter ne $envname) {
		print "     = TD - C = Somehow we got here with a packet not from the daemon we expected! Could be a security issue or a broken fetish daemon!\n" if ($DEBUG >= 1);
		return(0);
	}
	# run through the returned values in this packet and add them to the environmental hash. We're going to change the logic
	# a bit here. Up till this point we've had fetish->environmental type -> values. We're going to change here to 
	# environmental type -> fetish -> values. This is because we can have multiple fetishes returning the same environmental 
	# (like temperature) and we want to be able to filter only the best (by qual) to the shadow so we store them all for 
	# comparison.
	foreach ($xml->findnodes("$envname/environmental")) {
		$envtype = $_->findvalue("./name");
		$ENV{$TALSIMANNAME}{$envtype}{$envname}{'name'} = $envname;
		$ENV{$TALSIMANNAME}{$envtype}{$envname}{'value'} = $_->findvalue("./value");
		$ENV{$TALSIMANNAME}{$envtype}{$envname}{'qual'} = $_->findvalue("./qual");
		# We're going to store the current time here so we can see how old this value is and chose somthing better if it's 
		# really old. Also for cleaning the ENV hash.
		$ENV{$TALSIMANNAME}{$envtype}{$envname}{'age'}  = time();
	}
	print "     = TD - I = Response from Fetish $envname Stored. \n" if ($DEBUG >= 1);
}

### Simple little sub to return the avaialble environmentals currently stored by this talisman daemon. 
sub getEnvironmentals {
		my @available; 
		my $key;
	
		foreach $key (keys $ENV{$TALSIMANNAME}) {
			push (@available, $key);
		}
		return @available;
}

### Sub to craft an errror response to a client for an unexpected result of some kind. 
sub errresponse {

        my $msg = shift;
        my $xml = XML::LibXML::Document->new('1.0', 'utf-8');
        my $root;
        my $msgtag;
        my $typetag;

        # Create a new XML tree and format it as an error response with the msg provided to the sub.
        $root = $xml->createElement("$TALSIMANNAME");
        $xml->addChild($root);
        $typetag = $xml->createElement('msgtype');
        $typetag->addChild($xml->createTextNode("ERROR"));
        $root->addChild($typetag);
        $msgtag = $xml->createElement('msg');
        $msgtag->addChild($xml->createTextNode("$msg"));
        $root->addChild($msgtag);
        return $xml;
}

sub getInvocations {



}

### Sub to build an XML tree of the currently available environmnetals provied by this Talisman Daemon.
sub returnEnvCapbiliy {
	my @envavailable = @{$_[0]};
	my $root;
        my $key;
        my $fetval;
        my $fetqual;
        my $typetag;
        my $nametag;
        my $envtag;
        my $qualtag;
	my $bestqual;
	my $bestname;
        my $xml = XML::LibXML::Document->new('1.0', 'utf-8');

        # Create a new XML tree and build a table of all ENVs avaible and the best quaity for each. 
        $root = $xml->createElement("$TALSIMANNAME");
        $xml->addChild($root);
        $typetag = $xml->createElement('msgtype');
        $typetag->addChild($xml->createTextNode("ENVIRONMENTAL"));
        $root->addChild($typetag);
	# Run through our stored environemtnals and list the best quality for each proveded by this fetish.
        for $key (@envavailable) {
		$bestname, $bestqual = findBestEnvQual($key);
                $envtag = $xml->createElement('environmental');
                $root->addChild($envtag);
                $nametag = $xml->createElement('name');
                $envtag->addChild($nametag);
                $nametag->addChild($xml->createTextNode("$key"));
		$qualtag = $xml->createElement('qual');
		$envtag->addChild($qualtag);
		$qualtag->addChild($xml->createTextNode("$bestqual"));
        }
        return $xml;
}

sub returnInvCapbiliy {
        my @envavailable = @{$_[0]};

}

### Sub to find and return the highest quality value for a requested Environmental.
sub getAndReturnEnv {

	my $environmental = shift;
	my $fetish;
	my $envvalue;
	my $xml;
	my $qual;
	
	# Find the highest quality response for this environmental and retrn it. 
	$fetish, $qual = findBestEnvQual("$environmental");	
	$envvalue = $ENV{$TALSIMANNAME}{$environmental}{$fetish}{'value'};
	$xml = formEnvResponse($environmental, $envvalue);
	return($xml);

}

### Sub to find and return the fetish name with the best quality for the requested  environental. 
sub findBestEnvQual {

	my $environmental = shift;
	my $key;
        my $qual;
        my $highqual = -1;
        my $highname = "";
        my $envvalue;

	# Run through each fetish that returned a environmental of this type.
        foreach $key (keys $ENV{$TALSIMANNAME}{$environmental}) {
		if ($ENV{$TALSIMANNAME}{$environmental}{$key}{'qual'}) {
                	# Grab the quality for the current fetish if it's defined. 
                	$qual = $ENV{$TALSIMANNAME}{$environmental}{$key}{'qual'};
		} else {
			# set the default quality of the sensor to -1. i.e undefined. 
			$qual = -1;
		}
                # compare the quality to the current highest quality fetish indexed. This is -1 and none to start with.
                if ($qual >= $highqual) {
                        # if this fetish has a higher or equal quality than the current highest. Save it's name and 
                        # make it the new highscore and move on. 
                        $highname = $key;
                        $highqual = $qual;
                } else {
                        # else this is not better or equal to what we already have. Move on. 
                }

        }
	# at this point we should have a winner for the fetish with the highest quality measurement of this type. 
	return ($highname, $highqual);
}

### Sub to build and XML tree for en environmntal query and return it. 
sub formEnvResponse {
	my $environmntal = shift;
	my $envvalue = shift;
	my $root;
        my $typetag;
        my $nametag;
        my $envtag;
        my $valtag;
        my $xml = XML::LibXML::Document->new('1.0', 'utf-8');

        # Create a new XML tree and fill it with the data from the ENV hash, then return it. 
        $root = $xml->createElement("$TALSIMANNAME");
        $xml->addChild($root);
        $typetag = $xml->createElement('msgtype');
        $typetag->addChild($xml->createTextNode("ENVIRONMENTAL"));
        $root->addChild($typetag);
	$envtag = $xml->createElement('environmental');
	$root->addChild($envtag);
	$nametag = $xml->createElement('name');
	$envtag->addChild($nametag);
	$nametag->addChild($xml->createTextNode("$environmntal"));
	$valtag = $xml->createElement('value');
	$envtag->addChild($valtag);
	$valtag->addChild($xml->createTextNode("$envvalue"));
        return $xml;

}

### END OF LINE ###
