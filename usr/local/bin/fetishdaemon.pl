#!/usr/bin/pperl

######################################################################
######################################################################
## fetsihdaemon.pl: Generic Fetish daemon for managing and interfacing 
## to fetishes in the kinethesia framework. 
## 
## Written by Kai Rigby - 25/02/2014
##
## v1: 		First implementation of a Fetish Daemon for the 
##			Kinethesia SW/HW framework.
## v1.1: 	Adding proper XML handling of values for passing from
##			the FD to the TD.
## v1.2:	Made the Daemon generic so it can interface with many
## 			types of fetish to cut down on codebase.
## v1.3:	Almost complete re-write to use Lib::XML and much 
## 			cleaner code and commnting.

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

if (!$ARGV[0]) {
	print "\nUsage: fetishdaemon.pl <FETSH TYPE>. Available fetish types are defined in the documentation for kinethesia.\n\n";
	exit 1;
}

# Set up default values for the below. All values are overridable in the config file. 
my $FETISH = $ARGV[0];
my $DAEMON = 0;
my $DEBUG = 1;
my $DAEMONPORT = 2001;
my $BINDADDRESS = "127.0.0.1";
my $POLLPERIOD = 30;
my $SERVERKEY = "/etc/kinethesia/certs/server.key";
my $SERVERCRT = "/etc/kinethesia/certs/server.crt";
my $CLIENTCRT = "/etc/kinethesia/certs/client1.crt";
my $CLIENTKEY = "/etc/kinethesia/certs/client1.key";
my $CACRT = "/etc/kinethesia/certs/ca.crt";
my $CONFIGFILE = "/etc/kinethesia/talismandaemon.xml";
my $ALERTDAEMONADDR = "127.0.0.1";
my $ALERTDAEMONPORT = "1975";
# Create an XML parser engine for the program.
my $parser = XML::LibXML->new();
# Global hash for storing the env details returned by this FD.
my %ENV;

# Start the Daemon and load in the config file.
print "\n*** Starting Fetish Daemon for fetish $FETISH ***\n\n";
print "= I = Reading in config file: $CONFIGFILE\n";
my $cfg = loadAndParseConfig();
print "\n= I = Config file read\n";

# Check if the conig file has a section for the fetish called. 
if (!$cfg->findnodes("fd-$FETISH")) {
	print "\n= C = No config found in $CONFIGFILE for fetish: $FETISH. Exiting.\n\n";
	exit(0);
}

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

# POE session to gather data from the fetish and populate the global variables with their current values for serving
# to other clients/services at the configured pollperiod. Essentially a spinning timer. 
POE::Session->create(
	inline_states => {
		_start => sub {
			print "\n= I = Starting fetish polling Session with a polling period of $POLLPERIOD\n" if ($DEBUG == 1);
			$_[HEAP]->{next_alarm_time} = int(time());
			$_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
			print "= I = Fetish Polling session started\n" if ($DEBUG == 1);
		},
		# Every "tick" period, poll the fetish and do all the relevent tasks around that, then go back to sleep for the next pollperiod. 
		tick => sub {
			print "\n= I = Polling fetish for environmental values and populating variables\n" if ($DEBUG == 1);
			pollfetish();
			$_[HEAP]->{next_alarm_time} = $_[HEAP]->{next_alarm_time} + $POLLPERIOD;
                        $_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
		}
	}
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

### Sub to process input to the listening fetish daemon from the talisman daemon or other client. 
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
	$immediate = $xml->findvalue("/query/immediate");
	print "= I = Client command received :\n\n$buf\n" if ($DEBUG == 1);
	print "= SSL = Authing Client Command\n" if ($DEBUG == 1);
	if ($heap->{sslfilter}->clientCertValid()) {
		print "= SSL = Client Certificate Valid, Authorised\n" if ($DEBUG == 1);
		# If the talisman Daemon requests a realtime value from the fetish, update the values 
		# and return them. Note this will slow down the query response. 
		if ($immediate) {
			print "\n= I = Clint has requested realtime fetish values, refreshing.\n" if ($DEBUG == 1);
			pollfetish();
		}
		# The option is available here to query the Fetish Daemon for only specific values.
		# the decision at this time is to only ask for everything it has and filter to the 
		# shadow at the talisman daemon level. But this can be changed at a later time for 
		# additional filtering and traffic efficiency on low bandwidth links.
		if ($command eq "all") {
			# Send the client all environmntals, values and quality levels currently stored in the global hash.
			$response = allresponse();
		} elsif ($command eq "poll") {
			# if the client sends a "poll" type query, respond. Acts as a kepalive, if needed, from the client. 
			$response = pollreponse();
		} else {
			# We don't know what thety asked for, inform them with an error type message.
			$response = errresponse("Unknown query command sent to fetish daemon $FETISH");
		}
		if ($DEBUG == 1) {
			print "= I = Sending Client Result:\n\n";
			print $response->toString(1);
			print "\n";
		}
		# Send the client the actual XML.
		$heap->{socket_wheel}->put($response);
	} else {
		# The Client Certificate failed authentication. Be nice and tell them so then kick them off the server. 
		print "= SSL = Client Certificate Invalid! Rejecting command and disconnecting!\n" if ($DEBUG == 1);
		$response = errresponse("INVALID CERT! Connection rejected!");
		print "= I = Sending Client Result:\n$response\n" if ($DEBUG == 1);
		$heap->{socket_wheel}->put($response);
		$kernel->delay(socket_death => 1);
	}
}

# Start the POE Kernel and run all configured services. 
$poe_kernel->run();

#### NON POE subs below this line

### Sub to load the config file into the global cfg variable for all other parts of the program to query. Looks for specific 
### values that override defaults and populated them in order of preference: Default->Global->Specific.
sub loadAndParseConfig {

        my $cfgref = $parser->parse_file($CONFIGFILE);
        my $xml = $cfgref -> getDocumentElement();

	if ($xml->findvalue("fd-$FETISH/debug")) {
	        $DEBUG = $xml->findvalue("fd-$FETISH/debug");
        	print "\n    = I = Loading Debug Setting from config file: $DEBUG\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("fd-$FETISH/daemonport")) {
	        $DAEMONPORT = $xml->findvalue("fd-$FETISH/daemonport");
	        print "    = I = Loading daemon port from config file: $DAEMONPORT\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("GlobalFetishD/bindaddress")) {
	        $BINDADDRESS = $xml->findvalue("GlobalFetishD/bindaddress");
	        print "    = I = Loading Global bind address from config file: $BINDADDRESS\n" if ($DEBUG == 1);
	} elsif ($xml->findvalue("fd-$FETISH/bindaddress")) {
	        $BINDADDRESS = $xml->findvalue("fd-$FETISH/bindaddress");
	        print "    = I = Loading bind address from config file: $BINDADDRESS\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("GlobalFetishD/pollperiod")) {
	        $POLLPERIOD = $xml->findvalue("GlobalFetishD/pollperiod");
	        print "    = I = Loading Global poll period from config file: $POLLPERIOD\n" if ($DEBUG == 1);
	} elsif ($xml->findvalue("fd-$FETISH/pollperiod")) {
	        $POLLPERIOD = $xml->findvalue("fd-$FETISH/pollperiod");
	        print "    = I = Loading poll period from config file: $POLLPERIOD\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("GlobalFetishD/serverkey")) {
	        $SERVERKEY = $xml->findvalue("GlobalFetishD/serverkey");
	        print "    = I = Loading Global Server Key from config file: $SERVERKEY\n" if ($DEBUG == 1);
	} elsif ($xml->findvalue("fd-$FETISH/serverkey")) {
	        $SERVERKEY = $xml->findvalue("fd-$FETISH/serverkey");
	        print "    = I = Loading server key from config file: $SERVERKEY\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("GlobalFetishD/servercrt")) {
	        $SERVERCRT = $xml->findvalue("GlobalFetishD/servercrt");
	        print "    = I = Loading Global Server Certificate from config file: $SERVERCRT\n" if ($DEBUG == 1);
	} elsif ($xml->findvalue("fd-$FETISH/servercrt")) {
	        $SERVERCRT = $xml->findvalue("fd-$FETISH/servercrt");
	        print "    = I = Loading server certificate from config file: $SERVERCRT\n" if ($DEBUG == 1);
	}
	if ($xml->findvalue("GlobalFetishD/cacrt")) {
	        $CACRT = $xml->findvalue("GlobalFetishD/cacrt");
	        print "    = I = Loading Global CA Certificate from config file: $CACRT\n" if ($DEBUG == 1); 
	} elsif ($xml->findvalue("fd-$FETISH/cacrt")) {
	        $CACRT = $xml->findvalue("fd-$FETISH/cacrt");
	        print "    = I = Loading CA certificate from config file: $CACRT\n" if ($DEBUG == 1);
	}

	return $xml;
}

### Sub to craft an errror response to a client for an unexpected result of some kind. 
sub errresponse {

	my $msg = shift;
	my $xml = XML::LibXML::Document->new('1.0', 'utf-8');
	my $root;
	my $msgtag;
	my $typetag;

	# Create a new XML tree and format it as an error response with the msg provided to the sub.
	$root = $xml->createElement("$FETISH");
        $xml->addChild($root);
	$typetag = $xml->createElement('msgtype');
	$typetag->addChild($xml->createTextNode("ERROR"));
	$root->addChild($typetag);
	$msgtag = $xml->createElement('msg');
	$msgtag->addChild($xml->createTextNode("$msg"));
	$root->addChild($msgtag);
	return $xml;
}

### Sub to form a response to an environmental query from a client.
sub allresponse {

	my $root;
	my $key;
	my $fetval;
	my $fetqual;
	my $typetag;
	my $nametag;
	my $envtag;
	my $valtag;
	my $qualtag;
	my $xml = XML::LibXML::Document->new('1.0', 'utf-8');

	# Create a new XML tree and fill it with the data from the ENV hash, then return it. 
	$root = $xml->createElement("$FETISH");
	$xml->addChild($root);
	$typetag = $xml->createElement('msgtype');
	$typetag->addChild($xml->createTextNode("ENVIRONMENTAL"));
	$root->addChild($typetag);
	for $key (keys %ENV) {
		$fetval = $ENV{$key}{'value'};
		$fetqual = $ENV{$key}{'qual'};
		$envtag = $xml->createElement('environmental');
		$root->addChild($envtag);
		$nametag = $xml->createElement('name');
		$envtag->addChild($nametag);
		$nametag->addChild($xml->createTextNode("$key"));
		$valtag = $xml->createElement('value');
		$envtag->addChild($valtag);
		$valtag->addChild($xml->createTextNode("$fetval"));
		$qualtag = $xml->createElement('qual');
		$envtag->addChild($qualtag);
		$qualtag->addChild($xml->createTextNode("$fetqual"));
	}
        return $xml;
}

### Sub to form a response to a poll request from the Talisman Daemon.
sub pollreponse {

	my $response;
	my $msg;
	my $root;
	my $typetag;
	my $responsetag;
	my $valuetag;
	my $msgtag;

        my $xml = XML::LibXML::Document->new('1.0', 'utf-8');;
	$root = $xml->createElement("$FETISH");
	$xml->addChild($root);
	$typetag = $xml->createElement('msgtype');
        $typetag->addChild($xml->createTextNode("POLLRESPONSE"));
        $root->addChild($typetag);
	$responsetag = $xml->createElement('response');	
	$root->addChild($responsetag);
	$valuetag = $xml->createElement('value');
	$responsetag->addChild($valuetag);
	$valuetag->addChild($xml->createTextNode("OK"));
	$msgtag = $xml->createElement('msg');
	$responsetag->addChild($msgtag);
	$msgtag->addChild($xml->createTextNode(""));
        return $xml;
}

### Sub to poll the physical hardware, check the results, populate the global hash for this pollperiod and raise any alerts. 
sub pollfetish {

	my $envtemp;
	my $fetishresponse;
	my @environmentals;
	my %fetishvalues;

	#create an array containing the expected environmntal rsponses from the config file. 
	foreach ($cfg->findnodes("fd-$FETISH/environmental")) {
		foreach ($_->findnodes('./name')) {
			$envtemp = $_->textContent();
			push(@environmentals, $envtemp);
		}
	}
	# query the fetish and get the values it responds with.
	$fetishresponse = `/usr/local/bin/f-$FETISH.py`;
	chomp($fetishresponse);
	# if there was no response from the fetish, clear the values for reply and move on. 
	if (!$fetishresponse) {
		print "= W = No values from the Fetish! Fetish is either broken or not responding\n" if ($DEBUG == 1);
		undef %ENV;
		return(0);
	}
	#create a hash to store the responses from the fetish for ease of access.
	%fetishvalues = parseResponse($fetishresponse);

	# Compare expected environmentals against returned and make sure everything is as expected. This is mostly a debug sub.
	compareResults(\@environmentals, \%fetishvalues);
	
	# Populate the global environmentals hash for querying for this run of the poll.
	populateResults(\@environmentals, \%fetishvalues);
	
	# take the values returned and check them against any configured alert thresholds, then raise relevent alerts.
	raiseAlerts(\@environmentals);
	return(1);
}

### Sub to take expected responses, look at the configured responses and raise any alerts that are configured against this environmental variable.
sub raiseAlerts {
	my @expected = @{$_[0]};
	my $environmental;
	my @nodes;
	my $pollval;
	my $warnval;
	my $critval;

	print "= I = Examining returned values from fetish and raising any configured alerts\n\n" if ($DEBUG == 1);
	# run through each expected value and compare result against configured alerts (if they exist)
	foreach $environmental (@expected) { 
		if (!$ENV{$environmental}{'value'}) {
			# We have an expected value that was not returned. We already warned he user about this in debug. Might raise an INFO alert on this one day. 
			next;
		}
		# set the returned value and conigured alert values into some vars for ease of use (if configured).
		$pollval = $ENV{$environmental}{'value'};
		# find the cfg node that matches this environmental value
		@nodes = $cfg->findnodes("fd-$FETISH/environmental/name[text( )='$environmental']/..");
		# populate the various comparison values into variables. 
		foreach (@nodes) {
			$warnval = $_->findvalue("./warn");
			$critval = $_->findvalue("./crit");
		}
		# do some comparisons for alerts and warnings. 
		if ($critval) {
			if ($pollval >= $critval) {
				sendAlert($environmental, "CRITICAL", "CRITICAL ALERT: Polled value for $environmental of $pollval from $FETISH exceeds configured critical value of $critval!");
				print "    = C = CRITICAL!: Polled value for $environmental of $pollval exceeds configured critical value for this environmental of $critval! Raising CRITICAL ALERT\n" if ($DEBUG == 1);
			}
		} elsif ($warnval) {
			if ($pollval >= $warnval) {
				sendAlert($environmental, "WARNING", "WARNING: Polled value for $environmental of $pollval from $FETISH exceeds configured warning value of $warnval!");
				print "    = W = WARNING!: Polled value for $environmental of $pollval exceeds configured warning value for this environmental of $warnval! Raising WARNING ALERT\n" if ($DEBUG == 1);
			}
		}
		# reset the variables to undefined for next run or stuff carries over.
		$pollval = "";
		$warnval = "";
		$critval = "";
	}
	print "\n= I = Alerts and Warnings complete.\n\n"  if ($DEBUG == 1);
}

### Sub to Parse the response from the fetish itself and return a convenient hash of the values to use.
sub parseResponse {

	my $fetishresponse = shift;
	my %hash;
	my @values;
	my @temp;

	@values = split(',', $fetishresponse);
        # store the responses in a temp hash.
	foreach (@values) {
		@temp = split(':', $_);
		$hash{"$temp[0]"} = $temp[1];
	}
	return(%hash);
}

### Sub to compare the reuturned values of the fetish against the configured expected values. At this point mostly a debug sub.
sub compareResults  {
	my @expected = @{$_[0]};
	my %returned = %{$_[1]};
	my $returnedcount = 0;
	my $node_count;
	my $key;

	# Lets count how many values we got from the fetish and store if for comparison. 
	foreach (keys %returned) {
		$returnedcount++;
	}

	# First lets check if we got more values from the fetish than we were expecting from the config by counting the environmental nodes in the config and comparing to the count of returned. 
	$node_count = $cfg->findvalue("count(fd-$FETISH/environmental)");
	if ($node_count < $returnedcount) {
		# we have more responses than are configured. Lets tell the user about them if they care. 
		foreach $key (keys %returned) {
			if (!(grep {$_ eq $key} @expected)) {
				print "= W = Fetish returned environmental value $key that is not defined in your cfg file, have you forgotten to define an environmental? (You could just be filtering in which case ignore this message)\n" if ($DEBUG == 1);
			}
		}
	}
	# Now lets check if we didn't get a response from the fetish that we were expecting. 
	if ($node_count > $returnedcount) {
		# we have less responses than are configured. Lets tell the user about it if they care. 
		foreach (@expected) {
			if (!$returned{$_}) {
				print "= W = Fetish did not provide environmental $_ that is defined in the cfg file, Are you sure this fetish can give you this value?\n" if ($DEBUG == 1);
			}
		}
	}
	return(1);
}

### Sub to take our temp hash of responses and populte it into the global hash for the next pollperiod to be returned to any querying clients. 
sub populateResults {
	my @expected = @{$_[0]};
	my %returned = %{$_[1]};
	my $key;
	my @nodes;
	my $qualval;
	my $pollval;

	print "\n= I = Populating the Environmntal Hash with returned values\n\n" if ($DEBUG == 1);
	foreach $key (@expected) {
		# if there is no response from the fetish for this env type, skip on to the next we've already told the user if they cared. 
		if (!$returned{"$key"}) {
			next;
		}
		# find the cfg node that matches this env value. Must be an array, because LibXML
		@nodes = $cfg->findnodes("fd-$FETISH/environmental/name[text( )='$key']/..");
		# populate the qual value into a variable. 
		foreach (@nodes) {
			$qualval = $_->findvalue("./qual");
			chomp($qualval);
		}
		$pollval = $returned{"$key"};
		chomp($pollval);
		# assign the expected returned values to the response hash.
		print "    = I = Populating the Environmntal Hash for Environmental $key with Value: $pollval and Quality: $qualval\n" if ($DEBUG == 1);
		$ENV{"$key"}{'value'} = $pollval;
		$ENV{"$key"}{'qual'} = $qualval;
	}
	print "\n= I = Environmntal Hash Populated\n\n" if ($DEBUG == 1);
	return(1);
}

sub sendAlert {
	my $environmental = shift;
	my $level = shift;
	my $msg = shift;
	my $xml;

	POE::Component::Client::TCP->new(
		RemoteAddress => $ALERTDAEMONADDR,
    		RemotePort    => $ALERTDAEMONPORT,
    		Filter        => [ "POE::Filter::SSL", crt => $CLIENTCRT, key => $CLIENTKEY, client => 1 ],
    		Connected     => sub {
			$xml = formAlert($environmental, $level, $msg);
			$_[HEAP]{server}->put($xml);
		},
		ServerInput   => sub {
			delete $_[HEAP]->{server};
		},
	);
}

sub formAlert {
	my $environmental = shift;
	my $level = shift;
	my $msg = shift;
        my $root;
	my $envtag;
	my $alerttag;
        my $typetag;
        my $leveltag;
        my $msgtag;

        my $xml = XML::LibXML::Document->new('1.0', 'utf-8');;
        $root = $xml->createElement("$FETISH");
        $xml->addChild($root);
        $typetag = $xml->createElement('msgtype');
        $typetag->addChild($xml->createTextNode("ALERT"));
        $root->addChild($typetag);
	$alerttag = $xml->createElement('alert');
	$root->addChild($alerttag);
	$envtag = $xml->createElement('environmental');
	$alerttag->addChild($envtag);
	$envtag->addChild($xml->createTextNode("$environmental"));
        $leveltag = $xml->createElement('level');
        $alerttag->addChild($leveltag);
	$leveltag->addChild($xml->createTextNode("$level"));
        $msgtag = $xml->createElement('msg');
        $alerttag->addChild($msgtag);
        $msgtag->addChild($xml->createTextNode("$msg"));
        return $xml;
}


### END OF LINE ###
