#!/usr/bin/perl

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

if (!$ARGV[0]) {
	print "\nUsage: fetishdaemon.pl <FETSH TYPE>. Available fetish types are defined in the documentation for kinethesia.\n\n";
	exit 1;
}
my $FETISH = $ARGV[0];
print "\n*** Starting Fetish Daemon for fetish $FETISH ***\n\n";
my $CONFIGFILE = "/etc/kinethesia/talismandaemon.xml";
print "= I = Reading in config file: $CONFIGFILE\n";
my $parser = XML::LibXML->new();
my $cfgref = $parser->parse_file($CONFIGFILE);
my $cfg = $cfgref -> getDocumentElement();
print "= I = Config file read\n";

if (!$cfg->findnodes("fd-$FETISH")) {
	print "\n= C = No config found in $CONFIGFILE for fetish: $FETISH. Exiting.\n\n";
	exit(0);
}

# Set up default values or the below. All values are overridable in the config file. 
my $DAEMON = 0;
my $DEBUG = 0;
my $DAEMONPORT = 2001;
my $BINDADDRESS = "127.0.0.1";
my $POLLPERIOD = 30;
my $SERVERKEY = "/etc/kinethesia/certs/server.key";
my $SERVERCRT = "/etc/kinethesia/certs/server.crt";
my $CACRT = "/etc/kinethesia/certs/ca.crt";

if ($cfg->findvalue("fd-$FETISH/debug")) {
	$DEBUG = $cfg->findvalue("fd-$FETISH/debug");
	print "\n= I = Loading Debug Setting from config file: $DEBUG\n" if ($DEBUG == 1);
}
if ($cfg->findvalue("fd-$FETISH/daemonport")) {
	$DAEMONPORT = $cfg->findvalue("fd-$FETISH/daemonport");
	print "= I = Loading daemon port from config file: $DAEMONPORT\n" if ($DEBUG == 1);
}
if ($cfg->findvalue("GlobalFetishD/bindaddress")) {
	$BINDADDRESS = $cfg->findvalue("GlobalFetishD/bindaddress");
	print "= I = Loading Global bind address from config file: $BINDADDRESS\n" if ($DEBUG == 1);
} elsif ($cfg->findvalue("fd-$FETISH/bindaddress")) {
	$BINDADDRESS = $cfg->findvalue("fd-$FETISH/bindaddress");
	print "= I = Loading bind address from config file: $BINDADDRESS\n" if ($DEBUG == 1);
}
if ($cfg->findvalue("GlobalFetishD/pollperiod")) {
        $POLLPERIOD = $cfg->findvalue("GlobalFetishD/pollperiod");
	print "= I = Loading Global poll period from config file: $POLLPERIOD\n" if ($DEBUG == 1);
} elsif ($cfg->findvalue("fd-$FETISH/pollperiod")) {
        $POLLPERIOD = $cfg->findvalue("fd-$FETISH/pollperiod");
	print "= I = Loading poll period from config file: $POLLPERIOD\n" if ($DEBUG == 1);
}
if ($cfg->findvalue("GlobalFetishD/serverkey")) {
	$SERVERKEY = $cfg->findvalue("GlobalFetishD/serverkey");
	print "= I = Loading Global Server Key from config file: $SERVERKEY\n" if ($DEBUG == 1);
} elsif ($cfg->findvalue("fd-$FETISH/serverkey")) {
	$SERVERKEY = $cfg->findvalue("fd-$FETISH/serverkey");
	print "= I = Loading server key from config file: $SERVERKEY\n" if ($DEBUG == 1);
}
if ($cfg->findvalue("GlobalFetishD/servercrt")) {
	$SERVERCRT = $cfg->findvalue("GlobalFetishD/servercrt");
	print "= I = Loading Global Server Certificate from config file: $SERVERCRT\n" if ($DEBUG == 1);
} elsif ($cfg->findvalue("fd-$FETISH/servercrt")) {
	$SERVERCRT = $cfg->findvalue("fd-$FETISH/servercrt");
	print "= I = Loading server certificate from config file: $SERVERCRT\n" if ($DEBUG == 1);
}
if ($cfg->findvalue("GlobalFetishD/cacrt")) {
	$CACRT = $cfg->findvalue("GlobalFetishD/cacrt");
	print "= I = Loading Global CA Certificate from config file: $CACRT\n" if ($DEBUG == 1); 
} elsif ($cfg->findvalue("fd-$FETISH/cacrt")) {
	$CACRT = $cfg->findvalue("fd-$FETISH/cacrt");
	print "= I = Loading CA certificate from config file: $CACRT\n" if ($DEBUG == 1);
}

# Global hash for storing the env details returned by this FD.
my %ENV;

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
# to other clients/services.
POE::Session->create(
	inline_states => {
		_start => sub {
			print "\n= I = Starting fetish polling Session with a polling period of $POLLPERIOD\n" if ($DEBUG == 1);
			$_[HEAP]->{next_alarm_time} = int(time());
			$_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
			print "= I = Fetish Polling session started\n" if ($DEBUG == 1);
		},

		tick => sub {
			print "\n= I = Polling fetish for environmental values and populating variables\n" if ($DEBUG == 1);
			pollfetish();
			$_[HEAP]->{next_alarm_time} = $_[HEAP]->{next_alarm_time} + $POLLPERIOD;
                        $_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
		}
	}
);


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

# clean up if we shut down the server
sub parent_stop {
	my $heap = $_[HEAP];
	delete $heap->{listener};
	delete $heap->{session};
	print "= I = Listener Death!\n" if ($DEBUG == 1);
}


# open the socket for the remote session.
sub socket_birth {
	my ($socket, $address, $port) = @_[ARG0, ARG1, ARG2];

	$address = inet_ntoa($address);
	print "\n= S = Socket birth client connecting\n" if ($DEBUG == 1);

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

# close the socket session when the user exits.
sub socket_death {
	my $heap = $_[HEAP];
	if ($heap->{socket_wheel}) {
		print "= S = Socket death, client disconnected\n" if ($DEBUG == 1);
		delete $heap->{socket_wheel};
	}
}

#  yay! we sucessfully opened a socket. Set up the session.
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

sub socket_input {
	my ($heap, $kernel, $buf) = @_[HEAP, KERNEL, ARG0];
	my $response = "";
	my $sub;
	my $command = "";
	my $immediate = 0;
	my $refresh;
	my $ref;
	my $xml;

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
		# The option is available here ti query the Fetish Daemon for only specific values.
		# the decision at this time is to only ask for everything it has and filter to the 
		# shadow at the telisman daemon level. But this can be changed at a later time for 
		# additional filtering and traffic efficiency on low bandwidth links.
		if ($command eq "all") {
			$response = allresponse();
		} elsif ($command eq "poll") {
			$response = pollreponse();
		} else {
			$response = errresponse("Unknown query command sent to fetish daemon $FETISH");
		}
		if ($DEBUG == 1) {
			print "= I = Sending Client Result:\n\n";
			print $response->toString(1);
			print "\n";
		}
		$heap->{socket_wheel}->put($response);
	} else {
		print "= SSL = Client Certificate Invalid! Rejecting command and disconnecting!\n" if ($DEBUG == 1);
		$response = errresponse("INVALID CERT! Connection rejected!");
		print "= I = Sending Client Result:\n$response\n" if ($DEBUG == 1);
		$heap->{socket_wheel}->put($response);
		$kernel->delay(socket_death => 1);
	}
}

$poe_kernel->run();

#### NON POE subs below this line

sub errresponse {

	my $msg = shift;
	my $xml = XML::LibXML::Document->new('1.0', 'utf-8');
	my $root;
	my $msgtag;
	my $typetag;

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
	
sub pollfetish {

	my @values;
	my @temp;
	my $key;
	my $envtemp;
	my %keyval;
	my $node_cnt = 0;
	my @nodes;
	my $node;
	my $fetishresponse;
	my @environmentals;
	my $pollval;
	my $critval;
	my $warnval;
	my $qualval;

	$fetishresponse = `/usr/local/bin/f-$FETISH.py`;
	chomp($fetishresponse);
	if (!$fetishresponse) {
		print "= W = No values from the Fetish! Fetish is either broken or not responding\n" if ($DEBUG == 1);
		undef %ENV;
	} else {
		@values = split(',', $fetishresponse);	
		# store the responses in a temp hash.
                foreach (@values) {
                        @temp = split(':', $_);
                        $keyval{"$temp[0]"} = $temp[1];
                }
		#first lets make sure we have as many environmentals defined as were returned.
		my $node_cnt = $cfg->findvalue("count(fd-$FETISH/environmental)");
		if ($node_cnt < @values) {
			print "= W = Fetish returned more environmental values than are defined in your cfg file, have you forgotten to define an environmental? (You could just be filtering in which case ignore this message)\n" if ($DEBUG == 1);
		} 
		# now lts make sure we actually got all the values we expected from the config.
		foreach ($cfg->findnodes("fd-$FETISH/environmental")) {
    			foreach ($_->findnodes('./name')) {
				$envtemp = $_->textContent();
				#create an array of expected respones to hand up the the talismandaemon.
				push(@environmentals, $envtemp);	
				if (!$keyval{$envtemp}) {
					print "= W = Fetish did not provide environmental $envtemp that is defined in the cfg file, Are you sure this fetish can give you this value?\n" if ($DEBUG == 1);
				}
  			}
		}
		# Now lets go through our list of expected responses and make sure we don't have to raise any alerts based on the responses.
		foreach $key (@environmentals) {
			# if there is no response from the fetish for this env type, skip on to the next. 
			if (!$keyval{"$key"}) {
				next;
			}
			# find the cfg node that matches this env value.
                        @nodes = $cfg->findnodes("fd-$FETISH/environmental/name[text( )='$key']/..");
			# populate the various comparison values into variables. 
                        foreach (@nodes) {
                                $warnval = $_->findvalue("./warn");
                                $critval = $_->findvalue("./crit");
                                $qualval = $_->findvalue("./qual");
                        }
			$pollval = $keyval{"$key"};
			# assign the expected returned values to the response hash.
			$ENV{"$key"}{'value'} = $keyval{"$key"};
			$ENV{"$key"}{'qual'} = $qualval;
			# do some comparisons for alerts and warnings. 
			if ($critval) {
				if ($ENV{"$key"}{'value'} >= $critval) {
					print "= C = CRITICAL!: Polled value for $key of $pollval exceeds configured critical value for this environmental of $critval! Raising CRITICAL ALERT\n" if ($DEBUG == 1);
				}
			} elsif ($warnval) {
				if ($ENV{"$key"}{'value'} >= $warnval) {
					print "= W = WARNING!: Polled value for $key of $pollval exceeds configured warning value for this environmental of $warnval! Raising WARNING ALERT\n" if ($DEBUG == 1);
				}
			}
			# reset the variables for the next environmental in case they are undefiend and as such carry over.
			$pollval = "";
			$warnval = "";
			$critval = "";
			$qualval = "";
		}
		if ($DEBUG == 1) {
			print "= I = Values populated : ";
			foreach $key (keys(%ENV)) {
				print "$key:$ENV{$key}{'value'}, qual : $ENV{$key}{'qual'} ";
			}
			print "\n";
		}
	}
}
### END OF LINE ###
