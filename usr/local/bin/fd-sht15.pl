#!/usr/bin/perl

######################################################################
######################################################################
## fd-sht15.pl: Fetish daemon for managing and interfacing to the
## sht15 digital humidity and temperature sensor.
## 
## Written by Kai Rigby - 25/02/2014
##
## v1: 		First implementation of a Fetish Daemon for the 
##			Kinethesia SW/HW framework.
##

use strict;
use warnings;
use Data::Dumper; 
use Socket;
use XML::Simple;
use Config::IniFiles;
use POE qw(
	Wheel::SocketFactory
	Wheel::ReadWrite
	Driver::SysRW
	Filter::SSL
	Filter::Stackable
	Filter::Stream
);

my $configfile = "/home/pi/c0de/fetish-daemons/fd-sht15/talismandaemon.conf";
my %cfg;
print "= I = Reading in config file: $configfile\n";
tie %cfg, 'Config::IniFiles', ( -file => $configfile );
print "= I = Config file read\n";

# Set up default values or the below. All overridable in the config file. 
my $daemon = 0;
my $debug = 0;
my $daemonport = 2001;
my $bindaddress = "127.0.0.1";
my $pollperiod = 30;
my $serverkey = "/etc/kinethesia/certs/server.key";
my $servercrt = "/etc/kinethesia/certs/server.crt";
my $cacrt = "/etc/kinethesia/certs/ca.crt";

if ($cfg{'fd-sht15'}{'debug'}) {
	$debug = $cfg{'fd-sht15'}{'debug'};
	print "\n= I = Loading Debug Setting from config file: $debug\n" if ($debug == 1);
}
if ($cfg{'fd-sht15'}{'daemonport'}) {
	$daemonport = $cfg{'fd-sht15'}{'daemonport'};
	print "= I = Loading daemon port from config file: $daemonport\n" if ($debug == 1);
}
if ($cfg{'fd-sht15'}{'bindaddress'}) {
	$bindaddress = $cfg{'fd-sht15'}{'bindaddress'};
	print "= I = Loading bind address from config file: $bindaddress\n" if ($debug == 1);
}
if ($cfg{'fd-sht15'}{'pollperiod'}) {
	$pollperiod = $cfg{'fd-sht15'}{'pollperiod'};
	print "= I = Loading poll period from config file: $pollperiod\n" if ($debug == 1);
}
if ($cfg{'fd-sht15'}{'serverkey'}) {
	$serverkey = $cfg{'fd-sht15'}{'serverkey'};
	print "= I = Loading server key from config file: $serverkey\n" if ($debug == 1);
}
if ($cfg{'fd-sht15'}{'servercrt'}) {
	$servercrt = $cfg{'fd-sht15'}{'servercrt'};
	print "= I = Loading server certificate from config file: $servercrt\n" if ($debug == 1);
}
if ($cfg{'fd-sht15'}{'cacrt'}) {
	$cacrt = $cfg{'fd-sht15'}{'cacrt'};
	print "= I = Loading CA certificate from config file: $cacrt\n" if ($debug == 1);
}



# Environmentals provided by this server
my $temp = 0;
my $humidity = 0;
my $dewpoint = 0;


if ($daemon) {
        fork and exit;
}

# set print to flush immediatly, this is for the when debug is set high 
# and needs to print to term.
$| = 1;

# read in the config then start all the POE sessions.
# readconfig():

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
			print "\n= I = Starting fetish polling Session with a polling period of $pollperiod\n" if ($debug == 1);
#			$_[HEAP]->{next_alarm_time} = int(time()) + $pollperiod;
			$_[HEAP]->{next_alarm_time} = int(time());
			$_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
			print "= I = Fetish Polling session started\n" if ($debug == 1);
		},

		tick => sub {
			my @values;
			print "\n= I = Polling fetish for environmental values and populating variables\n" if ($debug == 1);
			@values = split(',', `/usr/local/bin/f-sht15.py`);
			$temp = $values[0];
			$humidity = $values[1];
			$dewpoint = $values[2];
			chomp($temp);
			chomp($humidity);
			chomp($dewpoint);
			print "= I = Values populated : $temp, $humidity, $dewpoint\n" if ($debug == 1);
			$_[HEAP]->{next_alarm_time} = $_[HEAP]->{next_alarm_time} + $pollperiod;
                        $_[KERNEL]->alarm(tick => $_[HEAP]->{next_alarm_time});
		}
	}
);


sub parent_start {
	my $heap = $_[HEAP];

	print "\n= I = Starting POE session and initialising socket\n" if ($debug == 1);
	$heap->{listener} = POE::Wheel::SocketFactory->new(
		BindAddress  => $bindaddress,
		BindPort     => $daemonport,
		Reuse        => 'yes',
		SuccessEvent => 'socket_birth',
		FailureEvent => 'socket_death',
  	);
	print "= I = Socket initialised on $bindaddress:$daemonport Waiting for connections\n" if ($debug == 1);
}

# clean up if we shut down the server
sub parent_stop {
	my $heap = $_[HEAP];
	delete $heap->{listener};
	delete $heap->{session};
	print "= I = Listener Death!\n" if ($debug == 1);
}


# open the socket for the remote session.
sub socket_birth {
	my ($socket, $address, $port) = @_[ARG0, ARG1, ARG2];

	$address = inet_ntoa($address);
	print "\n= S = Socket birth client connecting\n" if ($debug == 1);

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
		print "= S = Socket death, client disconnected\n" if ($debug == 1);
		delete $heap->{socket_wheel};
	}
}

#  yay! we sucessfully opened a socket. Set up the session.
sub socket_success {
	my ($heap, $kernel, $connected_socket, $address, $port) = @_[HEAP, KERNEL, ARG0, ARG1, ARG2];
	
	print "= I = CONNECTION from $address : $port \n" if ($debug == 1);
	print "= SSL = Creating SSL Object\n" if ($debug == 1);
	$heap->{sslfilter} = POE::Filter::SSL->new(
		crt    => 'keys/server.crt',
		key    => 'keys/server.key',
		cacrt  => 'keys/ca.crt',
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
	print "= SSL = SSL Socket Created\n" if ($debug == 1);
}

sub socket_input {
	my ($heap, $kernel, $buf) = @_[HEAP, KERNEL, ARG0];
	my $response = "";
	my $value = "";
	my $sub;
	chomp($buf);
	print "= I = Clint command received : $buf\n" if ($debug == 1);
	print "= SSL = Authing Client Command\n" if ($debug == 1);
	if ($heap->{sslfilter}->clientCertValid()) {
		print "= SSL = Client Certificate Valid, Authorised\n" if ($debug == 1);
		if ($buf eq "temp") {
			$value = $temp;
		} elsif ($buf eq "dewpoint") { 
			$value = $dewpoint;
		} elsif ($buf eq "humidity") {
			$value = $humidity;
		} else {
			$value = "Unknown request\n";
		}
		$response = $value;
		print "= I = Sending Client Result:  $response\n" if ($debug == 1);
		$heap->{socket_wheel}->put($response);
	} else {
		print "= SSL = Client Certificate Invalid! Rejecting command and disconnecting!\n" if ($debug == 1);
		$response = "INVALID CERT! Connection rejected!\n";
		print "= I = Sending Client Result:  $response\n" if ($debug == 1);
		$heap->{socket_wheel}->put($response);
		$kernel->delay(socket_death => 1);
	}
}

$poe_kernel->run();