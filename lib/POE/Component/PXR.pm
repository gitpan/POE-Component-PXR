package POE::Component::PXR;

use warnings;
use strict;
use FindBin qw/ $Bin /;
use lib "$Bin";

use POE qw/ Wheel::ReadWrite Component::Client::TCP Filter::Stream /;
use POE::Filter::XML;
use PXR::Node;
use PXR::NS qw/ :SERVICE :IQ /;

our $VERSION = '0.1.1';

sub new()
{
	my $class = shift;
	my $me = $class . '->new()';
	die "$me requires an even number of arguments" if(@_ & 1);
	
	my $args = {};
	while($#_ != -1)
	{
		my $key = lc(shift(@_));
		my $value = shift(@_);
		if(ref($value) eq 'HASH')
		{
			my $hash = {};
			foreach my $sub_key (keys %$value)
			{
				$hash->{lc($sub_key)} = $value->{$sub_key};
			}
			$args->{$key} = $hash;
			next;
		}
		$args->{$key} = $value;
	}

	$args->{'alias'} = 'POE::Component::PXR' if not defined $args->{'alias'};
	die "$me requires InitFinish to be defined" if not defined
		$args->{'states'}->{'initfinish'};
	
	POE::Component::Client::TCP->new
	(
#		SessionParams => [ options => { debug => 1, trace => 1 } ],
		RemoteAddress => $args->{'ip'},
		RemotePort => $args->{'port'},
		ConnectTimeout => 5,
		
		Filter => 'POE::Filter::Stream',

		Connected => \&init_connection,
		Disconnected => \&disconnected,

		ServerInput => \&initial_input,
		ServerError => \&server_error,

		InlineStates => {
			input_handler => \&input_handler,
			output_handler => \&output_handler,
			stage_two => \&stage_two,
			shutdown_socket => \&shutdown_socket,
			get_jid => \&get_jid,
			set_jid => \&set_jid,
			set_state => \&set_state,
			set_auth => \&set_auth,
			set_reg => \&set_reg,
			disco_query => \&disco_query,
			return_to_sender => \&return_to_sender,
		},
		
		Alias => $args->{'alias'},
		Started => \&start,
		Args => [ $args ],

	);
	
}

sub get_jid()
{
	my ($self, $kernel, $heap, $session, $event) = 
		@_[SESSION, KERNEL, HEAP, SENDER, ARG0];
	
	++$heap->{'id'};
	$heap->{'PENDING'}->{$heap->{'id'}}->[0] = $session;
	$heap->{'PENDING'}->{$heap->{'id'}}->[1] = $event;

	my $node = PXR::Node->new('iq');
	$node->attr('to', $heap->{'CONFIG'}->{'hostname'});
	$node->attr('type', +IQ_GET);
	$node->attr('id', $heap->{'id'});
	$node->insert_tag('query', +NS_JID);
	
	$kernel->call($self, 'output_handler', $node);
}

sub return_to_sender()
{
	my ($self, $kernel, $heap, $session, $event, $node) = 
		@_[SESSION, KERNEL, HEAP, SENDER, ARG0, ARG1];
	
	++$heap->{'id'};
	$heap->{'PENDING'}->{$heap->{'id'}}->[0] = $session;
	$heap->{'PENDING'}->{$heap->{'id'}}->[1] = $event;
	
	my $attrs = $node->get_attrs();

	if(exists($attrs->{'id'}))
	{
		warn $node->to_str();
		warn "Overwriting pre-existing 'id'!";
	}
	
	$node->attr('id', $heap->{'id'});
	$kernel->call($self, 'output_handler', $node);
}

sub set_jid()
{
	my ($self, $kernel, $heap, $session, $event, $jid) =
		@_[SESSION, KERNEL, HEAP, SENDER, ARG0, ARG1];

	++$heap->{'id'};
	$heap->{'PENDING'}->{$heap->{'id'}}->[0] = $session;
	$heap->{'PENDING'}->{$heap->{'id'}}->[1] = $event;

	my $node = PXR::Node->new('iq');
	$node->attr('to', $heap->{'CONFIG'}->{'hostname'});
	$node->attr('from', $jid);
	$node->attr('type', +IQ_SET);
	$node->attr('id', $heap->{'id'});
	$node->insert_tag('query', +NS_JID)->insert_tag('jid')->data($jid);

	$kernel->call($self, 'output_handler', $node);
}

sub set_state()
{
	my ($self, $kernel, $heap, $session, $event, $jid, $state) =
	@_[SESSION, KERNEL, HEAP, SENDER, ARG0 .. ARG2];

	++$heap->{'id'};
	$heap->{'PENDING'}->{$heap->{'id'}}->[0] = $session;
	$heap->{'PENDING'}->{$heap->{'id'}}->[1] = $event;

	my $node = PXR::Node->new('iq');
	$node->attr('to', $heap->{'CONFIG'}->{'hostname'});
	$node->attr('from', $jid);
	$node->attr('type', +IQ_SET);
	$node->attr('id', $heap->{'id'});
	my $state_tag = $node->insert_tag('query', +NS_STATE)->insert_tag('state');
	$state_tag->attr('type', $state);

	$kernel->call($self, 'output_handler', $node);
}

sub set_auth()
{
	my ($self, $kernel, $heap, $session, $event, $jid, $name, $password) =
	@_[SESSION, KERNEL, HEAP, SENDER, ARG0 .. ARG3];

	++$heap->{'id'};
	$heap->{'PENDING'}->{$heap->{'id'}}->[0] = $session;
	$heap->{'PENDING'}->{$heap->{'id'}}->[1] = $event;

	my $node = PXR::Node->new('iq');
	$node->attr('to', $heap->{'CONFIG'}->{'hostname'});
	$node->attr('from', $jid);
	$node->attr('type', +IQ_SET);
	$node->attr('id', $heap->{'id'});
	my $query = $node->insert_tag('query', +NS_AUTH);
	$query->insert_tag('name')->data($name);
	$query->insert_tag('password')->data($password);

	$kernel->call($self, 'output_handler', $node);
}

sub set_reg()
{
	my ($self, $kernel, $heap, $session, $event, $jid, $name, $password) =
	@_[SESSION, KERNEL, HEAP, SENDER, ARG0 .. ARG3];

	++$heap->{'id'};
	$heap->{'PENDING'}->{$heap->{'id'}}->[0] = $session;
	$heap->{'PENDING'}->{$heap->{'id'}}->[1] = $event;

	my $node = PXR::Node->new('iq');
	$node->attr('to', $heap->{'CONFIG'}->{'hostname'});
	$node->attr('from', $jid);
	$node->attr('type', +IQ_SET);
	$node->attr('id', $heap->{'id'});
	my $query = $node->insert_tag('query', +NS_REGISTER);
	$query->insert_tag('name')->data($name);
	$query->insert_tag('password')->data($password);

	$kernel->call($self, 'output_handler', $node);
}

sub disco_query()
{
	my ($self, $kernel, $heap, $session, $event, $jid, $path, $bool) =
	@_[SESSION, KERNEL, HEAP, SENDER, ARG0 .. ARG3];
	
	++$heap->{'id'};
	$heap->{'PENDING'}->{$heap->{'id'}}->[0] = $session;
	$heap->{'PENDING'}->{$heap->{'id'}}->[1] = $event;

	my $node = PXR::Node->new('iq');
	$node->attr('to', $heap->{'CONFIG'}->{'hostname'});
	$node->attr('from', $jid);
	$node->attr('type', +IQ_GET);
	$node->attr('id', $heap->{'id'});

	if($bool)
	{
		$node->insert_tag('query', +NS_DISCOINFO)->attr('node', $path);
		
	} else {

		$node->insert_tag('query', +NS_DISCOITEMS)->attr('node', $path);
	}

	$kernel->call($self, 'output_handler', $node);
}

sub start()
{
	my ($session, $kernel, $heap, $config) = @_[SESSION, KERNEL, HEAP, ARG0];
	
	$heap->{'CONFIG'} = $config;
	$heap->{'callback'} = sub{ $kernel->call($session, 'parse_error'); };
	$heap->{'id'} = 0;
}

sub init_connection()
{
	my ($session, $kernel, $heap, $socket) = @_[SESSION, KERNEL, HEAP, ARG0];

	$heap->{'socket'} = $socket;
	my $foundation = $heap->{'CONFIG'};
	my $host = $foundation->{'hostname'};
	my $xmlns = $foundation->{'xmlns'};
	my $stream = $foundation->{'stream'};

	$kernel->call($session, 'output_handler', 
		"<stream:stream to='$host' xmlns:stream='$stream' xmlns='$xmlns'>"
	);

	return;
}

sub disconnected()
{
	delete $_[HEAP]->{'callback'};
}

sub initial_input()
{
	my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];

	$heap->{'init_buffer'} .= $data;

	if($heap->{'init_buffer'} =~ /\<stream:stream(.*?)\>/s)
	{	
		$kernel->yield('stage_two');
		
	} else {
	
		warn $heap->{'init_buffer'};
	}
}

sub stage_two()
{
	my ($session, $kernel, $heap) = @_[SESSION, KERNEL, HEAP];
	
	my $w_callback = $heap->{'callback'};
	my $filter = POE::Filter::XML->new($heap->{'init_buffer'}, $w_callback);

	delete $heap->{'init_buffer'};

	if(not $filter)
	{
		$kernel->call($session, 'shutdown_socket', '1');
		die "Bad XML from the server";
	}
	
	delete $heap->{'server'};
	my $socket = $heap->{'socket'};
	$heap->{'server'} = POE::Wheel::ReadWrite->new(
		Handle			=> $socket,
		Filter			=> $filter,
		InputEvent		=> 'input_handler',
		ErrorEvent		=> 'got_server_error',
		FlushedEvent	=> 'got_server_flush',
	);
	delete $heap->{'socket'};
	
	$kernel->post($heap->{'CONFIG'}->{'state_parent'},
		$heap->{'CONFIG'}->{'states'}->{'initfinish'});
}

sub shutdown_socket()
{
	my ($kernel, $time) = @_[KERNEL, ARG0];

	$kernel->delay('shutdown', $time);
	return;
}

sub output_handler()
{
	my ($heap, $data) = @_[HEAP, ARG0];
	
	$heap->{'server'}->put($data);
	return;
}

sub input_handler()
{
	my ($session, $kernel, $heap, $data) = @_[SESSION, KERNEL, HEAP, ARG0];
	my $attrs = $data->get_attrs();
	if(exists($attrs->{'id'}))
	{
		if(defined($heap->{'PENDING'}->{$attrs->{'id'}}))
		{
			my $array = delete $heap->{'PENDING'}->{$attrs->{'id'}};
			$kernel->post($array->[0], $array->[1], $data);
			return;
		}
	}
	
	$kernel->post($heap->{'CONFIG'}->{'state_parent'}, 
		$heap->{'CONFIG'}->{'states'}->{'inputevent'} , $data);

	return;
}

sub server_error()
{
	my ($session, $kernel, $call, $code, $err) = 
		@_[SESSION, KERNEL, ARG0..ARG2];
	
	print "Server Error: $call: $code -> $err\n";
}

sub parse_error()
{
	die "SEVERE PARSING ERROR";
}

1;
