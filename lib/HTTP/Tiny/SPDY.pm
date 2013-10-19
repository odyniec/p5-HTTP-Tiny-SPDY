package HTTP::Tiny::SPDY;

use strict;
use warnings;

# ABSTRACT: A subclass of HTTP::Tiny with SPDY support

# VERSION

use HTTP::Tiny;
use Net::SPDY::Session;

use parent 'HTTP::Tiny';

my @attributes;
BEGIN {
    @attributes = qw(enable_SPDY handle_class);
    no strict 'refs';
    for my $accessor (@attributes) {
        *{$accessor} = sub {
            @_ > 1 ? $_[0]->{$accessor} = $_[1] : $_[0]->{$accessor};
        };
    }
}

=method new

    $http = HTTP::Tiny::SPDY->new( %attributes );

Constructor that returns a new HTTP::Tiny::SPDY object. It accepts the same
attributes as the constructor of HTTP::Tiny, and one additional attribute:

=for :list
* C<enable_SPDY>
A boolean that indicates if a SPDY connection should be negotiated for HTTPS
requests (default is true)

=cut

sub new {
    my ($class, %args) = @_;

    my $self = $class->SUPER::new(%args);

    $self->{enable_SPDY} = exists $args{enable_SPDY} ? $args{enable_SPDY} : 1;
    $self->{handle_class} = 'HTTP::Tiny::Handle::SPDY';

    return $self;
}

my %DefaultPort = (
    http => 80,
    https => 443,
);
 
package
    HTTP::Tiny::Handle::SPDY;

use strict;
use warnings;

use IO::Socket qw(SOCK_STREAM);

use parent -norequire, 'HTTP::Tiny::Handle';

sub connect {
    @_ == 4 || die(q/Usage: $handle->connect(scheme, host, port)/ . "\n");
    my ($self, $scheme, $host, $port) = @_;
 
    if ( $scheme eq 'https' ) {
        # Need IO::Socket::SSL 1.42 for SSL_create_ctx_callback
        die(qq/IO::Socket::SSL 1.42 must be installed for https support\n/)
            unless eval {require IO::Socket::SSL; IO::Socket::SSL->VERSION(1.42)};
        # Need Net::SSLeay 1.49 for MODE_AUTO_RETRY
        die(qq/Net::SSLeay 1.49 must be installed for https support\n/)
            unless eval {require Net::SSLeay; Net::SSLeay->VERSION(1.49)};
    }
    elsif ( $scheme ne 'http' ) {
      die(qq/Unsupported URL scheme '$scheme'\n/);
    }
    $self->{fh} = 'IO::Socket::INET'->new(
        PeerHost  => $host,
        PeerPort  => $port,
        $self->{local_address} ?
            ( LocalAddr => $self->{local_address} ) : (),
        Proto     => 'tcp',
        Type      => SOCK_STREAM,
        Timeout   => $self->{timeout}
    ) or die(qq/Could not connect to '$host:$port': $@\n/);
 
    binmode($self->{fh})
      or die(qq/Could not binmode() socket: '$!'\n/);

    if ( $scheme eq 'https') {
        my $ssl_args = $self->_ssl_args($host);

        $ssl_args->{SSL_npn_protocols} = ['spdy/3'];
        
        IO::Socket::SSL->start_SSL(
            $self->{fh},
            %$ssl_args,
            SSL_create_ctx_callback => sub {
                my $ctx = shift;
                Net::SSLeay::CTX_set_mode($ctx, Net::SSLeay::MODE_AUTO_RETRY());
            },
        );
 
        unless ( ref($self->{fh}) eq 'IO::Socket::SSL' ) {
            my $ssl_err = IO::Socket::SSL->errstr;
            die(qq/SSL connection failed for $host: $ssl_err\n/);
        }

        if ($self->{fh}->next_proto_negotiated &&
            $self->{fh}->next_proto_negotiated eq 'spdy/3')
        {
            # SPDY negotiation succeeded
            $self->{spdy} = {
                session => Net::SPDY::Session->new($self->{fh}),
                stream_id => 1,
            };
        }
    }

    $self->{host} = $host;
    $self->{port} = $port;
 
    return $self;   
}

my $Printable = sub {
    local $_ = shift;
    s/\r/\\r/g;
    s/\n/\\n/g;
    s/\t/\\t/g;
    s/([^\x20-\x7E])/sprintf('\\x%.2X', ord($1))/ge;
    $_;
};

# HTTP headers which must not be present in a SPDY request
my %invalid_headers;
undef @invalid_headers{qw( connection host )};
 
sub write_request {
    @_ == 2 || die(q/Usage: $handle->write_request(request)/ . "\n");
    my ($self, $request) = @_;

    if (defined $self->{spdy}) {
        my $framer = $self->{spdy}->{session}->{framer};

        my %frame = (
            type => Net::SPDY::Framer::SYN_STREAM,
            stream_id => $self->{spdy}->{stream_id},
            associated_stream_id => 0,
            priority => 2,
            flags => $request->{cb} ? 0 : Net::SPDY::Framer::FLAG_FIN,
            slot => 0,
            headers => [
                ':method' => $request->{method},
                ':scheme' => $request->{scheme},
                ':path' => $request->{uri},
                ':version' => 'HTTP/1.1',
                ':host' => $request->{host_port},
            ]
        );

        while (my ($k, $v) = each %{$request->{headers}}) {
            my $field_name = lc $k;

            # Omit invalid headers
            next if exists $invalid_headers{$field_name};

            for (ref $v eq 'ARRAY' ? @$v : $v) {
                /[^\x0D\x0A]/
                    or die(qq/Invalid HTTP header field value ($field_name): / . $Printable->($_). "\n");
                push @{$frame{headers}}, $field_name, $_;
            }
        }

        $framer->write_frame(%frame);

        if ($request->{cb}) {
            if ($request->{headers}{'content-length'}) {
                # write_content_body
                my ($len, $content_length) = (0, $request->{headers}{'content-length'});

                my $data = $request->{cb}->();
                my $last_frame = 0;

                do {
                    my %frame = (
                        control => 0,
                        stream_id => $self->{spdy}->{stream_id},
                        data => $data || '',
                        flags => 0,
                    );

                    $last_frame = !defined $data || !length $data;
                    
                    if (!$last_frame) {
                        $data = $request->{cb}->();
                        $last_frame = !defined $data || !length $data;
                    }

                    if ($last_frame) {
                        $frame{flags} |= Net::SPDY::Framer::FLAG_FIN;
                    }
                    
                    %frame = $framer->write_frame(%frame);
                    
                    $len += $frame{length};
                }
                while (!$last_frame);

                $len == $content_length
                    or die(qq/Content-Length mismatch (got: $len, expected: $content_length)\n/);
            }
            else {
                # write_chunked_body
            }
        }

        $self->{spdy}->{stream_id} += 2;

        return;
    }
    else {
        return $self->SUPER::write_request($request);
    }
}

sub read_response {
    @_ == 1 || die(q/Usage: $handle->read_response()/ . "\n");
    my($self) = @_;

    my $response;

    if (defined $self->{spdy}) {
        # SPDY connection
        my $framer = $self->{spdy}->{session}->{framer};

        while (my %frame = $framer->read_frame) {
            if (exists $frame{type} &&
                $frame{type} == Net::SPDY::Framer::SYN_REPLY)
            {
                my %frame_headers = @{$frame{headers}};
                my @http_headers = @{$frame{headers}};

                ($response->{status}, $response->{reason}) =
                    split /[\x09\x20]+/, delete($frame_headers{':status'}), 2;

                $response->{headers} = {};

                for (my $i = 0; $i < $#http_headers; $i += 2) {
                    if ($http_headers[$i] !~ /^:/) {
                        my $field_name = lc $http_headers[$i];

                        if (exists $response->{headers}->{$field_name}) {
                            if (ref $response->{headers}->{$field_name} ne 'ARRAY') {
                                $response->{headers}->{$field_name} = [
                                    $response->{headers}->{$field_name}
                                ];

                                push @{$response->{headers}->{$field_name}}, $http_headers[$i+1];
                            }
                        }
                        else {
                            $response->{headers}->{$field_name} = $http_headers[$i+1];
                        }
                    }
                }
            }

            if (!$frame{control}) {
                # TODO: Add support for max_size
                $response->{content} .= $frame{data};
            }

            last if ($frame{flags} & Net::SPDY::Framer::FLAG_FIN);

            # FIXME: Probably need to do better than just saying "throw another
            # 64K on us" after each and every frame
            $framer->write_frame(
                control => 1,
                type => Net::SPDY::Framer::WINDOW_UPDATE,
                stream_id => $frame{stream_id},
                delta_window_size => 0x00010000,
            );
        }
    }
    else {
        # Traditional HTTP(S) connection
        return undef;
    }
}

1;

__END__

=head1 SYNOPSIS

    use HTTP::Tiny::SPDY;

    my $response = HTTP::Tiny::SPDY->new->get('https://example.com/');

    die "Failed!\n" unless $response->{success};

    print "$response->{status} $response->{reason}\n";

    while (my ($k, $v) = each %{$response->{headers}}) {
        for (ref $v eq 'ARRAY' ? @$v : $v) {
            print "$k: $_\n";
        }
    }

    print $response->{content} if length $response->{content};

=head1 DESCRIPTION

This is a subclass of L<HTTP::Tiny> with added support for the SPDY protocol. It
is intended to be fully compatible with HTTP::Tiny so that it can be used as a
drop-in replacement for it.

=head1 SEE ALSO

=for :list
* L<HTTP::Tiny>
* L<Net::SPDY>
* L<SPDY Project Homepage|http://dev.chromium.org/spdy/>

=head1 ACKNOWLEDGEMENTS

SPDY protocol support is provided by L<Net::SPDY>, written by Lubomir Rintel.

=cut
