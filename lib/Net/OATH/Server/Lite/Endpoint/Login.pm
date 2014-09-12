package Net::OATH::Server::Lite::Endpoint::Login;
use strict;
use warnings;
use overload
    q(&{})   => sub { shift->psgi_app },
    fallback => 1;

use Try::Tiny qw/try catch/;
use Plack::Request;
use Params::Validate;
use JSON::XS qw/decode_json encode_json/;

use Authen::OATH;
use Net::OATH::Server::Lite::Error;

my %DIGEST_MAP = (
    SHA1 => q{Digest::SHA1},
    MD5 => q{Digest::MD5},
    # TODO: Support SHA256, SHA512
    # SHA256 => q{Digest::SHA256},
    # SHA512 => q{Digest::SHA512},
);

sub new {
    my $class = shift;
    my %args = Params::Validate::validate(@_, {
        data_handler => 1,
    });
    my $self = bless {
        data_handler   => $args{data_handler},
    }, $class;
    return $self;
}

sub data_handler {
    my ($self, $handler) = @_;
    $self->{data_handler} = $handler if $handler;
    $self->{data_handler};
}

sub psgi_app {
    my $self = shift;
    return $self->{psgi_app}
        ||= $self->compile_psgi_app;
}

sub compile_psgi_app {
    my $self = shift;

    my $app = sub {
        my $env = shift;
        my $req = Plack::Request->new($env);
        my $res; try {
            $res = $self->handle_request($req);
        } catch {
            # Internal Server Error
            warn $_;
            $res = $req->new_response(500);
        };
        return $res->finalize;
    };

    return $app;
}

sub handle_request {
    my ($self, $request) = @_;

    my $res = try {

        # DataHandler
        my $data_handler = $self->{data_handler}->new(request => $request);
        Net::OATH::Server::Lite::Error->throw(
            code => 500,
            error => q{server_error},
        ) unless ($data_handler && $data_handler->isa(q{Net::OATH::Server::Lite::DataHandler}));

        # REQUEST_METHOD
        Net::OATH::Server::Lite::Error->throw()
            unless ($request->method eq q{POST});

        my $params;
        eval {
            $params = decode_json($request->content);
        };
        Net::OATH::Server::Lite::Error->throw() unless $params;

        # Params
        my $id = $params->{id} or
            Net::OATH::Server::Lite::Error->throw(
                description => q{missing id},
            );

        my $password = $params->{password} or 
            Net::OATH::Server::Lite::Error->throw(
                description => q{missing password},
            );

        # obtain user model
        my $user = $data_handler->select_user($id) or
            Net::OATH::Server::Lite::Error->throw(
                code => 404,
                description => q{invalid id},
            );
        Net::OATH::Server::Lite::Error->throw(
            code => 500,
            error => q{server_error},
        ) unless $user->isa(q{Net::OATH::Server::Lite::Model::User});

        my $timestamp = ($params->{timestamp}) ? $params->{timestamp} : time();
        my $counter = (defined $params->{counter}) ? $params->{counter} : $user->counter;
        my $is_valid = $self->is_valid_password($password, $user, $timestamp, $counter);
        if ($user->type eq q{hotp} and !defined $params->{counter}) {
            $user->counter($user->counter + 1);
            $data_handler->update_user($user);
        }

        if ($is_valid) {
            my $response_params = {
                id => $user->id,
            };
            return $request->new_response(200,
                [ "Content-Type"  => "application/json;charset=UTF-8",
                  "Cache-Control" => "no-store",
                  "Pragma"        => "no-cache" ],
                [ encode_json($response_params) ]);
        } else {
            Net::OATH::Server::Lite::Error->throw(
                code => 400,
                description => q{invalid password},
            );
        }

    } catch {
        if ($_->isa("Net::OATH::Server::Lite::Error")) {
            my $error_params = {
                error => $_->error,
            };
            $error_params->{error_description} = $_->description if $_->description;

            return $request->new_response($_->code,
                [ "Content-Type"  => "application/json;charset=UTF-8",
                  "Cache-Control" => "no-store",
                  "Pragma"        => "no-cache" ],
                [ encode_json($error_params) ]);
        } else {
            die $_;
        }
    };
}

sub is_valid_password {
    my ($self, $password, $user, $timestamp, $counter) = @_;

    # generate password
    my $oath = 
        Authen::OATH->new( 
            digits => $user->digits,
            digest => _digest_for_oath($user->algorithm),
            timestep => $user->period,
        );

    if ($user->type eq q{totp}) {
        # TOTP
        return ($password eq $oath->totp($user->secret, $timestamp));
    } else {
        # HOTP
        return ($password eq $oath->hotp($user->secret, $counter));
    }

    return 1;
}

sub _digest_for_oath {
    my $algorithm = shift;
    return ($DIGEST_MAP{$algorithm}) ? $DIGEST_MAP{$algorithm} : q{Digest::SHA1};
}

1;
