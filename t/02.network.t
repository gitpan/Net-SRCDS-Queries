use Test::More qw(no_plan);
use IO::Socket::INET;

use constant INFO_RESULT =>
'ffffffff49076d6f64756c652074657374006c34645f686f73706974616c30315f61706172746d656e74006c6566743464656164004c3444202d20436f2d6f70202d204e6f726d616c00f401000400646c0001312e302e312e3300a08769656d7074792c736f757263656d6f642c636f6f702c7665727375732c737572766976616c00';
use constant CHALLENGE_RESULT => 'ffffffff41f8db8403';
use constant PLAYER_RESULT    => 'ffffffff4401004d6173736100000000007c4a6642';

BEGIN {
    use_ok('Net::SRCDS::Queries');
}

my $s = start_server();
SKIP: {
    skip 'skip network test. failed to bind local server' unless $s;
    my $q = Net::SRCDS::Queries->new( encoding => 'euc-jp' );

    my $buf;
    my $dest = sockaddr_in 27015, inet_aton 'localhost';

    # send client
    $q->send_a2s_info($dest);
    # recv server
    my $sender = $s->recv( $buf, 65535 );
    $s->send( pack( 'H*', INFO_RESULT ), 0, $sender );
    # recv client
    $q->{socket}->recv( $buf, 65535 );
    my $result = $q->parse_a2s_info($buf);
    my $expect = {
        'secure'    => 1,
        'max'       => 4,
        'players'   => 0,
        'app_id'    => 500,
        'os'        => 'l',
        'dir'       => 'left4dead',
        'map'       => 'l4d_hospital01_apartment',
        'password'  => 0,
        'bots'      => 0,
        'sname'     => 'module test',
        'desc'      => 'L4D - Co-op - Normal',
        'dedicated' => 'd',
        'version'   => 7,
        'port'      => 27015,
        'game_tag'  => 'empty,sourcemod,coop,versus,survival',
        'gversion'  => '1.0.1.3',
        'type'      => 'I'
    };
    is_deeply $expect, $result;

    # send client
    $q->send_challenge($dest);
    # recv server
    $sender = $s->recv( $buf, 65535 );
    $s->send( pack( 'H*', CHALLENGE_RESULT ), 0, $sender );
    # recv client
    $q->{socket}->recv( $buf, 65535 );
    $result = $q->parse_challenge($buf);
    $expect = {
        'cnum' => pack( 'H*', 'f8db8403' ),
        'type' => 'A',
    };
    is_deeply $expect, $result;

    # send client
    $q->send_a2s_player( $dest, $result->{cnum} );
    # recv server
    $sender = $s->recv( $buf, 65535 );
    $s->send( pack( 'H*', PLAYER_RESULT ), 0, $sender );
    # recv client
    $q->{socket}->recv( $buf, 65535 );
    $result = $q->parse_a2s_player($buf);
    $expect = {
        'player_info' => [
            {
                'connected' => '57.5727386474609',
                'name'      => 'Massa',
                'kills'     => 0
            }
        ],
        'num_players' => 1,
        'type'        => 'D'
    };
    is_deeply $expect, $result;
}

sub start_server {
    my $server = IO::Socket::INET->new(
        Proto     => 'udp',
        LocalPort => 27015,
    );
    return $server;
}
