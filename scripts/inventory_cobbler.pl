#!/usr/bin/perl

use strict;
use warnings;

#use Data::Dumper;
use Frontier::Client;
use JSON qw( encode_json );

# handle ^C
$SIG{INT} = sub { die "Caught a sigint $!" };

# sub defined eof
sub append($$);

unless (@ARGV == 2)
{
     print "\nUsage: $0 <target>  <output_file>\n";
     print "       $0 cobbler.domain.com /etc/ansible/environments/inventory.cobbler\n\n";
     exit;
}

my $targetbox = $ARGV[0];
my $output    = $ARGV[1];

my $server = Frontier::Client->new(
 'url' => "http://" . $targetbox . "/cobbler_api"
);

# Logging In
my $token = $server->call( 'login', 'seccobblerapi', '********' );

#warn Dumper \$server->call('get_systems');
#my $distros = $server->call('get_distros');
#my $profiles = $server->call('get_profiles');
#my $systems = $server->call('get_systems');
#my $images = $server->call('get_images');
#my $repos = $server->call('get_repos');

# remove and empty file
unlink ($output) if ( -f $output);
open (LR, ">$output") && close(LR);
chmod(0644, $output) if ( -f $output );

my $systems = $server->call('get_systems');

foreach my $s ( @{$systems} )
{
        # we must have  name and interfaces
        if ( defined $s->{name} && defined $s->{interfaces} )
        {
            my $sys_name     = $s->{hostname} || $s->{name};
            my $sys_namefull = $s->{name};

            my @interfaces = keys % { $s->{interfaces} };
            foreach my $int (@interfaces)
            {
                    my $ip   = $s->{interfaces}->{$int}->{'ip_address'}  || "NA";
                    my $gw   = $s->{interfaces}->{$int}->{'gateway'}     || "NA";
                    my $mac  = $s->{interfaces}->{$int}->{'mac_address'} || "NA";
                    my $mask = $s->{interfaces}->{$int}->{'netmask'}     || "NA";

                    my $info = sprintf "%s%40s%10s%25s%15s%20s%30s", $sys_name, $sys_namefull, $int, $ip, $gw, $mask, $mac;
                    #printf "%s%40s%10s%25s%15s%20s%30s\n", $sys_name, $sys_namefull, $int, $ip, $gw, $mask, $mac;
                    print "$info\n";
                    &append( $output, $info ); 

                    my %data = (
                         Ip         => "$ip",
                         Mac        => "$mac",
                         Netmask    => "$mask",
                         Gateway    => "$gw",
                         Device     => "cobbler.domain.com",
                         Interface  => "$int",
                         FullName   => "$sys_namefull",
                         Name       => "$sys_name"
                    );

                    #print encode_json (\%data) . "\n";

                    my $api_insert = sprintf("/usr/bin/curl -sk -X POST -H 'Content-Type: application/json' -d '%s' https://inventory.sec.domain.com/apiv1/db/cobblerinsert -o /dev/null", encode_json (\%data) );
                    system ($api_insert);

            }
            print "\n";
        }
}


sub append($$)
{

        my ($LogFile,$Msg) = @_;

        open(FILEH, ">>$LogFile") ||return();
        print FILEH "$Msg\n";
        close(FILEH);

        return 1;
}

