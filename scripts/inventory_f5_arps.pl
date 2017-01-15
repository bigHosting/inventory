#!/usr/bin/perl
#
# (c) Security Guy 2016.09.05
#
#
# root [inventory]> show create table inventory.f5;

# root [inventory]> CREATE TABLE `f5` (
#  `Id` mediumint(15) unsigned NOT NULL AUTO_INCREMENT,
#  `Ip` varchar(250) NOT NULL,
#  `Mac` varchar(250) NOT NULL,
#  `Name` varchar(250) NOT NULL,
#  `Device` varchar(250) NOT NULL,
#  `Vlan` varchar(250) NOT NULL,
#  `Date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
#  PRIMARY KEY (`Id`),
#  UNIQUE KEY `Uniq` (`Device`,`Ip`,`Mac`),
#  KEY `Device_idx` (`Device`),
#  KEY `Ip_idx` (`Ip`),
#  KEY `Mac_idx` (`Mac`),
#  KEY `Vlan_idx` (`Vlan`)
#) ENGINE=InnoDB DEFAULT CHARSET=latin1;

# root [inventory]> CREATE EVENT f5_cleanup ON SCHEDULE EVERY 6 HOUR DO DELETE FROM f5 WHERE Date < NOW() - INTERVAL 2 DAY;

use warnings;
use strict;

use LWP::UserAgent;
use JSON qw( decode_json encode_json from_json);
#use Data::Dumper;
sub append($$);

unless (@ARGV == 2)
{
     print "\nUsage: $0 <lb> <output_file>\n";
     print "$0 f5-load-balancer.domain.com /etc/ansible/environments/inventory.f5\n\n";
     print "      X.Y.147.178    00:50:56:8e:6c:0b          C45_VLAN_46
      X.Y.147.182    00:22:64:04:66:12          C45_VLAN_46
       X.Y.148.79           incomplete          C45_VLAN_47
      X.Y.146.118    00:50:56:8e:40:82          C45_VLAN_45\n\n";
     exit;
}

# target F5 load balancer
my $target = $ARGV[0];
my $output = $ARGV[1];
my $uri = "https://$target/mgmt/tm/net/arp/stats";
my $api_insert = '';

# http header, Authorization is base64 encoded user:password
my @headers = (
    'Content-Type'   => 'application/json',
    'Authorization'  => 'Basic bm*********',
    'user-agent'     => 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.10) Gecko/20100914 Firefox/3.6.10' 
);

my $ua = new LWP::UserAgent;
$ua->ssl_opts( verify_hostname => 0   );
$ua->ssl_opts( SSL_verify_mode => 0x0 );
$ua->env_proxy();

my $request = HTTP::Request->new( 'GET', $uri );
$request->header( @headers );
my $result = $ua->request($request);


# is request getting 200 ?
if (!$result->is_success)
{
        die "[*] $0 ERROR: remote page dif not return http code 200: -> " . $result->status_line; 
}

my $decoded_json = decode_json($result->content);

#print Dumper $decoded_json->{'entries'};
#exit;
unlink ($output) if ( -e $output );
open (LR, ">$output") && close(LR);
chmod(0644, $output) if ( -f $output );

my %data = %{ $decoded_json->{'entries'} };
foreach my $key (keys %data)
{
        my $MAC    = $decoded_json->{'entries'}->{$key}->{'nestedStats'}->{'entries'}->{'macAddress'}->{'description'};
        my $VLAN   = $decoded_json->{'entries'}->{$key}->{'nestedStats'}->{'entries'}->{'vlan'}->{'description'};
        my $IP     = $decoded_json->{'entries'}->{$key}->{'nestedStats'}->{'entries'}->{'ipAddress'}->{'description'};

        # skip if mac address is incomplete !
        #next if ( $MAC =~ m/incomplete/i );

        #strip out '/Common/' from the VLAN
        $VLAN =~ s#/Common/##gi;

        my $info = sprintf "%20s%20s%20s%40s\n", $IP, $MAC, $VLAN, $target;
        print $info;
        &append( $output, $info );

        my %data = (
                     Ip     => "$IP",
                     Mac    => "$MAC",
                     Vlan   => "$VLAN",
                     Name   => "$IP",
                     Device => "$target"
        );

        #print encode_json (\%data) . "\n";

        my $api_insert = sprintf("/usr/bin/curl -sk -X POST -H 'Content-Type: application/json' -d '%s' https://inventory.sec.domain.com/apiv1/db/f5insert -o /dev/null", encode_json (\%data) );
        system ($api_insert);

}

sub append($$)
{

        my ($LogFile,$Msg) = @_;

        open(FILEH, ">>$LogFile") ||return();
        print FILEH "$Msg\n";
        close(FILEH);

        return 1;
}

