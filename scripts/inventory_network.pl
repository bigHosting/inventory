#!/bin/env perl

# we need 5.14.1
#require 5.14.1;

use strict;
use warnings;

use LWP::Simple;
use JSON;
#use JSON qw( encode_json );

# handle ^C
$SIG{INT} = sub { die "Caught a sigint $!" };

# sub defined eof
sub append($$);

unless (@ARGV == 2)
{
     print "\nUsage: $0 <api_server>  <output_file>\n";
     print "       $0 observiumapi.net.domain.com /etc/ansible/environments/inventory.network\n\n";
     exit;
}

my $output    = $ARGV[1];

my $url = "https://". $ARGV[0] ."/table/devices";
my $list = get("$url");
if( ! defined( $list ) ) {
        die( "[*] $0: ERROR: Can not fetch addresses $url\n" );
}

my $decoded = decode_json($list);

# process results only if httpstatus is 200 and error is 0
if ( ($decoded->{'httpstatus'} != 200) || ( $decoded->{'error'} != 0) )
{
        die( "[*] $0: ERROR: httpstatus is != 200 OR error != 0\n" );
}

# products array
my @devices = @{ $decoded->{'data'} };

# do we have at least one entry ?
if ( scalar (@devices) < 1 )
{
        die( "[*] $0: ERROR: no devices found\n" );
}

unlink ($output) if ( -f $output);
open (LR, ">$output") && close(LR);
chmod(0644, $output) if ( -f $output );

foreach my $device ( @devices )
{
        #print $product->{'sourceip'} . " " . $product->{'type'} . "\n";
        # ignore if unknown
#        next if ( $device->{'type'} =~ m/UNKNOWN/);

        my $device_id   = $device->{'device_id'};
        my $hostname    = $device->{'hostname'};
        my $sysName     = $device->{'sysName'};
        my $snmp_version= $device->{'snmp_version'};
        my $sysDescr    = $device->{'sysDescr'};
        my $sysContact  = $device->{'sysContact'};
        my $version     = $device->{'version'};
        my $status      = $device->{'status'};
        my $location    = $device->{'location'};
        my $os          = $device->{'os'};
        my $hardware    = $device->{'hardware'};
        my $uptime      = $device->{'uptime'};
        my $last_polled = $device->{'last_polled'};

        my %data = (
             device_id    => "$device_id",
             hostname     => "$hostname",
             sysName      => "$sysName",
             snmp_version => "$snmp_version",
             sysDescr     => "$sysDescr",
             sysContact   => "$sysContact",
             version      => "$version",
             status       => "$status",
             location     => "$location",
             os           => "$os",
             hardware     => "$hardware",
             uptime       => "$uptime",
             last_polled  => "$last_polled"
        );

        print encode_json (\%data) . "\n\n";
        &append( $output, encode_json (\%data) );

        #my $api_insert = sprintf("/usr/bin/curl -sk -X POST -H 'Content-Type: application/json' -d '%s' https://inventory.sec.domain.com/apiv1/db/cobblerinsert -o /dev/null", encode_json (\%data) );
        #system ($api_insert);
}


sub append($$)
{

        my ($LogFile,$Msg) = @_;

        open(FILEH, ">>$LogFile") ||return();
        print FILEH "$Msg\n";
        close(FILEH);

        return 1;
}

