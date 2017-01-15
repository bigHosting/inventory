#!/usr/bin/perl

# (c) Security Guy . Snippets from Chris Wood's get_mco stuff

use warnings;
use strict;

use Getopt::Long;
use JSON;
use WWW::Curl::Easy;
use File::Slurp;
use Data::Dumper;

sub display_help {
         print "
usage: $0  -s|--server=puppetdb.domain.com  --ca=ca.pem  --cert=cert.pem  --key=key.pem   [-o|--outfile=out.txt]  [-d|--debug]

       $0  -s puppetdb.domain.com --ca=./ca.pem --cert=./cert.pem --key=./key.pem\n\n";
       exit 0;
}

# create empty file
sub NukeFile {
        my $dodo = shift;
        open (LR, ">$dodo") && close(LR);
        chmod(0644, $dodo) if ( -f $dodo );
        print "\n[*] $0: INFO: echo > $dodo\n\n";
}

my $string = '';

GetOptions(
        's|server=s'       => \ my $server,
        'ca=s'             => \ my $cafile,
        'cert=s'           => \ my $certfile,
        'd|debug|d'        => \ my $debug,
        'k|key=s'          => \ my $keyfile,
        'o|outfile|o=s'    => \ my $outfile,
) or &display_help;
if ( (scalar(@ARGV < 0)) || (!defined($server)) || (!defined($cafile)) || (!defined($certfile)) || (!defined($keyfile)) ) {  &display_help; }


my $url          = 'https://' . $server . ':8081/pdb/query/v4/facts/networking';

if ( ( ! -f $cafile ) || ( ! -f $certfile ) || ( ! -f $keyfile ) ) {
        die("Dying, one of cert, key, or ca files do not exist:\n  $cafile\n  $certfile\n  $keyfile\n");
}

my $results = {};

my $json = JSON->new()->allow_nonref();
my $curl = WWW::Curl::Easy->new;

if (!$curl)
{
        die (" WWW Curl Easy Unable to create curl object");
}

open(my $fileb, ">", \$string);
$curl->setopt( CURLOPT_CAINFO,    $cafile );
$curl->setopt( CURLOPT_SSLCERT,   $certfile );
$curl->setopt( CURLOPT_SSLKEY,    $keyfile );
$curl->setopt( CURLOPT_URL,       $url );
$curl->setopt( CURLOPT_WRITEDATA, $fileb );

if ($debug) {
        $curl->setopt( CURLOPT_VERBOSE, 1 );
}

my $response      = $curl->perform;
my $response_code = $curl->getinfo(CURLINFO_HTTP_CODE);

if ( ! ( ( $response_code == 200 ) && ( $response == 0 ) ) )
{
        #warn "An error happened: ", $curl->strerror($retcode), " ( +$retcode)\n";
        #warn "errbuf: ", $curl->errbuf;
        die( "An error happened: $response_code " . $curl->strerror($response_code) . " " . $curl->errbuf . "\n" );
}


my $ref = $json->decode($string);

my $filestring = '';

foreach my $item ( @{$ref} )
{
        my %server_info = (
                 'certname'    => $item->{certname},
                 'environment' => $item->{environment},
                 'ip'          => $item->{value}->{ip},
                 'fqdn'        => $item->{value}->{fqdn},
                 'mac'         => $item->{value}->{mac},
                 'interface'   => $item->{value}->{primary},
                 'interfaces'  => []
                );

        
        # server type: Physical or Virtual ?
        if ( $item->{value}->{mac} =~ m/^00:50:56|^00:0c:29/i)
        {
                    $server_info{'mactype'} = 'VmWare';
        } elsif ( $item->{value}->{mac} =~ m/^78:e7:d1:|^00:21:5a:|^00:1f:29:|^e4:11:5b:|^00:23:7d:|^18:a9:05:|^00:22:64:|^10:60:4b:|^d4:85:64:|^98:4b:e1:|^80:c1:6e:|^3c:d9:2b:|^10:1f:74:|^00:26:55:|^00:1e:0b:|^00:1a:4b:/i)
        {
                    $server_info{'mactype'} = 'Physical-HP';
        } elsif ( $item->{value}->{mac} =~ m/^00:30:48/)
        {
                    $server_info{'mactype'} = 'Physical-SuperMicro';
        } else {
                    $server_info{'mactype'} = 'NA';
        }

        # we need at least one interface defined !
        next if ( ! defined ( $item->{value}->{interfaces} ) );

        # loop through HASHREF
        foreach my $int (keys %{ $item->{value}->{interfaces} }) 
        {
                # IPV4 !
                if (defined ($item->{value}->{interfaces}->{$int}->{bindings}) )
                {
                        foreach my $i ( @{ $item->{value}->{interfaces}->{$int}->{bindings} } )
                        {
                                # skip loopback
                                next if ($i->{address} =~ m/^127/);

                                my %server_interfaces = (
                                        'address'  => $i->{address},
                                        'netmask'  => $i->{netmask},
                                        'network'  => $i->{network},
                                        'iface'    => $int,
                                );

                                if ( defined ( $item->{value}->{interfaces}->{$int}->{mac} ) )
                                {
                                        $server_interfaces{'mac'} = $item->{value}->{interfaces}->{$int}->{mac};
                                } else {
                                        $server_interfaces{'mac'} = $item->{value}->{mac};
                                }

                                push @{ $server_info{'interfaces'} }, \%server_interfaces;
                        }
                }

                # IPv6 !
                if (defined ($item->{value}->{interfaces}->{$int}->{bindings6}) )
                {
                        foreach my $i ( @{ $item->{value}->{interfaces}->{$int}->{bindings6} } )
                        {
                                # skip link local
                                next if ($i->{address} =~ m/^fe80/);
                                next if ($i->{address} =~ m/::1/);

                                my %server_interfaces = (
                                        'address'  => $i->{address},
                                        'netmask'  => $i->{netmask},
                                        'network'  => $i->{network},
                                        'iface'    => $int,
                                );

                                if ( defined ( $item->{value}->{interfaces}->{$int}->{mac} ) )
                                {
                                        $server_interfaces{'mac'} = $item->{value}->{interfaces}->{$int}->{mac};
                                } else {
                                        $server_interfaces{'mac'} = $item->{value}->{mac};
                                }


                                push @{ $server_info{'interfaces'} }, \%server_interfaces;
                        }
                }

        }

        push @{ $results->{'entries'} }, \%server_info;


        $filestring .= encode_json (\%server_info) . "\n\n";
}



if ($outfile)
{
        &NukeFile ( $outfile );
        write_file( $outfile, {append => 1 }, $filestring );
        print "\n[*] $0: INFO: $outfile generated\n\n";
} else {
        print $filestring;
}

# Now inject everything into database via API
#print Dumper ($results);
foreach my $entry ( @{ $results->{'entries'} } )
{
        my %api = (
                Ip          => $entry->{'ip'},
                Mac         => $entry->{'mac'},
                Mactype     => $entry->{'mactype'},
                Name        => $entry->{'fqdn'},
                Device      => $server,

                Certname    => $entry->{'certname'},
                Environment => $entry->{'environment'},
                Interface   => $entry->{'interface'},
        );

        foreach my $network_interface ( @{ $entry->{'interfaces'} } )
        {
                $api{Iface_network} = $network_interface->{network};
                $api{Iface_address} = $network_interface->{address};
                $api{Iface_netmask} = $network_interface->{netmask};
                $api{Iface_iface}   = $network_interface->{iface};
                $api{Iface_mac}     = $network_interface->{mac};

                #print encode_json (\%api) . "\n\n";
                my $api_insert = sprintf("/usr/bin/curl -sk -X POST -H 'Content-Type: application/json' -d '%s' https://inventory.sec.domain.com/apiv1/db/puppetdbinsert -o /dev/null", encode_json (\%api) );
                #print $api_insert . "\n";
                system ($api_insert);
        }

}

exit(0);

