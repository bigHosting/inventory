#!/usr/bin/perl
#
# (c) Security Guy 2016.09.20
#
#
# root [inventory]> show create table inventory.f5_vips;

#CREATE TABLE `f5_vips` (
#  `Id` mediumint(15) unsigned NOT NULL AUTO_INCREMENT,
#  `Name` varchar(250) NOT NULL,
#  `Destination` varchar(250) NOT NULL,
#  `Description` varchar(250) NOT NULL,
#  `Partition` varchar(250) NOT NULL,
#  `Lb` varchar(250) NOT NULL,
#  `Mask` varchar(250) NOT NULL,
#  `Enabled` varchar(250) NOT NULL,
#  `Pool` varchar(250) NOT NULL,  
#  `Ipprotocol` varchar(250) NOT NULL,
#  `Poolname` varchar(250) NOT NULL,
#  `Poolmembers` varchar(250) NOT NULL,
#  `Asm` varchar(250) NOT NULL,
#  `Date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
#  PRIMARY KEY (`Id`),
#  UNIQUE KEY `Uniq` (`Destination`,`Lb`),
#  KEY `Destination_idx` (`Destination`),
#  KEY `Poolmembers_idx` (`Poolmembers`),
#  KEY `Asm_idx` (`Asm`)
#) ENGINE=InnoDB DEFAULT CHARSET=latin1;
#CREATE EVENT f5_vips_cleanup ON SCHEDULE EVERY 6 HOUR DO DELETE FROM f5_vips WHERE Date < NOW() - INTERVAL 2 DAY;


use warnings;
use strict;

use LWP::UserAgent;
use JSON qw( decode_json encode_json from_json);
use Data::Dumper;

# append 'line to file' function
sub append($$)
{

        my ($LogFile,$Msg) = @_;

        open(FILEH, ">>$LogFile") ||return();
        print FILEH "$Msg\n";
        close(FILEH);

        return 1;
}

# 'curl' GET F5 url
sub f5_get($)
{
        my $URL = shift;

        # http header, Authorization is base64 encoded user:password
        my @headers = (
            'Content-Type'   => 'application/json',
            'Authorization'  => 'Basic bm******',
            'user-agent'     => 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.10) Gecko/20100914 Firefox/3.6.10' 
        );

        my $ua = new LWP::UserAgent;
        $ua->ssl_opts( verify_hostname => 0   );
        $ua->ssl_opts( SSL_verify_mode => 0x0 );
        $ua->env_proxy();

        my $request = HTTP::Request->new( 'GET', $URL );
        $request->header( @headers );
        my $result = $ua->request($request);

        # is request getting 200 ?
        if (!$result->is_success)
        {
                die "[*] $0 ERROR: remote page dif not return http code 200: -> " . $result->status_line; 
        }

        return decode_json($result->content);

}


unless (@ARGV == 2)
{
     print "\nUsage: $0 <lb> <output_file>\n";
     print "$0 f5-load-balancer.domain.com /etc/ansible/environments/inventory.f5.VIPs.C25\n\n";
     print '{"destination":"/C26/X.Y.145.131:3306","pool":"/C26/C26_EasyMail_Master_IPV4_3306_POOL","name":"C26_EasyMail_Master_X.Y.145.131_VIP","partition":"C26","mask":"255.255.255.255","enabled":"true","ipProtocol":"tcp"}

{"destination":"/C26/X.Y.145.133:3306","pool":"/C26/C26_EasyMail_Slave_IPV4_3306_POOL","name":"C26_EasyMail_Slave_X.Y.145.133_VIP","partition":"C26","mask":"255.255.255.255","enabled":"true","ipProtocol":"tcp"}' ."\n\n";
     exit;
}

# target F5 load balancer
my $target = $ARGV[0];
my $output = $ARGV[1];
my $api_insert = '';

##########################
#####  VIPs section  #####
##########################
my $decoded_json = f5_get("https://$target/mgmt/tm/ltm/virtual");
my $items        = $decoded_json->{'items'};
my %data         = ();

die ("no VIPs found") if (scalar ( @{$items} == 0 ) );

# remove and zero out output file #
unlink ($output) if ( -e $output );
open (LR, ">$output") && close(LR);
chmod(0644, $output) if ( -f $output );

# loop thtough VIPs
foreach my $item ( @{$items} )
{
        next if (! $item->{'mask'});                              # skip entries w/o 'mask'
        next if (! $item->{'pool'});                              # skip entries w/o 'pool'
        next if (! $item->{'enabled'});                           # skip entries w/o 'enabled'

        next if ( $item->{'mask'} =~ m/any/ );                    # skip forwarding VIPs

        my $mask           = $item->{'mask'};
        my $destination    = $item->{'destination'};
        my $enabled        = $item->{'enabled'};
        my $name           = $item->{'name'};
        my $pool           = $item->{'pool'};
        my $ipProtocol     = $item->{'ipProtocol'};
        my $partition      = $item->{'partition'};

        my $pool_name      = $pool;
        $pool_name         =~ s#/#~#g; # replace '/' with '~'

        my $description    = $item->{'description'} || "N/A";

        #####  ASM  section  #####
        my $asm            = 'N/A';
        if ( $item->{'policiesReference'} && $item->{'policiesReference'}->{'items'})
        {
                $asm = $item->{'policiesReference'}->{'items'}[0]->{'fullPath'}
        }


        #####  POOL  section  #####
        my $pool_query     = f5_get("https://$target/mgmt/tm/ltm/pool/$pool_name/members");
        my $pool_items     = $pool_query->{'items'};

        my $pool_members   = '';
        my @tmp_array      = ();
        #if (scalar ( @{$pool_items} == 0 ) ) { $pool_members   = 'N/A'; } else
        next if (scalar ( @{$pool_items} == 0 ) );

        foreach my $mem ( @{$pool_items} )
        {
                next if (! $mem->{'address'} );         # 'address' must be present
                push (@tmp_array, $mem->{'address'}."_state_".$mem->{'state'});   # add pool member address to temprary array
        }
        $pool_members = join(',', @tmp_array);          # flatten temporary array to string
        #print Dumper \@{$pool_items};


        #####  PRINT results  #####
        #my $info = sprintf "%20s%20s%20s%20s%20s\n", $destination, $mask, $enabled, $name, $pool;
        #print $info;

        %data = (
                     Name         => "$name",
                     Destination  => "$destination",
                     Description  => "$description",
                     Mask         => "$mask",
                     Enabled      => "$enabled",
                     Pool         => "$pool",
                     Ipprotocol   => "$ipProtocol",
                     Partition    => "$partition",
                     Lb           => "$target",
                     Poolname     => "$pool_name",
                     Poolmembers  => "$pool_members",
                     Asm          => "$asm"
        );

        #print encode_json (\%data) . "\n\n";
        &append( $output, encode_json(\%data) );
        my $api_insert = sprintf("/usr/bin/curl -sk -X POST -H 'Content-Type: application/json' -d '%s' https://inventory.sec.domain.com/apiv1/db/f5vipsinsert -o /dev/null", encode_json (\%data) );
        print "$api_insert\n";
        system ($api_insert);
}


