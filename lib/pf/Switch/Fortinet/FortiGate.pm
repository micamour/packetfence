package pf::Switch::Fortinet::FortiGate;

=head1 NAME

pf::Switch::Fortinet::FortiGate - Object oriented module to FortiGate using the external captive portal

=head1 SYNOPSIS

The pf::Switch::AeroHIVE::AP module implements an object oriented interface to interact with the AeroHIVE captive portal

=head1 STATUS

Tested on an AP330 running HiveOS 6.1r6.1779

=cut

=head1 BUGS AND LIMITATIONS

=head2 Redirect URL is not working

When selecting the option to redirect the user to the initially requested page, the AeroHIVE access point is not able to do the redirection properly.
Using the default success page of AeroHIVE works.

=cut

use strict;
use warnings;
use Log::Log4perl;
use pf::config;
use pf::node;
use pf::violation;
use pf::locationlog;
use pf::util;
use LWP::UserAgent;
use HTTP::Request::Common;

use base ('pf::Switch::Fortinet');

=head1 METHODS

=cut

sub description { 'FortiGate Firewall with web auth' }

sub supportsExternalPortal { return $TRUE; }

sub parseUrl {
    my($self, $req) = @_;
    my $logger = Log::Log4perl::get_logger( ref($self) );
    # need to synchronize the locationlog event if we'll reject
    $self->synchronize_locationlog("0", "0", clean_mac($$req->param('usermac')),
        0, $WIRELESS_MAC_AUTH, clean_mac($$req->param('Calling-Station-Id')), "0"
    );

    return ($$req->param('usermac'),undef,$$req->param('userip'),undef,$$req->param('post'),"200");
}

=head1 reevaluateParam

parameter to send to the reevaluate funtion

=cut

sub reevaluate_param {
   my ($self, $portalSession, $catalystSession) = @_;

   my %data = (
      'magic'            => $portalSession->session->param("ecwp-original-param-magic"),
      'username'         => $catalystSession->{'username'},
      'password'         => $catalystSession->{'password'},
      'post'             => $portalSession->session->param("ecwp-original-param-post"),
   );
   return %data;
}

=head2 returnRadiusAccessAccept

Prepares the RADIUS Access-Accept reponse for the network device.

Overriding the default implementation for the external captive portal

=cut

sub returnRadiusAccessAccept {
    my ($self, $vlan, $mac, $port, $connection_type, $user_name, $ssid, $wasInline, $user_role) = @_;
    my $logger = Log::Log4perl::get_logger( ref($self) );

    my $radius_reply_ref = {};

    my $node = node_view($mac);

    my $violation = pf::violation::violation_view_top($mac);
    # if user is unregistered or is in violation then we reject him to show him the captive portal 
    if ( $node->{status} eq $pf::node::STATUS_UNREGISTERED || defined($violation) ){
        $logger->info("[$mac] is unregistered. Refusing access to force the eCWP");
        my $radius_reply_ref = {
            'Tunnel-Medium-Type' => $RADIUS::ETHERNET,
            'Tunnel-Type' => $RADIUS::VLAN,
            'Tunnel-Private-Group-ID' => -1,
        }; 
        return [$RADIUS::RLM_MODULE_OK, %$radius_reply_ref]; 

    }
    else{
        $logger->info("[$mac] Returning ACCEPT");
        return [$RADIUS::RLM_MODULE_OK, %$radius_reply_ref];
    }

}

=head2 deauthenticateMacDefault

De-authenticate a MAC address from wireless network (including 802.1x).

Need to implement the CoA to remove the ACL and the redirect URL.

=cut

sub deauthenticateMacDefault {
    my ( $self, $mac, %opts ) = @_;
    my $logger = Log::Log4perl::get_logger( ref($self) );

    if ( !$self->isProductionMode() ) {
        $logger->info("not in production mode... we won't perform deauthentication");
        return 1;
    }

    my $ua = LWP::UserAgent->new;
    $ua->timeout(5);
    my $response = $ua->get($opts{'post'}.'/?magic='.$opts{'magic'}.'&username='.$opts{'username'}.'&password='.$opts{'password'});
    #my $response = $ua->post($opts{'post'}, magic => $opts{'magic'}, username => $opts{'username'}, password => $opts{'password'});
    if ($response->is_success) {
        $logger->info("Node $mac registered and allowed to pass the Firewall");
        return 1;
    } else {
        $logger->error("error :".$response->status_line);
        return 0;
    }
}


=head2 deauthTechniques

Return the reference to the deauth technique or the default deauth technique.

=cut

sub deauthTechniques {
    my ($this, $method) = @_;
    my $logger = Log::Log4perl::get_logger( ref($this) );
    my $default = $SNMP::HTTP;
    my %tech = (
        $SNMP::HTTP => 'deauthenticateMacDefault',
    );

    if (!defined($method) || !defined($tech{$method})) {
        $method = $default;
    }
    return $method,$tech{$method};
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2015 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;

