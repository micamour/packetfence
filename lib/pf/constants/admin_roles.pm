package pf::constants::admin_roles;

=head1 NAME

pf::constants::admin_roles - constants for admin_roles object

=cut

=head1 DESCRIPTION

pf::constants::admin_roles

=cut

use strict;
use warnings;
use base qw(Exporter);

our @EXPORT_OK = qw(@ADMIN_ACTIONS);

our @ADMIN_ACTIONS = qw(
    ADMIN_ROLES_CREATE
    ADMIN_ROLES_DELETE
    ADMIN_ROLES_READ
    ADMIN_ROLES_UPDATE

    CONFIGURATION_MAIN_READ
    CONFIGURATION_MAIN_UPDATE

    FINGERBANK_READ
    FINGERBANK_CREATE
    FINGERBANK_UPDATE
    FINGERBANK_DELETE

    FINGERPRINTS_READ
    FINGERPRINTS_UPDATE

    FIREWALL_SSO_READ
    FIREWALL_SSO_CREATE
    FIREWALL_SSO_UPDATE
    FIREWALL_SSO_DELETE

    FLOATING_DEVICES_CREATE
    FLOATING_DEVICES_DELETE
    FLOATING_DEVICES_READ
    FLOATING_DEVICES_UPDATE

    INTERFACES_CREATE
    INTERFACES_DELETE
    INTERFACES_READ
    INTERFACES_UPDATE

    MAC_READ
    MAC_UPDATE

    NODES_CREATE
    NODES_DELETE
    NODES_READ
    NODES_UPDATE

    PORTAL_PROFILES_CREATE
    PORTAL_PROFILES_DELETE
    PORTAL_PROFILES_READ
    PORTAL_PROFILES_UPDATE

    PROVISIONING_CREATE
    PROVISIONING_DELETE
    PROVISIONING_READ
    PROVISIONING_UPDATE

    REPORTS
    SERVICES

    SOH_CREATE
    SOH_DELETE
    SOH_READ
    SOH_UPDATE

    SWITCHES_CREATE
    SWITCHES_DELETE
    SWITCHES_READ
    SWITCHES_UPDATE

    USERAGENTS_READ

    USERS_READ
    USERS_CREATE
    USERS_CREATE_MULTIPLE
    USERS_UPDATE
    USERS_DELETE

    USERS_SET_ROLE
    USERS_SET_ACCESS_DURATION
    USERS_SET_UNREG_DATE
    USERS_SET_ACCESS_LEVEL
    USERS_MARK_AS_SPONSOR

    USERS_ROLES_CREATE
    USERS_ROLES_DELETE
    USERS_ROLES_READ
    USERS_ROLES_UPDATE

    USERS_SOURCES_CREATE
    USERS_SOURCES_DELETE
    USERS_SOURCES_READ
    USERS_SOURCES_UPDATE

    VIOLATIONS_CREATE
    VIOLATIONS_DELETE
    VIOLATIONS_READ
    VIOLATIONS_UPDATE

    SOH_READ
    SOH_CREATE
    SOH_UPDATE
    SOH_DELETE

    FINGERPRINTS_READ
    FINGERPRINTS_UPDATE

    USERAGENTS_READ

    MAC_READ
    MAC_UPDATE

    FIREWALL_SSO_READ
    FIREWALL_SSO_CREATE
    FIREWALL_SSO_UPDATE
    FIREWALL_SSO_DELETE

    REALM_READ
    REALM_CREATE
    REALM_UPDATE
    REALM_DELETE

    SCAN_READ
    SCAN_CREATE
    SCAN_UPDATE                                                                                                                                                                          
    SCAN_DELETE

    WMI_READ
    WMI_CREATE
    WMI_UPDATE
    WMI_DELETE

);

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2015 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and::or
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

