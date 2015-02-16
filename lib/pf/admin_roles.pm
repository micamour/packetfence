package pf::admin_roles;

=head1 NAME

pf::admin_roles add documentation

=cut

=head1 DESCRIPTION

pf::admin_roles

=cut

use strict;
use warnings;

use base qw(Exporter);
use pf::file_paths;
use List::MoreUtils qw(any all uniq);
use pf::config::cached;
use pf::factory::config;

our @EXPORT = qw(admin_can admin_can_do_any admin_can_do_any_in_group @ADMIN_ACTIONS %ADMIN_ROLES $cached_adminroles_config admin_allowed_options admin_allowed_options_all);
our %ADMIN_ROLES;
%ADMIN_ROLES = pf::factory::config->new('cached_hash', 'config::AdminRoles');
our @ADMIN_ACTIONS = @pf::constants::admin_roles::ADMIN_ACTIONS;

our %ADMIN_GROUP_ACTIONS = (
    CONFIGURATION_GROUP_READ => [
        qw( CONFIGURATION_MAIN_READ PORTAL_PROFILES_READ
          ADMIN_ROLES_READ  INTERFACES_READ SWITCHES_READ FLOATING_DEVICES_READ
          USERS_ROLES_READ  USERS_SOURCES_READ VIOLATIONS_READ SOH_READ
          FINGERPRINTS_READ USERAGENTS_READ MAC_READ)
      ],
    LOGIN_GROUP => [
        qw( SERVICES REPORTS USERS_READ NODES_READ CONFIGURATION_MAIN_READ
          PORTAL_PROFILES_READ PROVISIONING_READ ADMIN_ROLES_READ INTERFACES_READ
          SWITCHES_READ FLOATING_DEVICES_READ USERS_ROLES_READ USERS_SOURCES_READ
          VIOLATIONS_READ SOH_READ FINGERPRINTS_READ USERAGENTS_READ MAC_READ
          )
      ],
);

sub admin_can_do_any_in_group {
    my ($roles,$group) = @_;
    my $actions = $ADMIN_GROUP_ACTIONS{$group} if exists $ADMIN_GROUP_ACTIONS{$group};
    return ref $actions eq 'ARRAY' && admin_can_do_any($roles,@$actions);
}

sub admin_can {
    my ($roles, @actions) = @_;

    return 0 if any {$_ eq 'NONE'} @$roles;
    return any {
        my $role = $_;
        exists $ADMIN_ROLES{$role} && all { exists $ADMIN_ROLES{$role}{ACTIONS}{$_} } @actions
    } @$roles;
}

sub admin_can_do_any {
    my ($roles, @actions) = @_;

    return 0 if any {$_ eq 'NONE'} @$roles;
    return any {
        my $role = $_;
        exists $ADMIN_ROLES{$role} && any { exists $ADMIN_ROLES{$role}{ACTIONS}{$_} } @actions
    } @$roles;
}


=head2 admin_allowed_options

Get the allowed options for the given roles
Will return empty if any role allows all the values

=cut

sub admin_allowed_options {
    my ($roles,$option) = @_;
    #return an empty value if any of the roles are all
    return unless all { $_ ne 'ALL' } @$roles;

    my @options;
    foreach my $role (@$roles) {
        next unless exists $ADMIN_ROLES{$role};
        #If no option is defined then all are allowed
        return unless exists $ADMIN_ROLES{$role}{$option};

        my $allowed_options = $ADMIN_ROLES{$role}{$option};
        #If the allowed options is empty the all are allowed
        return unless defined $allowed_options && length $allowed_options;

        push @options, split /\s*,\s*/, $allowed_options;
    }
    return uniq @options;
}


=head2 admin_allowed_options_all

Get all the allowed values for a given role

=cut

sub admin_allowed_options_all {
    my ($roles, $option) = @_;
    return uniq map {split /\s*,\s*/, ($ADMIN_ROLES{$_}{$option} || '')} grep { exists $ADMIN_ROLES{$_} && exists $ADMIN_ROLES{$_}{$option} }  @$roles;
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

