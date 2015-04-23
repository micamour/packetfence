package pf::factory::billing;

=head1 NAME

pf::factory::billing

=cut

=head1 DESCRIPTION

pf::factory::billing

The factory for creating pf::billing objects

=cut

use strict;
use warnings;
use Module::Pluggable search_path => 'pf::billing::gateway', sub_name => 'modules' , require => 1, except => qr/^pf::billing::gateway::mirapay::(.*)$/;
use List::MoreUtils qw(any);
use pf::config;
use pf::firewallsso;

our @MODULES = __PACKAGE__->modules;

sub factory_for { 'pf::billing' }

sub new {
    my ($class,$name) = @_;
    my $object;
    my %data = %{$ConfigBilling{$name}};
    $data{id} = $name;
    if (%data) {
        my $subclass = $class->getModuleName($name,%data);
        $object = $subclass->new(%data);
    }
    return $object;
}

sub getModuleName {
    my ($class,$name,%data) = @_;
    my $mainClass = $class->factory_for;
    my $type = $data{type};
    my $subclass = "${mainClass}::${type}";
    die "type is not defined for $name" unless defined $type;
    die "$type is not a valid type" unless any { $_ eq $subclass  } @MODULES;
    $subclass;
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