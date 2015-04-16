package pf::constants::scan;

=head1 NAME

pf::constants::scan - constants for scan object

=cut

=head1 DESCRIPTION

pf::constants::scan

=cut

use strict;
use warnings;
use base qw(Exporter);

our @EXPORT_OK = qw(
  $SCAN_VID
  $POST_SCAN_VID
  $PRE_SCAN_VID
  $SEVERITY_HOLE
  $SEVERITY_WARNING
  $SEVERITY_INFO
  $STATUS_NEW
  $STATUS_STARTED
  $STATUS_CLOSED
);

use Readonly;

Readonly our $SCAN_VID => '1200001';
Readonly our $POST_SCAN_VID => '1200004';
Readonly our $PRE_SCAN_VID => '1200005';
Readonly our $SEVERITY_HOLE     => 1;
Readonly our $SEVERITY_WARNING  => 2;
Readonly our $SEVERITY_INFO     => 3;
Readonly our $STATUS_NEW => 'new';
Readonly our $STATUS_STARTED => 'started';
Readonly our $STATUS_CLOSED => 'closed';

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

