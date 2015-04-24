=head1 NAME

provisioner

=cut

=head1 DESCRIPTION

provisioner

=cut

use strict;
use warnings;
# pf core libs
use lib '/usr/local/pf/lib';

BEGIN {
    use lib qw(/usr/local/pf/t);
    use PfFilePaths;
}
use Test::More tests => 11;

use Test::NoWarnings;
use Test::Exception;

our $TEST_CATEGORY = "test";

our $TEST_OS = 'Apple iPod, iPhone or iPad',

our $TEST_NODE_ATTRIBUTE = { category => $TEST_CATEGORY };

use_ok("pf::provisioner");

my $provisioner = new_ok(
    "pf::provisioner",
    [{
        type     => 'autoconfig',
        category => [$TEST_CATEGORY],
        template => 'dummy',
        oses     => [$TEST_OS],
    }]
);

ok($provisioner->match($TEST_OS,$TEST_NODE_ATTRIBUTE),"Match both os and category");

ok(!$provisioner->match(undef,$TEST_NODE_ATTRIBUTE),"Don't match undef os");

ok(!$provisioner->match('Android',$TEST_NODE_ATTRIBUTE),"Don't Match os but Matching category");

ok(!$provisioner->match('Android','not_matching'),"Don't Match os and category");

$provisioner->category(['not_matching']);

ok(!$provisioner->match($TEST_OS,$TEST_NODE_ATTRIBUTE),"Match os but not category");

$provisioner->category([]);

ok($provisioner->match($TEST_OS,$TEST_NODE_ATTRIBUTE),"Match os with the any category");

ok(!$provisioner->match('Android',$TEST_NODE_ATTRIBUTE),"Don't match os with the any category");

$provisioner->category([$TEST_CATEGORY]);
$provisioner->oses([]);

ok($provisioner->match($TEST_OS,$TEST_NODE_ATTRIBUTE),"Match both os and category");


1;





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


