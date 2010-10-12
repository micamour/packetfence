#!/usr/bin/perl -w

use strict;
use warnings;
use diagnostics;

use lib qw(
   /usr/local/pf/conf
   /usr/local/pf/lib
);

use Test::Pod::Coverage tests => 6;

pod_coverage_ok("authentication::ldap");
pod_coverage_ok("authentication::local");
pod_coverage_ok("authentication::radius");
pod_coverage_ok("pf::SNMP");
pod_coverage_ok("pf::floatingdevice");
pod_coverage_ok("pf::freeradius");
