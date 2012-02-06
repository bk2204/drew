use strict;
use warnings;

use Test::More;
BEGIN { plan tests => 3 };
use Digest::Drew;
ok(1); # If we made it this far, we're ok.

my $ctx = Digest::Drew->new('SHA-1');
ok(defined($ctx));
my $newctx = $ctx->clone;
ok(defined($newctx));
