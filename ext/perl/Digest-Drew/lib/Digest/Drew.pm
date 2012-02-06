package Digest::Drew;

use 5.006000;
use strict;
use warnings;
use integer;

require Exporter;
require Digest::base;

our @ISA = qw(Exporter Digest::base);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Digest::Drew ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Digest::Drew', $VERSION);

# Preloaded methods go here.

sub new {
	my ($class, $algoname) = @_;
	$class = ref($class) if ref($class);
	my $self = ctx_new($algoname) || return;
	bless($self, $class);
}

sub DESTROY {
	my ($self) = @_;

	ctx_destroy($$self) if $$self;
}

sub clone {
	my ($self) = @_;
	my $clone = ctx_clone($$self) || return;

	bless(\$clone, ref($self));
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Digest::Drew - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Digest::Drew;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Digest::Drew, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

brian m. carlson, E<lt>bmc@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by brian m. carlson

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
