package captiveportal::Controller::Authenticate;
use Moose;

BEGIN { extends 'captiveportal::PacketFence::Controller::Authenticate'; }

=head1 NAME

captiveportal::Controller::Root - Root Controller for captiveportal

=head1 DESCRIPTION

[enter your description here]

=cut

=head1 AUTHOR

root

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

=head2 postAuthentication

TODO: documention

=cut

after 'postAuthentication' => sub {
    my ($self, $c) = @_;
    return if $c->has_errors;
    my $info = $c->stash->{info};
    $c->add_deferred_actions( sub {
        $info;
        #Do what I want
    });
    return ;
};

__PACKAGE__->meta->make_immutable;

1;
