package Apache2::AuthNetCust;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

use mod_perl2;

require Exporter;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
	
);
$VERSION = '0.01';

# test for the version of mod_perl, and use the appropriate libraries
require Apache2::Access;
require Apache2::Connection;
require Apache2::Log;
require Apache2::RequestRec;
require Apache2::RequestUtil;
use Apache2::Const -compile => qw(HTTP_UNAUTHORIZED OK DECLINED);

# Preloaded methods go here.

#handles Apache requests
sub handler
{
   my $r = shift; 

   my ($result, $password) = $r->get_basic_auth_pw;
    return $result if $result; 
 
   # change based on version of mod_perl 
   my $user = $r->user;

   # Command must be provided
   my $pipe_command = $r->dir_config('Command');
   # Argument delimiter to use between arguments
   my $delim = $r->dir_config('ArgDelimiter') ? $r->dir_config('ArgDelimiter') : "\|\|";
   
   if ($password eq "") {
        $r->note_basic_auth_failure;
	$r->log_error("user $user: no password supplied",$r->uri);
        return Apache2::Const::HTTP_UNAUTHORIZED;
   }
   
   my $command = "$pipe_command $user $delim $password";
   my $command_out = qx($command);
   
   if ($command_out eq 0) {
        return Apache2::Const::HTTP_UNAUTHORIZED;
   } elsif ($command_out eq 1) {
        return Apache2::Const::OK;
   } elsif ($command_out eq 2) {
        return Apache2::Const::DECLINED;
   }
}

# Autoload methods go after =cut, and are processed by the autosplit program.

# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Apache2::AuthNetCust - mod_perl module that calls a user defined auth backend

=head1 SYNOPSIS

 AuthName "Custom Auth"
 AuthType Basic

 PerlSetVar Command "/opt/mysite/scripts/auth.sh" # command must be set
 PerlSetVar ArgDelimiter "^^^" # if not set, defaults to ||

 require valid-user

 PerlAuthenHandler Apache2::AuthNetCust

=head1 DESCRIPTION

This module authenticates users via a user defined command, which must return 0 for HTTP_UNAUTHORIZED, 1 for OK and 2 for DECLINED. It has only one option.

=item PerlSetVar Command

The command which can be any command line parameter executable from mod_perl by whichever user Apache and mod_perl are running under.

=back

=head1 INSTALLATION 

It's a pretty straightforward install if you already have mod_perl installed.

After you have unpacked the distribution type:

 perl Makefile.PL
 make
 make test 
 make install

Then in your httpd.conf file or .htaccess file, in either a <Directory> or <Location> section put:

AuthName "Custom Auth"
 AuthType Basic

 PerlSetVar Command "/opt/mysite/scripts/auth.sh" # command must be set
 PerlSetVar ArgDelimiter "^^^" # if not set, defaults to ||

 require valid-user

 PerlAuthenHandler Apache2::AuthNetCust

If you don't have mod_perl, then the Makefile will prompt you to 
install.

You may also notice that the Makefile.PL will ask you to install ExtUtils::AutoInstall.  This is 
necessary for the installation process to automatically install any of the dependencies that you
are prompted for. You may choose to install the module, or not.

For an example of a simple auth handler script, see example_handler.pl

=head1 HOMEPAGE

Module Home: http://github.com/1stvamp/custauth

=head1 AUTHOR

 Wesley Mason <wes [at] 1stvamp [dot] org>

=head1 SEE ALSO

L<Apache2::AuthNetLDAP>

=head1 ACKNOWLEDGMENTS

Mark Wilcox and Shannon Eric Peevey for Apache2::AuthNetLDAP.

=head1 WARRANTY AND LICENSE

You can distribute and modify in accordance to the same license as Perl. Though I would like to know how you are using the module or if you are using the module at all.

Like most of the stuff on the 'net, I got this copy to work for me without destroying mankind, your mileage may vary.

=cut


1;
__END__
