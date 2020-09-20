#!/usr/bin/perl

sub daemonize {
   use POSIX;
   POSIX::setsid or die "setsid: $!";
   my $pid = fork() // die $!;
   exit(0) if $pid;

   chdir "/var/log/nginx/";       #Directorio de trabajo.
   umask 0;
   for (0 .. (POSIX::sysconf (&POSIX::_SC_OPEN_MAX) || 1024))
      { POSIX::close $_ }
   open (STDIN, "</dev/null");
   open (STDOUT, ">/dev/null");
   open (STDERR, ">&STDOUT");
 }

daemonize();
#Aquí va el código que quieras.
while (1) {
   `touch hola.txt`;
}