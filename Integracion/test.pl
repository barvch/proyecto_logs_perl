#!/usr/bin/perl
use Data::Dumper;
sub leeConfiguracion {
   open (CONFIG_FILE, "apache_eq2.conf");
   my @contenido = <CONFIG_FILE>;
   my %valores = ();
   my $campo = "";
   foreach (@contenido) {
	   	if ($_ =~ m#\[.+\]#) {
	   		$campo = $_;
	   		chomp($campo);
	   		$campo =~ s/\s+//g;
	   		$campo =~ s/.*\[//;
	   		$campo =~ s/\].*//;
	   	}
       elsif (index($_, "#") != -1) { # Se omiten los comentarios del archivo de conf
           next;
       } else { # Se guarda en el hash, llave y valor
           my $tmp = $_;
           $tmp =~ s/\n//;
           $tmp =~ s/\s+//g;
           my @temp = split("=", $tmp);
           $valores{$campo}{$temp[0]} = $temp[1];
       }
   }
   return %valores;
}


%valores = leeConfiguracion();

if (exists (${$valores{"apache"}}{"log"})) {
	$logService = ${$valores{"apache"}}{"log"};
}
if (exists ($valores{"apache2"})) {
	$enable = ${$valores{"apache2"}}{"enable"};
	$rutaLog = ${$valores{"apache2"}}{"log"};
	$attempts = ${$valores{"apache2"}}{"attempts"};
	$blockTime = ${$valores{"apache2"}}{"time"};
}
elsif (exists ($valores{"ngnix"})) {
	$enable = ${$valores{"ngnix"}}{"enable"};
	$rutaLog = ${$valores{"ngnix"}}{"log"};
	$attempts = ${$valores{"ngnix"}}{"attempts"};
	$blockTime = ${$valores{"ngnix"}}{"time"};
}
else{
	exit;
}
if ($enable ne "yes") {
	exit;
}
