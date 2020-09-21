#!/usr/bin/perl

use Apache::Log::Parser;
use Time::Local;
use Data::Dumper;
use lib '/opt/apache_eq2/';
use IPBlocker;
use feature qw(say);
use Data::Printer;

sub daemonize {
   use POSIX;
   POSIX::setsid or die "setsid: $!";
   my $pid = fork() // die $!;
   exit(0) if $pid;
   #Directorio de trabajo.
   chdir "/opt/apache_eq2";
   umask 0;
   for (0 .. (POSIX::sysconf (&POSIX::_SC_OPEN_MAX) || 1024))
   { POSIX::close $_ }
   open (STDIN, "</dev/null");
   open (STDOUT, ">/dev/null");
   open (STDERR, ">&STDOUT");
}

daemonize();


# Lectura de los valores del archivo de configuración
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

my %valores = leeConfiguracion();

if (exists (${$valores{"apache"}}{"log"})) {
   $logService = ${$valores{"apache"}}{"log"};
   if (not -e $logService) {
      `mkdir -p "\$(dirname $logService)" && touch "$logService"`;
   }
   open LOG, ">>".$logService or die "No se pudo escribir en la bitácora";
   print LOG "INICIO DEL SERVICIO - ".(strftime "%F %T", localtime)."\n";
   close(LOG);
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

# Variables globales
my $parser = Apache::Log::Parser->new( fast => 1 ); # Se crea el parser para los logs de Apache/Nginx

# Se define la ruta del log a revisar
my $ipBlocker = new IPBlocker($blockTime,$logService);
my $reloadFile = 1; #Checa el archivo de logs cada 1 segundo
my $bandera = 0; # Sirve para indicar si es la primera vez que se ingresa al bucle infinito
while(1) {
   if ($bandera == 0) { # Si es la primera vez que se ingresa al bucle
        $noLineasUltimoMonitoreo = `cat $rutaLog | wc -l`; # Se calcula la contidad de lineas actuales del log a revisar
        chomp($noLineasUltimoMonitoreo);
        $lineasPorRevisar = qx/tail -$noLineasUltimoMonitoreo $rutaLog/; # Se leen todas las lineas del log
        @lineas = split("\n", $lineasPorRevisar); # Se separa linea por linea
        $bandera = 1; # Se actualiza el valor de la bandera para que no caiga en este if nunca más
    } else {
        $noLineasActuales = `cat $rutaLog | wc -l`; # Se leen todas las lineas del log actualizado
        chomp($noLineasActuales);
        $lineasNuevas =  $noLineasActuales - $noLineasUltimoMonitoreo; # Se calculan las nuevas lineas que han sido generadas en el log desde la ultima revisión
        if ($lineasNuevas == 0) { # Si no hay diferencia, simplemente se espera para la siguiente revisión
            sleep($reloadFile);
            next;
        }
        # En caso de encontrar nuevas líneas en el log
        $lineasPorRevisar = qx/tail -$lineasNuevas $rutaLog/; # Se leen las nuevas líneas encontradas en el log
        @lineas = split("\n", $lineasPorRevisar); # Se separa linea por linea
        $noLineasUltimoMonitoreo = $noLineasActuales; # Se actualiza el valor del total de líneas leídas en la última revisión
    }
    my %ips = (); # Reset al hash que contiene el timestamp y el no. de veces que aparece
    my %hostsEncontrados = (); # Hash que almacena cuáles IPs ya han pasado a la función de banneo
    foreach (@lineas) {
        my $log = $parser->parse($_); # Se hace el parsing de la linea actual del log
        my $timestamp = $log->{rhost} ." - " . $log->{time} . " - " . $log->{date} . "\n"; # Se genera un timestamp de la linea actual. [HOST - HORA - FECHA]
        # El timestamp sirve como llave para nuestro hash. El valor asociado a la llave, es el número de apariciones de esa llave dentro de las lineas que se leyeron del log.
        if (exists($ips{$timestamp})) { # Si ya existe esa llave dentro del hash, recuperamos el valor y se incrementa en uno
            $cont = $ips{$timestamp};
            if ($cont >= $attempts) {next;} # Si se trata de una timestamp que ya ha sido identificado, se skipea
            $cont++; # Se incrementa el valor en uno
            $ips{$timestamp} = $cont; # Se actualiza el valor dentro del hash
            if($ips{$timestamp} >= $attempts) { #Y se revisa si el valor actualizado, es mayor o igual al tope de peticiones definidas en el archivo de configuaración
                if (exists($hostsEncontrados{$log->{rhost}})) { # Si existe dentro del hash la IP, ya ha sido banneada y no es necesario hacer algo
                    next;
                } else { # En caso de de que la IP no se encuentre dentro del hash
                    $hostsEncontrados{$log->{rhost}} = 1; # Se guarda la IP del host en el hash sólo como referencia para que no se repita
                    # Se manda a llamar la función para el banneo de la IP encontrada
                    $ipBlocker->blockIPs("$log->{rhost}");
                } 
            }
        } else { # En caso de que se trate de un timestamp nuevo
            $ips{$timestamp} = 1; # Se registra dentro del hash y se le asigna 1 aparición
        }
    }
    sleep($reloadFile);
}
