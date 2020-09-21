#!/usr/bin/perl

=encoding UTF-8

=head1 NAME

apache_eq2.pl - En este a archivo, se hace un parsing del log del servicio indicando (Apache/NGINX) dentro del archivo de 
configuracion B<(apache_eq2.conf)> y se determinan las direcciones IP de los clientes que estan haciendo un ataque de 
fuerza bruta.

=head1 SYNOPSIS

  Se llama al script que se carga el archivo de configuración "apache_eq2.conf". 
  En este archivo se pueden configurar diferentes valores como el servicio a monitorear, el tiempo de bloqueo a cada ip, 
  el log que se analizará y el número de intentos con el cual se bloqueará a un host.
  ./apache_eq2.pl

=head2 DESCRIPTION

  Este es el script principal que se encarga de llamar al módulo de bloqueo de IP's, tener un comportamiento 
  de "servicio" y estar monitoreando el log de que se le indicó en el archivo de "apache_eq2.conf" para 
  bloquear efectivamente las ips que intenten hacer un ataque por fuerza bruta/diccionario.

=over 12

=item C<Obtencion de datos - Mecanica de lectura del log>

Por cada ronda de monitoreo, se leen unicamente las nuevas lineas agregadas al log del servicio.  
De las lineas obtenidas para la ronda actual, se lee linea por linea y se obtienen los siguientes datos pertinentes:
B<Direccion IP> del Host que se conecta al servidor web ($log->{rhost}).
B<Hora> (UTC) en la que que llega la peticion al servidor en el formato HH:MM:SS  ($log->{time}).
B<Fecha> en la que llega la peticion al servidor web en formato DD/MM/AAAA ($log->{date}).

=item C<Analisis de datos y deteccion de ataques> 

La conjuncion de los 3 datos resultantes del parsing del log, se genera una llave para cada una de las lineas leidas con la siguiente nomenclatura:
 [IP] - [HORA] - [FECHA]
Por ejemplo:
 192.168.123.45 - 08:45:23 - 19/09/2020
Dicha llave, es almacenada dentro de un hash y como valor asociado, el numero de ocurrencias que se vayan detectando de la llave a la hora de recorrer linea por linea del log.
B<Cuando el numero de ocurrencias asociadas al timestamp excede el numero tope de intentos fallidos> indicados en el archivo de configuracion, se llama a la funcion encargada de bannear la IP.
El monitoreo es realizado cada cierto tiempo, el cual puede ser indicado/modificado dentro del archivo de configuracion.

=back

=head2 Methods

=over 12

=item C<daemonize>

Función encargada de dar al programa un comportamiento de servicio. No recibe ningún parámetro ni devuelve ningún valor.

=item C<tstktsk>

Función que se manda a llamar tras el término de ejecución del programa. Detecta si para terminar la ejecución se 
hace mediante SIGTERM, si es verdadero guarda en los logs la fecha de finalización del programa, en caso contrario 
no hace nada.
No recibe ningún argumento ni devuelve ningún valor.

=item C<leeConfiguracion>

Función encargada de parsear el archivo de configuración para inicializar algunas variables globales correctamente.
No recibe nada y devuelve un hash de hashes de los datos encontrados en el archivo de configuración.
Las llaves de los primeros hashes son los valores que se encuentran entre corchetes (en el archivo de configuración),
y los valores son los datos que se encuentran en dicha sección.

=back

=head1 LICENSE

Este módulo fue creado bajo una licencia artística.
Ver L<perlartistic>.

=head1 AUTHOR

Equipo2 - PBSI 14G

=head1 SEE ALSO

L<UnblockIP>

=cut


use Apache::Log::Parser;
use Time::Local;
use lib '/opt/apache_eq2/';
use IPBlocker;

#Función encargada de relizar la tarea para volver el script un servicio
#Crea un fork y sólo el PID child queda vivo. Se cambia al directorio de trabajo del programa en /opt/apache_eq2/
#y envía la salida estandar, entrada estándar y salida del error estándar a /dev/null para quitar la interacción
#con la shell.
sub daemonize {
   use POSIX;
   POSIX::setsid or die "setsid: $!";
   my $pid = fork() // die $!;
   exit(0) if $pid;
   #Directorio de trabajo.
   chdir "/opt/apache_eq2/";
   umask 0;
   for (0 .. (POSIX::sysconf (&POSIX::_SC_OPEN_MAX) || 1024))
   { POSIX::close $_ }
   open (STDIN, "</dev/null");
   open (STDOUT, ">/dev/null");
   open (STDERR, ">&STDOUT");
}

daemonize();

$SIG{TERM} = \&tsktsk;

sub tsktsk {
    $SIG{TERM} = \&tsktsk;           
    open LOG, ">>".$logService or die "No se pudo escribir en la bitácora"; 
    print LOG "SERVICIO DETENIDO ".(strftime "%F %T", localtime)."\n";
    close(LOG);
    exit;
}

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