use Data::Dumper;
use Apache::Log::Parser;
use Time::Local;

# Lectura de los valores del archivo de configuración

open (CONFIG_FILE, "servicio_eq2.conf");
@contenido = <CONFIG_FILE>;
%valores = ();
foreach (@contenido) {
    if (index($_, "#") != -1) { # Se omiten los comentarios del archivo de conf
        next;
    } else { # Se guarda en el hash, llave y valor
        @temp = split("=", $_);
        $valores{$temp[0]} = $temp[1];
    }
}

# Variables globales
$parser = Apache::Log::Parser->new( fast => 1 ); # Se crea el parser
%conteo = (); # Hash que tiene las veces que aparece un host en en log
%ips = ();
open(LISTA, "+>", "ips.txt");

# Se hace y llena el hash de los meses con su digito
%mesesValor = ();
@meses = qw(Jan Feb Mar Apr May Jun Jul Ago Sep Oct Nov Dec);
@digitos  =  qw(01 02 03 04 05 06 07 08 09 10 11 12);
@mesesValor{@meses} = @digitos;

# Se leen todas las lineas del archivo log indicado en el archivo de configuración
#$rutaLog = $valores{"log"}; # se usa la ruta del diccionario
$rutaLog = "ejemplo.log";
open(LOG_APACHE, $rutaLog); #$valores{"log"}
@lineas = <LOG_APACHE>;
#pop(@lineas);
foreach (@lineas) {
    $log = $parser->parse($_);
    #print $log->{agent}, "\n"; 
    #print $log->{path}, "\n";
    $timestamp = $log->{rhost} ." - " . $log->{time} . " - " . $log->{date} . "\n";
    if (exists($ips{$timestamp})) {
        $cont = $ips{$timestamp};
        if ($cont >= $valores{"attempts"}) {next;}
        $cont++;
        $ips{$timestamp} = $cont;
        if($ips{$timestamp} >= $valores{"attempts"}) {
            print("[+] Posible FB: $timestamp");
            print LISTA ("$timestamp\n");
        }
    } else {
        $ips{$timestamp} = 1;
    }
    #print $timestamp, "\n";
    @fecha = split("/", $log->{date});
    @tiempo = split(":", $log->{time});
    #$epochtime = timegm($tiempo[2],$tiempo[1],$tiempo[0],$fecha[0],$mesesValor{$fecha[1]},$fecha[2]); # La fecha en epoch xd
    #$valorTiempo = $epochtime + 10; # Para sumar segundos al timestamp encontrado
    if (exists($conteo{$log->{rhost}})){
        $cont = $conteo{$log->{rhost}};
        $cont++;
        $conteo{$log->{rhost}} = $cont;
    } else {
        $conteo{$log->{rhost}} = 1; 
    }
}
#print Dumper (\%conteo); 