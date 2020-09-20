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
$parser = Apache::Log::Parser->new( fast => 1 ); # Se crea el parser para los logs de Apache/Nginx

# Se hace y llena el hash de los meses con su digito
%mesesValor = (); # Hash que tendrá como llaves @meses y como valores @digitos, para cada valor respectivo
@meses = qw(Jan Feb Mar Apr May Jun Jul Ago Sep Oct Nov Dec);
@digitos  =  qw(01 02 03 04 05 06 07 08 09 10 11 12);
@mesesValor{@meses} = @digitos; # Se asigna llave y valor dentro de hash


# Se define la ruta del log a revisar

#$rutaLog = $valores{"log"}; # se usa la ruta del diccionario
#$rutaLog = "ejemplo.log";
$rutaLog = "/var/log/apache2/access.log.1";

while(1) {
    open(LISTA, "+>", "ips.txt"); # Se abre el archivo donde se almacenarán las IPs a bloquear en modo de sobre escritura
    $lineasPorRevisar = qx/tail -200 $rutaLog/; # Se leen las últimas 200 lineas del archivo log indicado en el archivo de configuración
    @lineas = split("\n", $lineasPorRevisar); # Se separa linea por linea
    %ips = (); # Hash que contiene el timestamp y el conteo de este timestamp de todas las peticiones que se encuentren en en log
    foreach (@lineas) {
        $log = $parser->parse($_); # Se hace el parsing de la linea actual del log
        $timestamp = $log->{rhost} ." - " . $log->{time} . " - " . $log->{date} . "\n"; # Se genera un timestamp de la linea actual. [HOST - HORA - FECHA]
        # El timestamp sirve como llave para nuestro hash. El valor asociado a la llave, es el número de apariciones de esa llave dentro de las lineas que se leyeron del log.
        if (exists($ips{$timestamp})) { # Si ya existe esa llave dentro del hash, recuperamos el valor y se incrementa en uno
            $cont = $ips{$timestamp};
            if ($cont >= $valores{"attempts"}) {next;} # Si se trata de una timestamp que ya ha sido identificado, se skipea
            $cont++; # Se incrementa el valor en uno
            $ips{$timestamp} = $cont; # Se actualiza el valor dentro del hash
            if($ips{$timestamp} >= $valores{"attempts"}) { #Y se revisa si el valor actualizado, es mayor o igual al tope de peticiones definidas en el archivo de configuaración
                print LISTA ("$timestamp"); # En caso de que sí, se escribe la IP a bloquear dentro del archivo
            }
        } else { # En caso de que se trate de un timestamp nuevo
            $ips{$timestamp} = 1; # Se registra dentro del hash y se le asigna 1 aparición
        }
    }
    print("Se ha actualizado la lista de IP's por bloquear\n");
    close(LISTA); # Se cierra el archivo ya con las IPs escritas.
    sleep($valores{"time"}); # Se esperan n segundos para volver a revisar el log de apache.
}