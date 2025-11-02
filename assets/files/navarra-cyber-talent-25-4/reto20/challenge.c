#include <util/delay.h>
#include <avr/io.h>
#include <stdlib.h>
#include <string.h>

char myrandomseed[4] = "XXXX";
int lalala=42;
long Myrandom(long max){

	return(rand()%max);

}

void Serialbegin(void) {
    UBRR0H = (103 >> 8);
    UBRR0L = 103; // 9600 baud con 16MHz
    UCSR0B = (1 << RXEN0) | (1 << TXEN0);  // Habilita transmisor
    UCSR0C = (1 << UCSZ01) | (1 << UCSZ00); // 8 bits de datos
}

void Serialsend(char c) {
    while (!(UCSR0A & (1 << UDRE0))); // Espera que el buffer esté vacío
    UDR0 = c;
}

void Serialprint(const char *s) {
    while (*s) {
        Serialsend(*s++);
    }
}

void Serialprintln(const char *s) {
    Serialprint(s);
    Serialsend('\n');
	Serialsend('\r');

}

uint8_t Serialavailable(void) {
    return ((UCSR0A & (1 << RXC0)) != 0); // Retorna 1 si hay datos en el buffer
}

char Serialread(void) {
    while (!Serialavailable()); // Espera hasta que haya datos
    return UDR0;
}

void readPass(){
	char caracter;
	int indice;
	int userend;
	char entrada[32];
	userend=0;
	indice=0;
	while(userend != 1){
		while (Serialavailable() == 0) {_delay_ms(50);}
		caracter = Serialread();
		if ((caracter == '\r') || (caracter == '\n')) {
			entrada[indice] = '\0';
			userend=1;
			if (lalala == 388) {
				showflag();
				indice = 0;
			} else {
				Serialprintln("\n\rIncorrect password!!");
				indice = 0;
			}
		} else {
			Serialsend('*');
			entrada[indice] = caracter;
			indice=indice+1;
		}
	}
}

void menuOpciones(){
    Serialprintln("\n\r===== PLC Gasolinera =====");
    Serialprintln("1. Ver niveles de tanques");
    Serialprintln("2. Estado de bombas");
    Serialprintln("3. Historial de entregas");
    Serialprintln("4. Cambiar precios (requiere password)");
    Serialprintln("5. Salir");
    Serialprint("\n\rSelecciona opcion: ");
}

void verTanques(){
    int gasolina = Myrandom(101);
    int diesel = Myrandom(101);
    int aditivo = Myrandom(101);

    Serialprintln("\n\r--- Niveles de Tanques ---");
    char buffer[64];
    sprintf(buffer,"Gasolina: %d%%", gasolina);
    Serialprintln(buffer);
    sprintf(buffer,"Diesel: %d%%", diesel);
    Serialprintln(buffer);
    sprintf(buffer,"Aditivo: %d%%", aditivo);
    Serialprintln(buffer);
}

void estadoBombas(){
    Serialprintln("\n\r--- Estado de Bombas ---");
    if(Myrandom(2)==0){
        Serialprintln("Bomba 1: Activa");
    } else {
        Serialprintln("Bomba 1: Inactiva");
    }
    if(Myrandom(2)==0){
        Serialprintln("Bomba 2: Activa");
    } else {
        Serialprintln("Bomba 2: Inactiva");
    }
}

void historialEntregas(){
    Serialprintln("\n\r--- Historial de Entregas ---");
    char buffer[64];
    const char *productos[] = {"Gasolina", "Diesel", "Aditivo"};

    for(int i=0; i<3; i++){
        int dia = Myrandom(30) + 1;
        int mes = Myrandom(12) + 1;
        int litros = (Myrandom(29) + 1) * 1000;  // 1000 a 30000
        const char *producto = productos[Myrandom(3)];

        sprintf(buffer,"Camion cisterna - %02d/%02d - %d L %s", dia, mes, litros, producto);
        Serialprintln(buffer);
    }
}

void cambiarPrecios(){
    Serialprintln("\n\r*** Acceso restringido ***");
    Serialprint("Introduce password: ");
    readPass();
}

void showflag(){
	Serialprintln("\n\rWelcome to the system");
	Serialprintln("\n\rC0nclave{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}");
}

void setup(){
    Serialbegin();
    srand(myrandomseed[0]);
}

void loop(){
    char opcion;
    while(1){
        menuOpciones();
        while(Serialavailable()==0){_delay_ms(50);}
        opcion = Serialread();
	while(Serialread() != '\n'){
		_delay_ms(50);
	}
        Serialsend(opcion);
        Serialprintln("");
        switch(opcion){
            case '1': verTanques(); break;
            case '2': estadoBombas(); break;
            case '3': historialEntregas(); break;
            case '4': cambiarPrecios(); break;
            case '5': Serialprintln("\n\rSaliendo al menu principal..."); return;
            default: Serialprintln("\n\rOpcion invalida."); break;
        }
    }
}

int main(void){
    setup();
    while(1){
        loop();
    }
}
