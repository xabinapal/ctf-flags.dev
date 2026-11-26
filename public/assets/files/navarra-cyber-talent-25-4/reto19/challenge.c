#include <util/delay.h>
#include <avr/io.h>
#include <stdlib.h>
#include <string.h>

void showflag(){
	Serialprintln("\n\rWelcome to the system");
	Serialprintln("\n\rC0nclave{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}");
}

long Myrandom(long max){
    return(rand() % max);
}

void Serialbegin(void) {
    UBRR0H = (103 >> 8);
    UBRR0L = 103; // 9600 baud con 16MHz
    UCSR0B = (1 << RXEN0) | (1 << TXEN0);
    UCSR0C = (1 << UCSZ01) | (1 << UCSZ00);
}

void Serialsend(char c) {
    while (!(UCSR0A & (1 << UDRE0)));
    UDR0 = c;
}

void Serialprint(const char *s) {
    while (*s) Serialsend(*s++);
}

void Serialprintln(const char *s) {
    Serialprint(s);
    Serialsend('\n');
    Serialsend('\r');
}

uint8_t Serialavailable(void) {
    return ((UCSR0A & (1 << RXC0)) != 0);
}

char Serialread(void) {
    while (!Serialavailable());
    return UDR0;
}

char readLine(char *out){
    char caracter;
    int i = 0;
    caracter = Serialread();
    while(caracter != '\n'){
        out[i++] = caracter;
        caracter = Serialread();
    }
    out[i] = '\0';
}

void menuOpciones(){
    Serialprintln("\n\r===== Sistema de Control de Tunel =====");
    Serialprintln("1. Estado de Ventiladores");
    Serialprintln("2. Nivel de CO2");
    Serialprintln("3. Estado de Iluminacion");
    Serialprintln("4. Historial de Alertas");
    Serialprintln("5. Salir");
    Serialprint("\n\rSelecciona opcion: ");
}

void estadoVentiladores(){
    Serialprintln("\n\r--- Estado de Ventiladores ---");
    char buffer[64];
    for(int i = 1; i <= 3; i++){
        sprintf(buffer, "Ventilador %d: %s", i, Myrandom(2) ? "Activo" : "Inactivo");
        Serialprintln(buffer);
    }
}

void nivelCO2(){
    int co2 = Myrandom(1000); // ppm
    char buffer[64];
    sprintf(buffer, "\n\rNivel de CO2: %d ppm", co2);
    Serialprintln(buffer);
}

void estadoIluminacion(){
    Serialprintln("\n\r--- Estado de Iluminacion ---");
    char buffer[64];
    for(int i = 1; i <= 5; i++){
        sprintf(buffer, "Luz %d: %s", i, Myrandom(2) ? "Encendida" : "Apagada");
        Serialprintln(buffer);
    }
}

void historialAlertas(){
    Serialprintln("\n\r--- Historial de Alertas ---");
    char buffer[64];
    const char *alertas[] = {"CO2 Alto", "Ventilador Inactivo", "Luz Apagada"};

    for(int i = 0; i < 3; i++){
        int dia = Myrandom(30) + 1;
        int mes = Myrandom(12) + 1;
        const char *alerta = alertas[Myrandom(3)];
        sprintf(buffer, "Alerta - %02d/%02d - %s", dia, mes, alerta);
        Serialprintln(buffer);
    }
}

void setup(){
    Serialbegin();
}

void loop(){
    char opcion[2];
    while(1){
        menuOpciones();
        readLine(opcion);
        Serialsend(opcion[0]);
        Serialprintln("");
        switch(opcion[0]){
            case '1': estadoVentiladores(); break;
            case '2': nivelCO2(); break;
            case '3': estadoIluminacion(); break;
            case '4': historialAlertas(); break;
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

