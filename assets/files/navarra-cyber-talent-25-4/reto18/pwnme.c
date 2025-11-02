#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

char comando[]="cat /home/flag/flag.txt";
char password[33];

void win() {
    system(comando);
    exit(0);
}

void vuln() {
    char buffer[128];
    memset(buffer, 0, sizeof(buffer));
    printf("Give me the password");
    for(int i=0;i<3;i++){

	printf("\n");
	printf("password: ");

	fflush(stdout);
    
	scanf("%s",buffer);

	printf(buffer);

	if(strcmp(buffer,password) == 0){

		sprintf(comando,"cat /flag/flag.txt");

	}

    }

}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    getrandom(password, 32, 0);

    vuln();

    printf("\nHere it is your flag: ");   
    win(); 
    
    return 0;
}
