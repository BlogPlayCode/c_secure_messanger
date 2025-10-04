rm kyber_utility.o -f
gcc -o kyber_utility.o kyber_utility.c kyber/ref/*.c -Ikyber/ref
chmod +x kyber_utility.o
