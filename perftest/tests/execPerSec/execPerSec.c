#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

void usage(char *exe)
{
    printf("Usage: %s <frequency (Hz)> [<time to run (seconds)>]\n", exe);
    exit(1);
}

int main(int argc, char *argv[])
{
    pid_t pid;
    int wstatus = 0;
    char exe[] = "/bin/true";
    char *args[] = {"/bin/true", NULL};

    if (argc < 2) {
        usage(argv[0]);
    }

    int freq = atoi(argv[1]);
    if (freq <= 0) {
        printf("Frequency must be > 0\n");
        usage(argv[0]);
    }

    unsigned int delay = 1000000 / freq;

    int secs = 0;
    if (argc > 2) {
        secs = atoi(argv[2]);
        if (secs < 0) {
            printf("Time to run must be >= 0\n");
            usage(argv[0]);
        }
    }

    unsigned long total = secs * freq;

    unsigned long count = 0;
    while (total == 0 || count < total) {
        pid = fork();
        if (pid < 0) {
            printf("Fork failed, count = %ld\n", count);
            exit(2);
        } else if (pid == 0) {
            // child
            if (execve(exe, args, NULL) != 0) {
                printf("Execve failed, count = %ld\n", count);
                exit(3);
            }
        }

        wait(&wstatus);
        usleep(delay);
        count++;
    }

    return 0;
}

