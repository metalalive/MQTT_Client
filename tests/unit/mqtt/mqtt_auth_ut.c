#include "mqtt_include.h"

static void RunAllTestGroups(void) {} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main
