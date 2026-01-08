#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "logger.h"

int main(void) {
    const char *path = "/tmp/logger-test.log";
    unlink(path);
    assert(logger_init(path, false)==0);
    LOG_INFOF("hello %d", 1);
    logger_flush();
    logger_shutdown();
    struct stat st; 
    assert(stat(path, &st)==0);
    assert(st.st_size>0);
    unlink(path);

    /* stdout-only logging with null file path should still work */
    assert(logger_init(NULL, true)==0);
    LOG_WARNF("to stdout only");
    logger_flush();
    logger_shutdown();

    /* disable stdout and file (no output sinks) should still initialize */
    assert(logger_init(NULL, false)==0);
    LOG_ERRORF("no sink");
    logger_shutdown();
    return 0;
}
