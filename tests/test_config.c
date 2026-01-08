#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "config.h"

int main(void) {
    proxy_config cfg;
    config_init_defaults(&cfg);
    assert(cfg.listen_port==1080);
    assert(cfg.upstream_port==2080);
    assert(cfg.require_auth==false);
    assert(cfg.require_upstream_auth==false);
    config_free(&cfg);

    const char *cfg_path = "/tmp/proxy-chain-test.cfg";
    FILE *f = fopen(cfg_path, "w");
    fprintf(f, "listen_port=5555\nupstream_host=example.com\nrequire_auth=true\nauth_user=u\nauth_pass=p\nrequire_upstream_auth=true\nupstream_user=uu\nupstream_pass=pp\nlog_to_stdout=false\nlog_to_file=true\nlog_file=/tmp/pc.log\nlog_level=debug\n");
    fclose(f);

    assert(config_load(cfg_path, &cfg)==0);
    assert(cfg.listen_port==5555);
    assert(strcmp(cfg.upstream_host,"example.com")==0);
    assert(cfg.require_auth==true);
    assert(cfg.require_upstream_auth==true);
    assert(strcmp(cfg.auth_user,"u")==0);
    assert(strcmp(cfg.auth_pass,"p")==0);
    assert(strcmp(cfg.upstream_user,"uu")==0);
    assert(strcmp(cfg.upstream_pass,"pp")==0);
    assert(cfg.log_to_stdout==false);
    assert(cfg.log_to_file==true);
    assert(strcmp(cfg.log_file,"/tmp/pc.log")==0);
    assert(cfg.log_level==LOG_DEBUG);
    config_free(&cfg);
    remove(cfg_path);

    /* ensure booleans can be toggled back to false and missing creds handled */
    f = fopen(cfg_path, "w");
    fprintf(f, "require_auth=false\nrequire_upstream_auth=false\n");
    fclose(f);
    assert(config_load(cfg_path, &cfg)==0);
    assert(cfg.require_auth==false);
    assert(cfg.require_upstream_auth==false);
    config_free(&cfg);
    remove(cfg_path);

    /* empty credential values should NOT flip auth flags */
    f = fopen(cfg_path, "w");
    fprintf(f, "auth_user=\nauth_pass=\nupstream_user=\nupstream_pass=\n");
    fclose(f);
    assert(config_load(cfg_path, &cfg)==0);
    assert(cfg.require_auth==false);
    assert(cfg.require_upstream_auth==false);
    assert(cfg.auth_user==NULL);
    assert(cfg.auth_pass==NULL);
    assert(cfg.upstream_user==NULL);
    assert(cfg.upstream_pass==NULL);
    config_free(&cfg);
    remove(cfg_path);

    /* invalid path should fail */
    assert(config_load("/nonexistent/path/zzz.cfg", &cfg)!=0);
    return 0;
}
