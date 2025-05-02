
start_opts() {
if (argc > 1) {
        if (strcmp(argv[1], "--dump-config") == 0) {
	    dump_config(cfg);
	    shutdown_OK(cfg, -1);
	    exit(0);
	}else {
	  shutdown_bad_opts(cfg, argc , argv);
	}
	
    }
}

