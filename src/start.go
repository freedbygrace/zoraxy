package main

import (
	"context"
	"log"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/auth/sso/oauth2"
	"imuslab.com/zoraxy/mod/eventsystem"

	"github.com/gorilla/csrf"
	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/acme"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/auth/apitoken"
	"imuslab.com/zoraxy/mod/auth/sso/forward"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/dockerux"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/dynamicproxy/redirection"
	"imuslab.com/zoraxy/mod/forwardproxy"
	"imuslab.com/zoraxy/mod/geodb"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/info/logviewer"
	"imuslab.com/zoraxy/mod/mdns"
	"imuslab.com/zoraxy/mod/netstat"
	"imuslab.com/zoraxy/mod/pathrule"
	"imuslab.com/zoraxy/mod/plugins"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
	"imuslab.com/zoraxy/mod/sshprox"
	"imuslab.com/zoraxy/mod/statistic"
	"imuslab.com/zoraxy/mod/statistic/analytic"
	"imuslab.com/zoraxy/mod/streamproxy"
	"imuslab.com/zoraxy/mod/tlscert"
	"imuslab.com/zoraxy/mod/webserv"
)

/*
	Startup Sequence

	This function starts the startup sequence of all
	required modules. Their startup sequences are inter-dependent
	and must be started in a specific order.

	Don't touch this function unless you know what you are doing
*/

func startupSequence() {
	startupStart := time.Now()

	//Start a system wide logger and log viewer
	l, err := logger.NewLogger(LOG_PREFIX, *path_logFile)
	if err == nil {
		SystemWideLogger = l
	} else {
		panic(err)
	}

	if !*enableLog {
		//Disable file logging, use fmt logger instead
		l, err = logger.NewFmtLogger()
		if err != nil {
			panic(err)
		}
		SystemWideLogger = l
		SystemWideLogger.Println("System wide logging is disabled, all logs will be printed to STDOUT only")
	} else {
		// Load log configuration from file
		logConfig, err := logger.LoadLogConfig(CONF_LOG_CONFIG)
		if err != nil {
			SystemWideLogger.Println("Failed to load log config, using defaults: " + err.Error())
			logConfig = &logger.LogConfig{
				Enabled:  false,
				MaxSize:  "0",
				Compress: true,
			}
		}

		// Apply the configuration
		if err := l.ApplyLogConfig(logConfig); err != nil {
			SystemWideLogger.Println("Failed to apply log config: " + err.Error())
		}

		SystemWideLogger = l
		if !logConfig.Enabled {
			SystemWideLogger.Println("Log rotation is disabled")
		} else {
			SystemWideLogger.Println("Log rotation is enabled, max log file size " + logConfig.MaxSize)
		}
		SystemWideLogger.Println("System wide logging is enabled")
	}

		LogViewer = logviewer.NewLogViewer(&logviewer.ViewerOption{
			RootFolder: *path_logFile,
		})
	SystemWideLogger.Println("[Startup Timing] Logger initialized in " + time.Since(startupStart).String())
	stepStart := time.Now()

		// Initialize the cluster manager (for multi-node configuration replication)
		clusterManager = NewClusterManager(CONF_CLUSTER_CONFIG, nodeUUID, SystemWideLogger)
		if err := clusterManager.Load(); err != nil {
			SystemWideLogger.PrintAndLog("cluster", "Failed to load cluster config", err)
		}

		// Apply cluster configuration from flags/env vars if provided
		if *clusterEnabled || *clusterSecret != "" || *clusterPeers != "" || *clusterMeshMode || *clusterAdvertiseAddr != "" || os.Getenv("ZORAXY_ADVERTISE_ADDR") != "" {
			applyClusterFlagsConfig()
		}

		// Auto-detect advertise address for mesh mode (parse management port)
		mgmtPort := 8000
		if portStr := strings.TrimPrefix(*webUIPort, ":"); portStr != "" {
			if p, err := strconv.Atoi(portStr); err == nil {
				mgmtPort = p
			}
		}
		clusterManager.InitializeAdvertiseAddr(mgmtPort)

		// Start Docker Swarm auto-discovery if enabled
		if *clusterSwarmMode && *clusterSwarmService != "" {
			clusterManager.StartSwarmDiscovery(*clusterSwarmService, *clusterSwarmPort, *clusterSwarmScheme, 30*time.Second)
		}

		// Start heartbeat loop if cluster is enabled
		if clusterManager.IsEnabled() {
			clusterManager.StartHeartbeat()
			SystemWideLogger.PrintAndLog("cluster", "Cluster heartbeat started", nil)
		}
	SystemWideLogger.Println("[Startup Timing] Cluster manager initialized in " + time.Since(stepStart).String())
	stepStart = time.Now()

	//Create database
	backendType := database.GetRecommendedBackendType()
	switch *databaseBackend {
	case "leveldb":
		backendType = dbinc.BackendLevelDB
	case "boltdb":
		backendType = dbinc.BackendBoltDB
	}
	l.PrintAndLog("database", "Using "+backendType.String()+" as the database backend", nil)
	db, err := database.NewDatabase("./sys.db", backendType)
	if err != nil {
		log.Fatal(err)
	}
	sysdb = db
	//Create tables for the database
	sysdb.NewTable("settings")
	SystemWideLogger.Println("[Startup Timing] Database initialized in " + time.Since(stepStart).String())
	stepStart = time.Now()

	//Create tmp folder and conf folder
	os.MkdirAll(TMP_FOLDER, 0775)
	os.MkdirAll(CONF_HTTP_PROXY, 0775)

	//Create an auth agent
	sessionKey, err := auth.GetSessionKey(sysdb, SystemWideLogger)
	if err != nil {
		log.Fatal(err)
	}
	authAgent = auth.NewAuthenticationAgent(SYSTEM_NAME, []byte(sessionKey), sysdb, true, SystemWideLogger, func(w http.ResponseWriter, r *http.Request) {
		//Not logged in. Redirecting to login page
		http.Redirect(w, r, "/login.html", http.StatusTemporaryRedirect)
	})

	// Create initial admin account from flags/env vars if no users exist
	if authAgent.GetUserCounts() == 0 && *adminUser != "" && *adminPassword != "" {
		err := authAgent.CreateUserAccount(*adminUser, *adminPassword, "")
		if err != nil {
			SystemWideLogger.PrintAndLog("auth", "Failed to create initial admin account: "+err.Error(), nil)
		} else {
			SystemWideLogger.PrintAndLog("auth", "Initial admin account created from startup flags: "+*adminUser, nil)
		}
	}

	// Create an API key manager for plugin authentication
	pluginApiKeyManager = auth.NewAPIKeyManager()

	// Create an API token manager for external REST API access
	apiTokenManager, err = apitoken.NewTokenManager(sysdb)
	if err != nil {
		log.Fatal("Failed to initialize API token manager: " + err.Error())
	}
	// Set cluster callbacks for API token sync
	if clusterManager != nil {
		apiTokenManager.SetClusterCallbacks(
			func(tokenID, name, tokenHash, scopesJSON, description string, createdAt, expiresAt int64, disabled bool) {
				clusterManager.BroadcastAPIToken(context.Background(), tokenID, name, tokenHash, scopesJSON, description, createdAt, expiresAt, disabled)
			},
			func(tokenID string) {
				clusterManager.BroadcastAPITokenDelete(context.Background(), tokenID)
			},
		)
	}

	// Create bootstrap API token from CLI flag or environment variable
	bootstrapToken := *initialAPIToken
	if envToken := os.Getenv("ZORAXY_API_TOKEN"); envToken != "" {
		bootstrapToken = envToken
	}
	if bootstrapToken != "" && *enableRestAPI {
		// Create a bootstrap token with full access
		token, created, err := apiTokenManager.CreateTokenWithRawValue(
			"bootstrap-token",
			bootstrapToken,
			[]string{apitoken.ScopeAll},
			"Bootstrap token created from CLI/environment variable",
			time.Time{}, // Never expires
		)
		if err != nil {
			SystemWideLogger.PrintAndLog("auth", "Failed to create bootstrap API token", err)
		} else if created {
			SystemWideLogger.PrintAndLog("auth", "Bootstrap API token created: "+token.ID, nil)
		} else {
			SystemWideLogger.PrintAndLog("auth", "Bootstrap API token already exists, skipping", nil)
		}
	}

	SystemWideLogger.PrintAndLog("auth", "API token manager initialized", nil)
	SystemWideLogger.Println("[Startup Timing] Auth & token manager initialized in " + time.Since(stepStart).String())
	stepStart = time.Now()

	//Create a TLS certificate manager
	tlsCertManager, err = tlscert.NewManager(CONF_CERT_STORE, SystemWideLogger)
	if err != nil {
		panic(err)
	}

	//Create a redirection rule table
	db.NewTable("redirect")
	redirectAllowRegexp := false
	db.Read("redirect", "regex", &redirectAllowRegexp)
	redirectCaseSensitive := false
	db.Read("redirect", "case_sensitive", &redirectCaseSensitive)
	redirectTable, err = redirection.NewRuleTable(CONF_REDIRECTION, redirectAllowRegexp, redirectCaseSensitive, SystemWideLogger)
	if err != nil {
		panic(err)
	}
	SystemWideLogger.Println("[Startup Timing] TLS cert & redirect manager initialized in " + time.Since(stepStart).String())
	stepStart = time.Now()

	//Create a geodb store
	geodbStore, err = geodb.NewGeoDb(sysdb, &geodb.StoreOptions{
		AllowSlowIpv4LookUp:          !*enableHighSpeedGeoIPLookup,
		AllowSlowIpv6Lookup:          !*enableHighSpeedGeoIPLookup,
		Logger:                       SystemWideLogger,
		SlowLookupCacheClearInterval: GEODB_CACHE_CLEAR_INTERVAL * time.Minute,
	})
	if err != nil {
		panic(err)
	}
	SystemWideLogger.Println("[Startup Timing] GeoIP database initialized in " + time.Since(stepStart).String())
	stepStart = time.Now()

	//Create a load balancer
	loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{
		SystemUUID: nodeUUID,
		Geodb:      geodbStore,
		Logger:     SystemWideLogger,
	})

	//Create the access controller
	accessController, err = access.NewAccessController(&access.Options{
		Database:     sysdb,
		GeoDB:        geodbStore,
		ConfigFolder: CONF_ACCESS_RULE,
	})
	if err != nil {
		panic(err)
	}

	//Create authentication providers
	forwardAuthRouter = forward.NewAuthRouter(&forward.AuthRouterOptions{
		Address:  "",
		Logger:   SystemWideLogger,
		Database: sysdb,
	})

	oauth2Router = oauth2.NewOAuth2Router(&oauth2.OAuth2RouterOptions{
		Logger:   SystemWideLogger,
		Database: sysdb,
	})

	//Create a statistic collector
	statisticCollector, err = statistic.NewStatisticCollector(statistic.CollectorOption{
		Database: sysdb,
	})
	if err != nil {
		panic(err)
	}
	statisticCollector.SetAutoSave(STATISTIC_AUTO_SAVE_INTERVAL)
	SystemWideLogger.Println("[Startup Timing] LoadBalancer, AccessController, Auth providers, Stats initialized in " + time.Since(stepStart).String())
	stepStart = time.Now()

	//Start the static web server
	staticWebServer = webserv.NewWebServer(&webserv.WebServerOptions{
		Sysdb:                  sysdb,
		Port:                   strconv.Itoa(WEBSERV_DEFAULT_PORT), //Default Port
		WebRoot:                *path_webserver,
		EnableDirectoryListing: true,
		EnableWebDirManager:    *allowWebFileManager,
		Logger:                 SystemWideLogger,
	})
	//Restore the web server to previous shutdown state
	staticWebServer.RestorePreviousState()

	//Create a netstat buffer
	netstatBuffers, err = netstat.NewNetStatBuffer(300, SystemWideLogger)
	if err != nil {
		SystemWideLogger.PrintAndLog("Network", "Failed to load network statistic info", err)
		panic(err)
	}

	/*
		Path Rules

		This section of starutp script start the path rules where
		user can define their own routing logics
	*/

	pathRuleHandler = pathrule.NewPathRuleHandler(&pathrule.Options{
		Enabled:      false,
		ConfigFolder: CONF_PATH_RULE,
	})
	SystemWideLogger.Println("[Startup Timing] WebServer, NetStat, PathRules initialized in " + time.Since(stepStart).String())
	stepStart = time.Now()

	/*
		MDNS Discovery Service

		This discover nearby ArozOS Nodes or other services
		that provide mDNS discovery with domain (e.g. Synology NAS)
	*/

	if *allowMdnsScanning {
		portInt, err := strconv.Atoi(strings.Split(*webUIPort, ":")[1])
		if err != nil {
			portInt = 8000
		}

		hostName := *mdnsName
		if hostName == "" {
			hostName = MDNS_HOSTNAME_PREFIX + nodeUUID
		} else {
			//Trim off the suffix
			hostName = strings.TrimSuffix(hostName, ".local")
		}

		mdnsScanner, err = mdns.NewMDNS(mdns.NetworkHost{
			HostName:     hostName,
			Port:         portInt,
			Domain:       MDNS_IDENTIFY_DOMAIN,
			Model:        MDNS_IDENTIFY_DEVICE_TYPE,
			UUID:         nodeUUID,
			Vendor:       MDNS_IDENTIFY_VENDOR,
			BuildVersion: SYSTEM_VERSION,
		}, "")
		if err != nil {
			SystemWideLogger.Println("Unable to startup mDNS service. Disabling mDNS services")
		} else {
			//Start initial scanning
			go func() {
				hosts := mdnsScanner.Scan(MDNS_SCAN_TIMEOUT, "")
				previousmdnsScanResults = hosts
				SystemWideLogger.Println("mDNS Startup scan completed")
			}()

			//Create a ticker to update mDNS results every 5 minutes
			ticker := time.NewTicker(MDNS_SCAN_UPDATE_INTERVAL * time.Minute)
			stopChan := make(chan bool)
			go func() {
				for {
					select {
					case <-stopChan:
						ticker.Stop()
					case <-ticker.C:
						hosts := mdnsScanner.Scan(MDNS_SCAN_TIMEOUT, "")
						previousmdnsScanResults = hosts
						SystemWideLogger.Println("mDNS scan result updated")
					}
				}
			}()
			mdnsTickerStop = stopChan
		}
	}

	//Create WebSSH Manager
	webSshManager = sshprox.NewSSHProxyManager()

	//Create TCP Proxy Manager
	streamProxyManager, err = streamproxy.NewStreamProxy(&streamproxy.Options{
		AccessControlHandler: accessController.DefaultAccessRule.AllowConnectionAccess,
		ConfigStore:          CONF_STREAM_PROXY,
		Logger:               SystemWideLogger,
	})
	if err != nil {
		panic(err)
	}

	//Create WoL MAC storage table
	sysdb.NewTable("wolmac")
	SystemWideLogger.Println("[Startup Timing] mDNS, WebSSH, StreamProxy initialized in " + time.Since(stepStart).String())
	stepStart = time.Now()

	//Create an email sender if SMTP config exists
	sysdb.NewTable("smtp")
	EmailSender = loadSMTPConfig()

	//Create an analytic loader
	AnalyticLoader = analytic.NewDataLoader(sysdb, statisticCollector)

	//Create basic forward proxy
	sysdb.NewTable("fwdproxy")
	fwdProxyEnabled := false
	fwdProxyPort := 5587
	sysdb.Read("fwdproxy", "port", &fwdProxyPort)
	sysdb.Read("fwdproxy", "enabled", &fwdProxyEnabled)
	forwardProxy = forwardproxy.NewForwardProxy(sysdb, fwdProxyPort, SystemWideLogger)
	if fwdProxyEnabled {
		SystemWideLogger.PrintAndLog("Forward Proxy", "HTTP Forward Proxy Listening on :"+strconv.Itoa(forwardProxy.Port), nil)
		forwardProxy.Start()
	}

	/*
		ACME API

		Obtaining certificates from ACME Server
	*/
	//Create a table just to store acme related preferences
	sysdb.NewTable("acmepref")
	acmeHandler = initACME()
	acmeAutoRenewer, err = acme.NewAutoRenewer(
		ACME_AUTORENEW_CONFIG_PATH,
		CONF_CERT_STORE,
		int64(*acmeAutoRenewInterval),
		*acmeCertAutoRenewDays,
		acmeHandler,
		SystemWideLogger,
	)
	if err != nil {
		log.Fatal(err)
	}
	SystemWideLogger.Println("[Startup Timing] SMTP, Analytics, ForwardProxy, ACME initialized in " + time.Since(stepStart).String())
	stepStart = time.Now()

	/*
		Plugin Manager
	*/
	pluginFolder := *path_plugin
	pluginFolder = strings.TrimSuffix(pluginFolder, "/")
	ZoraxyAddrPort, err := netip.ParseAddrPort(*webUIPort)
	ZoraxyPort := 8000
	if err == nil && ZoraxyAddrPort.IsValid() && ZoraxyAddrPort.Port() > 0 {
		ZoraxyPort = int(ZoraxyAddrPort.Port())
	}
	pluginManager = plugins.NewPluginManager(&plugins.ManagerOptions{
		PluginDir:          pluginFolder,
		Database:           sysdb,
		Logger:             SystemWideLogger,
		PluginGroupsConfig: CONF_PLUGIN_GROUPS,
		APIKeyManager:      pluginApiKeyManager,
		ZoraxyPort:         ZoraxyPort,
		CSRFTokenGen: func(r *http.Request) string {
			return csrf.Token(r)
		},
		SystemConst: &zoraxy_plugin.RuntimeConstantValue{
			ZoraxyVersion:    SYSTEM_VERSION,
			ZoraxyUUID:       nodeUUID,
			DevelopmentBuild: *development_build,
		},
		/* Plugin Store URLs */
		PluginStoreURLs: []string{
			"https://raw.githubusercontent.com/aroz-online/zoraxy-official-plugins/refs/heads/main/directories/index.json",
			//TO BE ADDED
		},
		/* Developer Options */
		EnableHotReload:   *development_build, //Default to true if development build
		HotReloadInterval: 5,                  //seconds
	})

	/*
		Event Manager
	*/
	eventsystem.InitEventSystem(SystemWideLogger)

	//Sync latest plugin list from the plugin store
	go func() {
		err = pluginManager.UpdateDownloadablePluginList()
		if err != nil {
			SystemWideLogger.PrintAndLog("plugin-manager", "Failed to sync plugin list from plugin store", err)
		} else {
			SystemWideLogger.PrintAndLog("plugin-manager", "Plugin list synced from plugin store", nil)
		}
	}()

	err = pluginManager.LoadPluginsFromDisk()
	if err != nil {
		SystemWideLogger.PrintAndLog("plugin-manager", "Failed to load plugins", err)
	}
	SystemWideLogger.Println("[Startup Timing] Plugin manager initialized in " + time.Since(stepStart).String())

	/* Docker UX Optimizer */
	if runtime.GOOS == "windows" && *runningInDocker {
		SystemWideLogger.PrintAndLog("warning", "Invalid start flag combination: docker=true && runtime.GOOS == windows. Running in docker UX development mode.", nil)
	}
	DockerUXOptimizer = dockerux.NewDockerOptimizer(*runningInDocker, SystemWideLogger)

	SystemWideLogger.Println("[Startup Timing] Total startup sequence completed in " + time.Since(startupStart).String())
}

/* Finalize Startup Sequence */
// This sequence start after everything is initialized
func finalSequence() {
	//Start ACME renew agent
	acmeRegisterSpecialRoutingRule()

	//Inject routing rules
	registerBuildInRoutingRules()

	//Set the host specific TLS behavior resolver for resolving TLS behavior for each hostname
	tlsCertManager.SetHostSpecificTlsBehavior(dynamicProxyRouter.ResolveHostSpecificTlsBehaviorForHostname)

	// Set up certificate change callbacks for cluster synchronization
	setupCertificateClusterSync()
}

/* Shutdown Sequence */
func ShutdownSeq() {
	SystemWideLogger.Println("Shutting down " + SYSTEM_NAME)
	SystemWideLogger.Println("Closing Netstats Listener")
	if netstatBuffers != nil {
		netstatBuffers.Close()
	}

	SystemWideLogger.Println("Closing Statistic Collector")
	if statisticCollector != nil {
		statisticCollector.Close()
	}

	if mdnsTickerStop != nil {
		SystemWideLogger.Println("Stopping mDNS Discoverer (might take a few minutes)")
		// Stop the mdns service
		mdnsTickerStop <- true
	}
	if mdnsScanner != nil {
		mdnsScanner.Close()
	}
	SystemWideLogger.Println("Shutting down load balancer")
	if loadBalancer != nil {
		loadBalancer.Close()
	}
	SystemWideLogger.Println("Closing Certificates Auto Renewer")
	if acmeAutoRenewer != nil {
		acmeAutoRenewer.Close()
	}

	if accessController != nil {
		SystemWideLogger.Println("Closing Access Controller")
		accessController.Close()
	}

	//Close the plugin manager
	SystemWideLogger.Println("Shutting down plugin manager")
	if pluginManager != nil {
		pluginManager.Close()
	}

	//Remove the tmp folder
	SystemWideLogger.Println("Cleaning up tmp files")
	os.RemoveAll("./tmp")

	//Close database
	SystemWideLogger.Println("Stopping system database")
	sysdb.Close()

	//Close logger
	SystemWideLogger.Println("Closing system wide logger")
	SystemWideLogger.Close()
}
