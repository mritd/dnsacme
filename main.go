package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/mritd/logrus"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var commit string

var listProviders bool

var conf = Config{DNSConfig: make(map[string]string)}

var rootCmd = &cobra.Command{
	Use:     "dnsacme",
	Short:   "Simple tool to manage ACME Cert(Ony Supported DNS-01)",
	Example: "  dnsacme --test --domain='*.example.com' --dns=cloudflare --dns-config=CLOUDFLARE_API_TOKEN=xxxxxxxxxxxxxx",
	Version: commit,
	PreRun:  preCheck,
	Run: func(cmd *cobra.Command, args []string) {

		// Print the currently supported DNS Providers
		// advanced users can use build tag to delete some DNS Providers to reduce the file size
		if listProviders {
			var providers Providers
			for k := range providerFn {
				providers = append(providers, k)
			}
			sort.Sort(providers)

			fmt.Println("=========== DNS Providers ===========")
			for i, name := range providers {
				fmt.Printf("  %d. %s\n", i+1, name)
			}
			return
		}

		Obtain(&conf)
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Error(err)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&conf.TestMode, "test", false, "Use Let's Encrypt Staging CA to test")
	rootCmd.PersistentFlags().StringSliceVarP(&conf.Domains, "domain", "d", nil, "ACME cert domains")
	rootCmd.PersistentFlags().StringVarP(&conf.Email, "email", "m", "caddy@zerossl.com", "ACME email")
	rootCmd.PersistentFlags().StringVar(&conf.StorageDir, "dir", dataDir(), "ACME cert status storage directory")
	rootCmd.PersistentFlags().StringVarP(&conf.KeyType, "key-type", "t", "P384", "ACME cert key type")
	rootCmd.PersistentFlags().StringVarP(&conf.DNSProvider, "dns", "p", "", "ACME DNS provider")
	rootCmd.PersistentFlags().StringToStringVar(&conf.DNSConfig, "dns-config", map[string]string{}, "ACME DNS provider config map")
	rootCmd.PersistentFlags().BoolVar(&conf.ZeroSSLCA, "zerossl", true, "Obtain cert with ZeroSSL CA")
	rootCmd.PersistentFlags().StringVar(&conf.ObtainingHook, "obtaining-hook", "", "CertMagic obtaining hook command")
	rootCmd.PersistentFlags().StringVar(&conf.ObtainedHook, "obtained-hook", "", "CertMagic obtained hook command")
	rootCmd.PersistentFlags().StringVar(&conf.FailedHook, "failed-hook", "", "CertMagic obtain failed hook command")
	rootCmd.PersistentFlags().BoolVar(&listProviders, "list-providers", false, "List supported DNS providers")

	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false
}

func dataDir() string {
	var err error
	var basedir string

	if basedir = os.Getenv("XDG_CONFIG_HOME"); basedir == "" {
		basedir, err = os.UserConfigDir()
		if err != nil {
			logrus.Error(err)
			return "./dnsacme"
		}
	}

	return filepath.Join(basedir, "dnsacme")
}

// preCheck Check the necessary configuration before running
func preCheck(cmd *cobra.Command, _ []string) {
	if listProviders {
		return
	}

	if conf.Domains == nil || len(conf.Domains) == 0 {
		_ = cmd.Help()
		logrus.Fatal("ACME Domain is empty")
	}
	if conf.Email == "" {
		_ = cmd.Help()
		logrus.Fatal("ACME Email is empty")
	}
	if conf.DNSProvider == "" {
		_ = cmd.Help()
		logrus.Fatal("ACME DNS Provider is empty")
	}
	if conf.DNSConfig == nil || len(conf.DNSConfig) == 0 {
		_ = cmd.Help()
		logrus.Fatal("ACME DNS Provider config is empty")
	}
	if conf.ObtainingHook != "" && len(strings.Fields(conf.ObtainingHook)) != 1 {
		_ = cmd.Help()
		logrus.Fatalf("Obtaining Hook does not support parameter parsing: [%s]", conf.ObtainingHook)
	}
	if conf.ObtainedHook != "" && len(strings.Fields(conf.ObtainedHook)) != 1 {
		_ = cmd.Help()
		logrus.Fatalf("Obtained Hook does not support parameter parsing: [%s]", conf.ObtainedHook)
	}
	if conf.FailedHook != "" && len(strings.Fields(conf.FailedHook)) != 1 {
		_ = cmd.Help()
		logrus.Fatalf("Failed Hook does not support parameter parsing: [%s]", conf.FailedHook)
	}

	switch strings.ToLower(conf.KeyType) {
	case "ed25519":
	case "p256":
	case "p384":
	case "rsa2048":
	case "rsa4096":
	case "rsa8192":
	default:
		logrus.Fatalf("Unsupported KeyType: %s", conf.keyType)
	}
}
