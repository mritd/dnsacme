package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/viper"

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
	Example: "  dnsacme --domain='*.example.com' --dns=cloudflare --dns-config=CLOUDFLARE_API_TOKEN=xxxxxxxxxxxxxx",
	Version: commit,
	PreRun:  initConfig,
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
	rootCmd.PersistentFlags().StringSliceP("domain", "d", nil, "ACME cert domains")
	rootCmd.PersistentFlags().StringP("email", "m", "caddy@zerossl.com", "ACME email")
	rootCmd.PersistentFlags().String("storage-dir", dataDir(), "ACME cert status storage directory")
	rootCmd.PersistentFlags().StringP("key-type", "t", "P384", "ACME cert key type")
	rootCmd.PersistentFlags().StringP("dns", "p", "", "ACME DNS provider")
	rootCmd.PersistentFlags().StringToString("dns-config", map[string]string{}, "ACME DNS provider config map")
	rootCmd.PersistentFlags().Bool("zerossl", true, "Obtain cert with ZeroSSL CA")
	rootCmd.PersistentFlags().String("obtaining-hook", "", "CertMagic obtaining hook command")
	rootCmd.PersistentFlags().String("obtained-hook", "", "CertMagic obtained hook command")
	rootCmd.PersistentFlags().String("failed-hook", "", "CertMagic obtain failed hook command")
	rootCmd.PersistentFlags().BoolVarP(&listProviders, "list-providers", "l", false, "List supported DNS providers")

	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false

	_ = viper.BindEnv("domain", "ACME_DOMAIN")
	_ = viper.BindEnv("email", "ACME_EMAIL")
	_ = viper.BindEnv("storage-dir", "ACME_STORAGE_DIR")
	_ = viper.BindEnv("key-type", "ACME_KEY_TYPE")
	_ = viper.BindEnv("dns", "ACME_DNS_PROVIDER")
	_ = viper.BindEnv("dns-config", "ACME_DNS_CONFIG")
	_ = viper.BindEnv("zerossl", "ACME_ZEROSSL")
	_ = viper.BindEnv("obtaining-hook", "ACME_OBTAINING_HOOK")
	_ = viper.BindEnv("obtained-hook", "ACME_OBTAINED_HOOK")
	_ = viper.BindEnv("failed-hook", "ACME_FAILED_HOOK")

	_ = viper.BindPFlags(rootCmd.PersistentFlags())

}

func dataDir() string {
	var err error
	var basedir string

	if basedir = os.Getenv("XDG_CONFIG_HOME"); basedir == "" {
		basedir, err = os.UserConfigDir()
		if err != nil {
			logrus.Error(err)
			return "./certmagic"
		}
	}

	return filepath.Join(basedir, "certmagic")
}

func initConfig(cmd *cobra.Command, _ []string) {
	if listProviders {
		return
	}

	conf.Domains = viper.GetStringSlice("domain")
	if conf.Domains == nil || len(conf.Domains) == 0 {
		_ = cmd.Help()
		logrus.Fatal("ACME Domain is empty")
	}

	conf.Email = viper.GetString("email")
	if conf.Email == "" {
		_ = cmd.Help()
		logrus.Fatal("ACME Email is empty")
	}

	conf.StorageDir = viper.GetString("storage-dir")

	conf.KeyType = strings.ToLower(viper.GetString("key-type"))
	switch conf.KeyType {
	case "ed25519":
	case "p256":
	case "p384":
	case "rsa2048":
	case "rsa4096":
	case "rsa8192":
	default:
		logrus.Fatalf("Unsupported KeyType: %s", conf.keyType)
	}

	conf.DNSProvider = viper.GetString("dns")
	if conf.DNSProvider == "" {
		_ = cmd.Help()
		logrus.Fatal("ACME DNS Provider is empty")
	}

	conf.DNSConfig = viper.GetStringMapString("dns-config")
	if conf.DNSConfig == nil || len(conf.DNSConfig) == 0 {
		_ = cmd.Help()
		logrus.Fatal("ACME DNS Provider config is empty")
	}

	conf.ZeroSSLCA = viper.GetBool("zerossl")

	conf.ObtainingHook = viper.GetString("obtaining-hook")
	if conf.ObtainingHook != "" && len(strings.Fields(conf.ObtainingHook)) != 1 {
		_ = cmd.Help()
		logrus.Fatalf("Obtaining Hook does not support parameter parsing: [%s]", conf.ObtainingHook)
	}

	conf.ObtainedHook = viper.GetString("obtained-hook")
	if conf.ObtainedHook != "" && len(strings.Fields(conf.ObtainedHook)) != 1 {
		_ = cmd.Help()
		logrus.Fatalf("Obtained Hook does not support parameter parsing: [%s]", conf.ObtainedHook)
	}

	conf.FailedHook = viper.GetString("failed-hook")
	if conf.FailedHook != "" && len(strings.Fields(conf.FailedHook)) != 1 {
		_ = cmd.Help()
		logrus.Fatalf("Failed Hook does not support parameter parsing: [%s]", conf.FailedHook)
	}
}
