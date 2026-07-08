package main

import (
	"errors"
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
	Example: "  dnsacme --domain='*.example.com' --email='your.example.com' --dns=cloudflare --dns-config=CLOUDFLARE_API_TOKEN=xxxxxxxxxxxxxx",
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
	rootCmd.PersistentFlags().StringP("email", "m", "", "ACME email")
	rootCmd.PersistentFlags().String("storage-dir", dataDir(), "ACME cert status storage directory")
	rootCmd.PersistentFlags().StringP("key-type", "t", "P384", "ACME cert key type")
	rootCmd.PersistentFlags().StringP("dns", "p", "", "ACME DNS provider")
	rootCmd.PersistentFlags().StringToString("dns-config", map[string]string{}, "ACME DNS provider config map")
	rootCmd.PersistentFlags().Bool("zerossl", true, "Obtain cert with ZeroSSL CA")
	rootCmd.PersistentFlags().String("obtaining-hook", "", "CertMagic obtaining hook command")
	rootCmd.PersistentFlags().String("obtained-hook", "", "CertMagic obtained hook command")
	rootCmd.PersistentFlags().String("failed-hook", "", "CertMagic obtain failed hook command")
	rootCmd.PersistentFlags().BoolVarP(&listProviders, "list-providers", "l", false, "List supported DNS providers")
	rootCmd.PersistentFlags().String("eab-keyid", "", "ACME Custom EABKeyID")
	rootCmd.PersistentFlags().String("eab-mackey", "", "ACME Custom EABHMACKey")

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
	_ = viper.BindEnv("eab-keyid", "ACME_EABKEYID")
	_ = viper.BindEnv("eab-mackey", "ACME_EABHMACKEY")

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

	var err error
	conf, err = configFromViper()
	if err != nil {
		_ = cmd.Help()
		logrus.Fatal(err)
	}
}

func configFromViper() (Config, error) {
	dnsConfig := viper.GetStringMapString("dns-config")
	if len(dnsConfig) == 0 {
		dnsConfig = parseDNSConfig(viper.GetString("dns-config"))
	}

	return validateConfig(Config{
		Domains:       viper.GetStringSlice("domain"),
		Email:         viper.GetString("email"),
		StorageDir:    viper.GetString("storage-dir"),
		KeyType:       viper.GetString("key-type"),
		DNSProvider:   viper.GetString("dns"),
		DNSConfig:     dnsConfig,
		ZeroSSLCA:     viper.GetBool("zerossl"),
		EABKeyID:      viper.GetString("eab-keyid"),
		EABHMACKey:    viper.GetString("eab-mackey"),
		ObtainingHook: viper.GetString("obtaining-hook"),
		ObtainedHook:  viper.GetString("obtained-hook"),
		FailedHook:    viper.GetString("failed-hook"),
	})
}

func parseDNSConfig(raw string) map[string]string {
	result := make(map[string]string)
	for _, item := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || key == "" {
			continue
		}
		result[key] = value
	}
	return result
}

func validateConfig(c Config) (Config, error) {
	if c.Domains == nil || len(c.Domains) == 0 {
		return c, errors.New("ACME Domain is empty")
	}

	if c.Email == "" {
		return c, errors.New("ACME Email is empty")
	}

	c.KeyType = strings.ToLower(c.KeyType)
	switch c.KeyType {
	case "ed25519":
	case "p256":
	case "p384":
	case "rsa2048":
	case "rsa4096":
	case "rsa8192":
	default:
		return c, fmt.Errorf("Unsupported KeyType: %s", c.KeyType)
	}

	if c.DNSProvider == "" {
		return c, errors.New("ACME DNS Provider is empty")
	}

	if c.DNSConfig == nil || len(c.DNSConfig) == 0 {
		return c, errors.New("ACME DNS Provider config is empty")
	}

	if c.ObtainingHook != "" && len(strings.Fields(c.ObtainingHook)) != 1 {
		return c, fmt.Errorf("Obtaining Hook does not support parameter parsing: [%s]", c.ObtainingHook)
	}

	if c.ObtainedHook != "" && len(strings.Fields(c.ObtainedHook)) != 1 {
		return c, fmt.Errorf("Obtained Hook does not support parameter parsing: [%s]", c.ObtainedHook)
	}

	if c.FailedHook != "" && len(strings.Fields(c.FailedHook)) != 1 {
		return c, fmt.Errorf("Failed Hook does not support parameter parsing: [%s]", c.FailedHook)
	}

	return c, nil
}
