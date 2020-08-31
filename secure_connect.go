package gocql

import (
	"archive/zip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"
)

func NewClusterSecureConnectBundle(bundleName string) (*ClusterConfig, error) {
	endpoints, config, err := unmarshalBundle(bundleName)
	if err != nil {
		return nil, err
	}
	cfg := NewCluster(endpoints...)
	cfg.SNIConfig = config
	return cfg, nil
}

func unmarshalBundle(bundleName string) ([]string, *SNIConfig, error) {
	r, err := zip.OpenReader(bundleName)
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()

	// 2. Put in temp directory (the following MUST BE FILES for this to work.
	//    a) 'cert' file
	//    b) 'key' file
	//    c) 'ca.crt' file

	dir, err := ioutil.TempDir("", "securezip")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir) // the files are only needed until we create the tlsConfig, at that point they have been read in and processed, so not needed any longer and can be deleted at end of method.

	// add each file from bundle to the directory
	for _, f := range r.File {
		fpath := filepath.Join(dir, f.Name)

		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return nil, nil, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return nil, nil, err
		}

		rc, err := f.Open()
		if err != nil {
			return nil, nil, err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return nil, nil, err
		}
	}

	// 4. Load the 'config.json' file as json into a map[string]interface{}
	// open config.json file
	file, err := os.Open(path.Join(dir, "config.json")) // For read access.
	if err != nil {
		return nil, nil, err
	}
	// read the opened jsonFile as a byte array.
	byteValue, _ := ioutil.ReadAll(file)
	file.Close()

	// parse json file
	config := secureBundleConfig{}
	_ = json.Unmarshal(byteValue, &config)

	// 5. Create url: "https://<config.json["host"]:config.json["port"]>/metadata
	metadataURL := fmt.Sprintf("https://%s:%d/metadata", config.Host, config.Port)

	// 6. tlsConfig, err := setupTLSConfig(&sniConfig.SSLOpts)
	//    if err != nil {
	//      return nil, nil, err
	//    }
	tlsConfig, err := setupTLSConfig(&SslOptions{
		CertPath:               path.Join(dir, config.CertLocation),
		KeyPath:                path.Join(dir, config.KeyLocation),
		CaPath:                 path.Join(dir, config.CaCertLocation),
		EnableHostVerification: true,
	})
	if err != nil {
		return nil, nil, err
	}
	metadata, err := getSecureBundleMetadata(metadataURL, tlsConfig)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig.InsecureSkipVerify = true

	return metadata.ContactInfo.ContactPoints, &SNIConfig{
		SNIProxyAddress: metadata.ContactInfo.SNIProxyAddress,
		tlsConfig:       tlsConfig,
	}, err
}

func getSecureBundleMetadata(endpoint string, tlsConfig *tls.Config) (*secureBundleMetadata, error) {
	var client = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	var metadata secureBundleMetadata

	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		// err := utils.NewError(resp.StatusCode, msg)
		// return nil, err
	}

	json.NewDecoder(resp.Body).Decode(&metadata)

	return &metadata, nil
}

type secureBundleConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	CaCertLocation string `json:"caCertLocation"`
	KeyLocation    string `json:"keyLocation"`
	CertLocation   string `json:"certLocation"`
}

type secureBundleMetadata struct {
	Version     int    `json:"version"`
	Region      string `json:"region"`
	ContactInfo struct {
		Type            string   `json:"type"`
		LocalDC         string   `json:"localDC"`
		ContactPoints   []string `json:"contact_points"`
		SNIProxyAddress string   `json:"sni_proxy_address"`
	} `json:"contact_info"`
}
