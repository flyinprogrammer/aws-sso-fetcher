package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/mitchellh/go-homedir"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type AWSSSOCredential struct {
	StartURL    string  `json:"startUrl"`
	Region      string  `json:"region"`
	AccessToken string  `json:"accessToken"`
	ExpiresAt   AWSTime `json:"expiresAt"`
}

type CredentialProcessJson struct {
	Version         int     `json:"Version"`
	AccessKeyID     string  `json:"AccessKeyId"`
	SecretAccessKey string  `json:"SecretAccessKey"`
	SessionToken    string  `json:"SessionToken"`
	Expiration      AWSTime `json:"Expiration"`
}

type Profile struct {
	SSOAccountID string
	SSORegion    string
	SSORoleName  string
	SSOStartUrl  string
}

type AWSTime struct {
	time.Time
}

func (it *AWSTime) UnmarshalJSON(data []byte) error {
	t, err := time.Parse("2006-01-02T15:04:05Z07:00", strings.Trim(strings.Replace(string(data), "UTC", "Z", 1), `"`))
	if err == nil {
		*it = AWSTime{t}
	}

	return err
}

func (it AWSTime) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%sZ\"", it.Time.UTC().Format("2006-01-02T15:04:05"))), nil
}

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	_, ok := os.LookupEnv("DEBUG")
	if ok {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) != 1 {
		fmt.Println("should only be 1 argument, and should be the name of a profile")
		os.Exit(1)
	}
	profileName := fmt.Sprintf("profile %s", argsWithoutProg[0])
	log.Debug().Str("profileName", profileName).Msg("profile name")

	homePath, err := homedir.Dir()
	if err != nil {
		log.Fatal().Err(err).Msg("error getting home dir")
	}
	log.Debug().Str("path", homePath).Msg("home")

	awsConfigPath := filepath.Join(homePath, ".aws", "config")
	log.Debug().Str("path", awsConfigPath).Msg("config")

	awsSsoCachePath := filepath.Join(homePath, ".aws", "sso", "cache")
	log.Debug().Str("path", awsSsoCachePath).Msg("sso_cache")

	cachedProfile, err := getCachedFile(awsSsoCachePath, profileName)
	if err != nil {
		log.Error().Err(err).Msg("error accessing cached profile")
	}
	if cachedProfile != nil {
		printProfile(*cachedProfile)
		os.Exit(0)
	}

	profileSection, err := getAwsProfile(awsConfigPath, profileName)
	if err != nil {
		log.Fatal().Err(err).Str("profile", profileName).Str("path", awsConfigPath).Msg("error getting aws profile")
	}

	profile, err := parseProfile(profileSection)
	if err != nil {
		log.Fatal().Err(err).Msg("error creating profile, that's not great")
	}

	awsSSOCredential, err := getSsoCachedLogin(profile, awsSsoCachePath)
	if err != nil {
		log.Fatal().Err(err).Msg("could not get sso cached login")
	}

	credentialProcessJson, err := getSsoRoleCredentials(profile, awsSSOCredential)
	if err != nil {
		log.Fatal().Err(err).Msg("could not get role credentials with SSO credentials")
	}
	err = writeCachedFile(awsSsoCachePath, profileName, credentialProcessJson)
	if err != nil {
		log.Error().Err(err).Msg("could not write cache file")
	}
	printProfile(credentialProcessJson)
}

func writeCachedFile(awsSsoCachePath, awsSSOProfileName string, credentialProcessJson CredentialProcessJson) error {
	cachedFileName := getCachedFileName(awsSSOProfileName)
	cachedFilePath := filepath.Join(awsSsoCachePath, cachedFileName)
	buffer, err := jsonEncode(credentialProcessJson)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(cachedFilePath, buffer.Bytes(), 0600)
	if err != nil {
		return err
	}
	return nil
}

func getCachedFile(awsSsoCachePath, awsSSOProfileName string) (*CredentialProcessJson, error) {
	cachedFileName := getCachedFileName(awsSSOProfileName)
	cachedFilePath := filepath.Join(awsSsoCachePath, cachedFileName)
	var credentialProcessJson CredentialProcessJson

	bytes, err := ioutil.ReadFile(cachedFilePath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &credentialProcessJson)
	if err != nil {
		return nil, err
	}
	if time.Now().After(credentialProcessJson.Expiration.Time) {
		log.Debug().Str("expire", credentialProcessJson.Expiration.String()).Msg("credentials expired")
		return nil, nil
	}
	log.Debug().Str("path", cachedFilePath).Msg("using cache file")
	return &credentialProcessJson, nil
}

func getCachedFileName(awsSSOProfileName string) string {
	profileNameSha1 := sha1.Sum([]byte(awsSSOProfileName))
	return fmt.Sprintf("aws-sso-fetcher-%s.json", hex.EncodeToString(profileNameSha1[:]))
}

func printProfile(credentialProcessJson CredentialProcessJson) {
	buffer, err := jsonEncode(credentialProcessJson)
	if err != nil {
		log.Fatal().Err(err).Msg("encoding json exploded")
	}
	fmt.Printf("%s", buffer.String())
}

func jsonEncode(credentialProcessJson CredentialProcessJson) (*bytes.Buffer, error) {
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", " ")
	err := encoder.Encode(credentialProcessJson)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

func getSsoRoleCredentials(profile Profile, awsSSOCredential AWSSSOCredential) (CredentialProcessJson, error) {

	var credentialProcessJson CredentialProcessJson

	config, err := external.LoadDefaultAWSConfig(external.WithRegion(profile.SSORegion))
	if err != nil {
		log.Fatal().Err(err).Msg("error loading default config")
	}
	client := sso.New(config)
	resp, err := client.GetRoleCredentialsRequest(&sso.GetRoleCredentialsInput{
		AccessToken: aws.String(awsSSOCredential.AccessToken),
		AccountId:   aws.String(profile.SSOAccountID),
		RoleName:    aws.String(profile.SSORoleName),
	}).Send(context.TODO())
	if err != nil {
		return credentialProcessJson, err
	}
	return CredentialProcessJson{
		Version:         1,
		AccessKeyID:     *resp.RoleCredentials.AccessKeyId,
		SecretAccessKey: *resp.RoleCredentials.SecretAccessKey,
		SessionToken:    *resp.RoleCredentials.SessionToken,
		Expiration:      AWSTime{aws.MillisecondsTimeValue(resp.RoleCredentials.Expiration)},
	}, nil
}

func getSsoCachedLogin(profile Profile, ssoCachePath string) (AWSSSOCredential, error) {
	var awsSSOCredential AWSSSOCredential

	bs := sha1.Sum([]byte(profile.SSOStartUrl))
	cachedFilePath := filepath.Join(ssoCachePath, fmt.Sprintf("%x.json", bs))
	bytes, err := ioutil.ReadFile(cachedFilePath)
	if err != nil {
		return awsSSOCredential, err
	}

	err = json.Unmarshal(bytes, &awsSSOCredential)
	if err != nil {
		return awsSSOCredential, err
	}

	if time.Now().After(awsSSOCredential.ExpiresAt.Time) {
		log.Debug().Str("ExpiresAt", awsSSOCredential.ExpiresAt.String()).Msg("credential is expired")
		return awsSSOCredential, fmt.Errorf("Credentials expired")
	}

	return awsSSOCredential, nil
}

func parseProfile(section *ini.Section) (Profile, error) {
	var profile Profile

	profileAccountId, err := section.GetKey("sso_account_id")
	if err != nil {
		return profile, fmt.Errorf("error getting sso_account_id from profile: %w", err)
	}
	log.Debug().Str("id", profileAccountId.String()).Msg("found account id")
	profile.SSOAccountID = profileAccountId.String()

	profileRegionKey, err := section.GetKey("sso_region")
	if err != nil {
		return profile, fmt.Errorf("error getting sso_region from profile: %w", err)
	}
	log.Debug().Str("value", profileRegionKey.String()).Msg("profile Region")
	profile.SSORegion = profileRegionKey.String()

	profileRoleName, err := section.GetKey("sso_role_name")
	if err != nil {
		return profile, fmt.Errorf("error getting sso_role_name from profile: %w", err)
	}
	log.Debug().Str("name", profileRoleName.String()).Msg("found role name")
	profile.SSORoleName = profileRoleName.String()

	profileSSOStartURLKey, err := section.GetKey("sso_start_url")
	if err != nil {
		return profile, fmt.Errorf("error getting sso_start_url from profile: %w", err)
	}
	log.Debug().Str("value", profileSSOStartURLKey.String()).Msg("profile StartUrl")
	profile.SSOStartUrl = profileSSOStartURLKey.String()

	return profile, nil
}

func getAwsProfile(configPath, profileName string) (*ini.Section, error) {
	cfg, err := ini.Load(configPath)
	if err != nil {
		return nil, err
	}
	return cfg.GetSection(profileName)
}
